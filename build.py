#!/usr/bin/env python3
"""
Build a full-featured macOS app from an official, closed-source release.

Three instructions per architecture, all anchored on instruction patterns rather than addresses,
and a missing anchor is a hard failure:

  1. The initializer is forced down its activation branch, so Pro is enabled at launch.
  2. The trial check is replaced with `return false`, so the licence page reads "Licensed on this
     Mac" instead of counting down a trial.
  3. The shared activation setter always receives `true`, so a later deactivation or remote
     verification cannot lock the app again.

The app is then re-signed. Signing strips the hardened runtime flag: the nested frameworks still
carry the vendor's signature, and dyld refuses to mix its identity with ours. Pass --identity (or
set SIGN_IDENTITY) to sign with your own certificate; that keeps the signing identity stable, so
Full Disk Access survives updates.

Sparkle is pointed at the given appcast by default, so the app cannot update itself back into the
official build. Use --keep-feed to leave the vendor feed.

Usage:
  ./build.py --upstream owner/repo --dmg download.dmg
  ./build.py --upstream owner/repo                    # downloads the latest release
  SIGN_IDENTITY="My Builder" ./build.py --upstream owner/repo --version 3.4.0

macOS only. Needs lipo, nm, codesign and hdiutil.
"""
import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

APPCAST_URL = "https://raw.githubusercontent.com/oenderg/grasp/main/appcast.xml"
SPARKLE_PUBLIC_KEY = "MQEMtxrlAP1XyYthvetCdxX11JMtzPPh4HFRNNYCZ+M="

UPSTREAM_REPO = os.environ.get("UPSTREAM_REPO", "")

# Function prologues of the tiny private `setActive(_:product:activated:)` helper that both
# enablePro() and disablePro() call. Matching the prologue alone is not enough: the program has
# generic copies with the same preamble, so each candidate must also contain the store of its
# boolean argument (see find_set_active). No symbols are needed; 3.4.0 is stripped.
SET_ACTIVE_ARM = bytes.fromhex(
    "ff4301d1f85f01a9f65702a9f44f03a9fd7b04a9fd030191f30302aaf40301aaf50300aa"
)
SET_ACTIVE_X86 = bytes.fromhex(
    "554889e5415741564155415453504189d74989f64889fb"
)
# The productActivated store, and the prologue of the trialActive() it calls next.
SET_ACTIVE_STORE_ARM = bytes.fromhex("f33f0039e00315aa")  # strb w19,[sp,#0xf]; mov x0,x21
SET_ACTIVE_ARG_ARM = bytes.fromhex("f30302aa")  # mov x19,x2 (the activated argument)
SET_ACTIVE_ARG_X86 = bytes.fromhex("4189d7")  # movl %edx,%r15d
TRIAL_PROLOGUE_ARM = bytes.fromhex("f657bda9")  # stp x22,x21,[sp,#-0x30]!
TRIAL_PROLOGUE_X86 = bytes.fromhex("554889e5")  # push rbp; mov rsp,rbp

ARCHES = ("arm64", "x86_64")


def die(message):
    raise SystemExit(f"ERROR: {message}")


def run(*cmd, **kwargs):
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("capture_output", True)
    try:
        return subprocess.run(cmd, **kwargs)
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr.rstrip(), file=sys.stderr)
        die(f"command failed ({error.returncode}): {' '.join(map(str, cmd))}")


def find_set_active(code, arch):
    """Find the activation helper: its prologue plus the store of its boolean argument."""
    needle = SET_ACTIVE_ARM if arch == "arm64" else SET_ACTIVE_X86
    marker = rb"\xf3\x3f\x00\x39\xe0\x03\x15\xaa" if arch == "arm64" else rb"\x44\x88\x7d(.)"
    candidates = []
    offset = code.find(needle)
    while offset >= 0:
        match = re.search(marker, code[offset : offset + 0x100], re.S)
        if match:
            candidates.append((offset, offset + match.start(), match))
        offset = code.find(needle, offset + 1)
    if not candidates:
        die("setActive() anchor not found (compiler or licensing code changed)")
    if len(candidates) > 1:
        die(f"setActive() anchor matched {len(candidates)} helpers")
    return candidates[0]


def trial_target(code, start, arch):
    """The first call after the activation store that lands on a bool-returning prologue."""
    prologue = TRIAL_PROLOGUE_ARM if arch == "arm64" else TRIAL_PROLOGUE_X86
    end = min(start + 0x100, len(code))
    if arch == "arm64":
        for offset in range(start, end, 4):
            insn = struct.unpack_from("<I", code, offset)[0]
            if insn & 0xFC000000 != 0x94000000:
                continue
            immediate = insn & 0x03FFFFFF
            if immediate & 0x02000000:
                immediate -= 0x04000000
            target = offset + (immediate << 2)
            if code[target : target + 4] == prologue:
                return target
    else:
        index = start
        while index < end:
            if code[index] == 0xE8:
                target = index + 5 + struct.unpack_from("<i", code, index + 1)[0]
                if code[target : target + 4] == prologue:
                    return target
                index += 5
            else:
                index += 1
    die("trialActive() call not found after the activation store")


def guard_sites(code, impl, arch):
    """Every call to trialActive followed by a test of its result.

    That is the initializer and the Paddle verification callback. Each test is changed to fall
    through to the enablePro() path, while the trialActive call itself stays (it has side effects).
    """
    sites = []
    if arch == "arm64":
        for offset in range(0, len(code) - 8, 4):
            insn = struct.unpack_from("<I", code, offset)[0]
            if insn & 0xFC000000 != 0x94000000:
                continue
            immediate = insn & 0x03FFFFFF
            if immediate & 0x02000000:
                immediate -= 0x04000000
            if offset + (immediate << 2) != impl:
                continue
            follow = struct.unpack_from("<I", code, offset + 4)[0]
            if follow & 0x7F800000 == 0x36000000 and (follow & 0x1F) == 0:
                sites.append(offset + 4)
    else:
        index = 0
        while index < len(code) - 8:
            if code[index] != 0xE8:
                index += 1
                continue
            target = index + 5 + struct.unpack_from("<i", code, index + 1)[0]
            follow = index + 5
            if (
                target == impl
                and code[follow : follow + 2] == b"\xa8\x01"
                and (code[follow + 2] in (0x74, 0x75) or code[follow + 2 : follow + 4] in (b"\x0f\x84", b"\x0f\x85"))
            ):
                sites.append(follow)
                index += 5
            else:
                index += 1
    if not sites:
        die("no trialActive() result test found (initializer changed)")
    return sites


def edit_arm64(code):
    start, store, _ = find_set_active(code, "arm64")
    impl = trial_target(code, store + 8, "arm64")

    # 1. The initializer's trialActive() result test falls through to enablePro().
    sites = guard_sites(code, impl, "arm64")[:1]
    struct.pack_into("<I", code, sites[0], 0xD503201F)  # nop
    # 2. trialActive -> false, so the licence page reads "Licensed", not a trial.
    struct.pack_into("<II", code, impl, 0x52800000, 0xD65F03C0)  # mov w0,#0; ret
    # 3. setActive receives activated=true from both enablePro() and disablePro(), so a later
    #    Paddle deactivation cannot re-lock the app. Rewrite only the argument load at the top;
    #    the rest of the function (including the retain) keeps its original registers.
    arg = code.find(SET_ACTIVE_ARG_ARM, start, start + 0x40)
    if arg < 0:
        die("setActive(): mov x19,x2 argument load not found")
    struct.pack_into("<I", code, arg, 0x52800033)  # mov w19,#1
    verify_arm64(code, impl, arg, sites)


def verify_arm64(code, impl, arg, sites):
    if struct.unpack_from("<II", code, impl) != (0x52800000, 0xD65F03C0):
        die("arm64 trialActive anchor did not change")
    if struct.unpack_from("<I", code, arg)[0] != 0x52800033:
        die("arm64 setActive anchor did not change")
    if struct.unpack_from("<I", code, sites[0])[0] != 0xD503201F:
        die("arm64 result-test anchor did not change")


def edit_x86_64(code):
    start, store, _ = find_set_active(code, "x86_64")
    impl = trial_target(code, store + 4, "x86_64")

    # 1. `test al, 1` -> `or al, 1`, making the initializer's jump fall through to enablePro().
    sites = guard_sites(code, impl, "x86_64")[:1]
    code[sites[0] : sites[0] + 2] = b"\x0c\x01"
    # 2. trialActive -> false.
    code[impl : impl + 3] = b"\x31\xc0\xc3"  # xor eax,eax; ret
    # 3. setActive receives activated=true from both enablePro() and disablePro().
    arg = code.find(SET_ACTIVE_ARG_X86, start, start + 0x40)
    if arg < 0:
        die("setActive(): movl %edx,%r15d argument load not found")
    code[arg : arg + 3] = b"\x41\xb7\x01"  # movb $1,%r15b
    verify_x86_64(code, impl, arg, sites)


def verify_x86_64(code, impl, arg, sites):
    if code[impl : impl + 3] != b"\x31\xc0\xc3":
        die("x86_64 trialActive anchor did not change")
    if code[arg : arg + 3] != b"\x41\xb7\x01":
        die("x86_64 setActive anchor did not change")
    if code[sites[0] : sites[0] + 2] != b"\x0c\x01":
        die("x86_64 result-test anchor did not change")


def edit_binary(binary):
    edited = []
    for arch in ARCHES:
        thin = binary.with_name(f".{binary.name}.{arch}")
        run("lipo", "-thin", arch, str(binary), "-output", str(thin))
        try:
            code = bytearray(thin.read_bytes())
            if arch == "arm64":
                edit_arm64(code)
            else:
                edit_x86_64(code)
            destination = binary.with_name(f".{binary.name}.{arch}.edited")
            destination.write_bytes(code)
            destination.chmod(0o755)
            edited.append(str(destination))
        finally:
            thin.unlink(missing_ok=True)
    run("lipo", "-create", *edited, "-output", str(binary))
    for part in edited:
        Path(part).unlink(missing_ok=True)
    print(f"edited {binary}")


def sign(app, identity, keychain):
    ad_hoc = identity is None
    identity = identity or "-"
    # The build certificate is self-signed and has no Team ID, so library validation would refuse
    # the nested frameworks with the hardened runtime on. Strip it, as the ad-hoc path does.
    command = ["codesign", "--force", "--sign", identity, "--options", "0",
               "--preserve-metadata=entitlements"]
    if not ad_hoc and keychain:
        command += ["--keychain", keychain]

    def is_code(path):
        try:
            return run("file", "-b", str(path)).stdout.find("Mach-O") >= 0
        except subprocess.CalledProcessError:
            return False

    nested = []
    for root, dirs, files in os.walk(app / "Contents"):
        for name in files:
            path = Path(root) / name
            if path.is_file() and is_code(path):
                nested.append(path)
        for name in dirs:
            path = Path(root) / name
            if path.suffix in (".app", ".xpc", ".framework") or name.endswith(".dylib"):
                nested.append(path)
    # Deepest paths first, then files before the bundles that contain them.
    nested.sort(key=lambda p: (len(p.parts), str(p)), reverse=True)
    for path in nested:
        run(*command, str(path))
    run(*command, str(app))
    run("codesign", "--verify", "--deep", "--strict", str(app))
    if ad_hoc:
        print("signed ad-hoc (hardened runtime removed)")
    else:
        print(f"signed by: {identity}")


def edit_feed(app, url, key):
    plist_path = app / "Contents" / "Info.plist"
    with plist_path.open("rb") as handle:
        plist = plistlib.load(handle)
    plist["SUFeedURL"] = url
    plist["SUPublicEDKey"] = key
    with plist_path.open("wb") as handle:
        plistlib.dump(plist, handle, sort_keys=False)


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def latest_release(upstream):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{upstream}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "grasp-build"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def download_release(destination, version, upstream):
    if not upstream:
        die("--upstream is required when no --dmg is given")
    release = latest_release(upstream)
    tag = release["tag_name"].removeprefix("v")
    if version and version != tag:
        die(f"latest upstream release is {tag}, not {version}")
    assets = [a for a in release.get("assets", []) if a["name"].endswith(".dmg")]
    if len(assets) != 1:
        die(f"release {tag} has {len(assets)} dmg assets, expected one")
    asset = assets[0]
    print(f"downloading {asset['name']} ({asset['size'] / 1e6:.1f} MB)")
    request = urllib.request.Request(asset["browser_download_url"], headers={"User-Agent": "grasp-build"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)
    expected = (asset.get("digest") or "").removeprefix("sha256:")
    if expected and digest(destination) != expected:
        die("downloaded DMG digest does not match GitHub's")
    return tag


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--upstream", default=UPSTREAM_REPO, help="release repository, owner/name")
    parser.add_argument("--dmg", type=Path, help="edit this official DMG instead of downloading one")
    parser.add_argument("--version", help="version to require (or to download when --dmg is absent)")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "dist",
                        help="output directory (default: ./dist next to this script)")
    parser.add_argument("--identity", default=os.environ.get("SIGN_IDENTITY"),
                        help="codesign identity (default: $SIGN_IDENTITY, else ad-hoc)")
    parser.add_argument("--keychain", default=os.environ.get("SIGN_KEYCHAIN"),
                        help="keychain holding the identity (default: $SIGN_KEYCHAIN)")
    parser.add_argument("--appcast-url", default=APPCAST_URL, help="Sparkle feed URL to embed")
    parser.add_argument("--sparkle-public-key", default=SPARKLE_PUBLIC_KEY,
                        help="public half of the EdDSA key that signs the feed")
    parser.add_argument("--keep-feed", action="store_true", help="leave upstream's Sparkle feed")
    parser.add_argument("--no-sign", action="store_true", help="skip code signing (inspection only)")
    args = parser.parse_args()

    if sys.platform != "darwin":
        die("macOS only")

    work = Path(tempfile.mkdtemp(prefix="grasp-patch-"))
    mount = work / "mnt"
    mount.mkdir()
    dmg = args.dmg
    try:
        if dmg is None:
            dmg = work / "upstream.dmg"
            version = download_release(dmg, args.version, args.upstream)
        else:
            dmg = dmg.resolve()
            if not dmg.is_file():
                die(f"no such DMG: {dmg}")
            print(f"sha256 {digest(dmg)}  {dmg.name}")

        run("hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", str(mount), str(dmg))
        apps = list(mount.glob("*.app"))
        if len(apps) != 1:
            die(f"expected one .app in the image, found {len(apps)}")
        app = work / "App.app"
        run("ditto", str(apps[0]), str(app))

        info = app / "Contents" / "Info.plist"
        if not info.is_file():
            die("image does not look like a supported app")
        with info.open("rb") as handle:
            plist = plistlib.load(handle)
        executable = plist.get("CFBundleExecutable")
        if not executable or not (app / "Contents" / "MacOS" / executable).is_file():
            die("image does not look like a supported app")
        version = plist["CFBundleShortVersionString"]
        if args.version and version != args.version:
            die(f"image is version {version}, expected {args.version}")

        if not args.no_sign:
            run("codesign", "--verify", "--deep", "--strict", str(app))
        if not args.keep_feed:
            edit_feed(app, args.appcast_url, args.sparkle_public_key)
        edit_binary(app / "Contents" / "MacOS" / executable)
        if not args.no_sign:
            sign(app, args.identity, args.keychain)

        args.out.mkdir(parents=True, exist_ok=True)
        stage = work / "stage"
        stage.mkdir()
        run("ditto", str(app), str(stage / "App.app"))
        (stage / "Applications").symlink_to("/Applications")
        output = args.out / f"Grasp-{version}.dmg"
        output.unlink(missing_ok=True)
        run("hdiutil", "create", "-quiet", "-volname", f"Grasp {version}", "-srcfolder", str(stage),
            "-format", "UDZO", "-ov", str(output))
        print(f"built {output}")
    finally:
        subprocess.run(["hdiutil", "detach", str(mount), "-quiet"], check=False)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
