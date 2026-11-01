#!/usr/bin/env python3
"""Generate the Sparkle feed for one release.

Usage: appcast.py <archive> <version> <download-url> <output.xml> <owner/repo>

The EdDSA private key comes from $SPARKLE_ED_PRIVATE_KEY (a PEM). Sparkle verifies the raw
archive bytes, so the public half must be the one embedded in the app.
"""
import base64
import os
import shutil
import subprocess
import sys
import tempfile
from email.utils import formatdate
from pathlib import Path
from xml.sax.saxutils import escape

MIN_MACOS = "14.0"


def openssl():
    """LibreSSL cannot do `pkeyutl -rawin`, so find a real OpenSSL."""
    for candidate in (
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
        shutil.which("openssl3") or "",
        shutil.which("openssl") or "",
    ):
        if candidate and Path(candidate).exists():
            version = subprocess.run([candidate, "version"], capture_output=True, text=True).stdout
            if version.startswith(("OpenSSL 3", "OpenSSL 4")):
                return candidate
    raise SystemExit("ERROR: need OpenSSL 3+ for ed25519 signing")


def sign(archive, key_pem):
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
        handle.write(key_pem)
        key_path = handle.name
    try:
        signature = subprocess.run(
            [openssl(), "pkeyutl", "-sign", "-inkey", key_path, "-rawin", "-in", str(archive)],
            capture_output=True,
            check=True,
        ).stdout
    finally:
        os.unlink(key_path)
    if len(signature) != 64:
        raise SystemExit(f"ERROR: expected a 64-byte ed25519 signature, got {len(signature)}")
    return base64.b64encode(signature).decode()


def main():
    archive, version, url, out, repo = (
        Path(sys.argv[1]),
        sys.argv[2],
        sys.argv[3],
        Path(sys.argv[4]),
        sys.argv[5],
    )
    key = os.environ.get("SPARKLE_ED_PRIVATE_KEY", "")
    if not key:
        raise SystemExit("ERROR: SPARKLE_ED_PRIVATE_KEY is not set")

    signature = sign(archive, key)
    out.write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Grasp</title>
    <link>https://github.com/{escape(repo)}</link>
    <description>Paywall-free macOS builds.</description>
    <language>en</language>
    <item>
      <title>{escape(version)}</title>
      <pubDate>{formatdate(localtime=False, usegmt=True)}</pubDate>
      <sparkle:version>{escape(version)}</sparkle:version>
      <sparkle:shortVersionString>{escape(version)}</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>{MIN_MACOS}</sparkle:minimumSystemVersion>
      <sparkle:releaseNotesLink>https://github.com/{escape(repo)}/releases/tag/v{escape(version)}</sparkle:releaseNotesLink>
      <enclosure url="{escape(url)}"
                 sparkle:version="{escape(version)}"
                 sparkle:shortVersionString="{escape(version)}"
                 length="{archive.stat().st_size}"
                 type="application/octet-stream"
                 sparkle:edSignature="{escape(signature)}" />
    </item>
  </channel>
</rss>
""")
    print(f"appcast for {version}, edSignature {signature[:16]}...")


if __name__ == "__main__":
    main()
