#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

IMG_PATH="$TMP_DIR/bug-report-screenshot.png"

python3 - "$IMG_PATH" << 'PYEOF'
import pathlib
import sys
from PIL import Image, ImageDraw, ImageFont

out_path = pathlib.Path(sys.argv[1])
img = Image.new("RGB", (1120, 260), "white")
draw = ImageDraw.Draw(img)

font = None
for fp in (
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
):
    if pathlib.Path(fp).exists():
        font = ImageFont.truetype(fp, 28)
        break
if font is None:
    font = ImageFont.load_default(size=28)

draw.text((30, 35), "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE", fill="black", font=font)
draw.text((30, 125), "GITHUB_TOKEN=" + "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", fill="black", font=font)
draw.text((30, 205), "-> HTTP 401 Unauthorized", fill="black", font=font)
img.save(out_path)
PYEOF

cd "$REPO_ROOT"
echo "$ python3 -m shotguard scan bug-report-screenshot.png"
set +e
python3 -m shotguard scan "$IMG_PATH"
status=$?
set -e
echo "Exit code: $status"
