from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from shotguard.cli import main as cli_main

SYNTHETIC_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
SYNTHETIC_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def _render_text_png(lines: list[str], out_path: Path) -> None:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        magick_bin = shutil.which("magick") or shutil.which("convert")
        if magick_bin is None:
            raise unittest.SkipTest("Pillow or ImageMagick required for OCR test")
        proc = subprocess.run(
            [
                magick_bin,
                "-background",
                "white",
                "-fill",
                "black",
                "-pointsize",
                "36",
                "-bordercolor",
                "white",
                "-border",
                "40",
                f"label:{chr(10).join(lines)}",
                str(out_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"ImageMagick failed: {proc.stderr}")
        return

    font_candidates = [
        "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ]
    font = None
    for candidate in font_candidates:
        if Path(candidate).is_file():
            font = ImageFont.truetype(candidate, 36)
            break
    if font is None:
        font = ImageFont.load_default(size=36)

    width = 1400
    height = 80 + len(lines) * 64
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        draw.text((40, y), line, fill=(0, 0, 0), font=font)
        y += 64
    img.save(out_path)


@unittest.skipUnless(shutil.which("tesseract"), "tesseract binary required")
class TestEndToEndOCR(unittest.TestCase):
    def test_scan_detects_secrets_and_passes_clean_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            dirty_png = tmp_dir / "leaked.png"
            clean_png = tmp_dir / "clean.png"

            _render_text_png(
                [
                    f"AWS_ACCESS_KEY_ID={SYNTHETIC_AWS}",
                    f"GITHUB_TOKEN={SYNTHETIC_GH}",
                ],
                dirty_png,
            )
            _render_text_png(
                [
                    "Build finished successfully in 4.2s",
                    "Status: PASS with zero credentials",
                ],
                clean_png,
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "shotguard",
                    "scan",
                    str(dirty_png),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            report = json.loads(proc.stdout)
            rule_ids = {item["rule_id"] for item in report["findings"]}
            self.assertIn("aws-access-key", rule_ids)
            self.assertIn("github-token", rule_ids)
            self.assertNotIn(SYNTHETIC_AWS, proc.stdout)
            self.assertNotIn(SYNTHETIC_GH, proc.stdout)

            clean_rc = cli_main(["scan", str(clean_png)])
            self.assertEqual(clean_rc, 0)

    @unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg binary required")
    def test_scan_gif_extracts_frames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            frame1 = tmp_dir / "f1.png"
            frame2 = tmp_dir / "f2.png"
            gif_path = tmp_dir / "leak.gif"

            _render_text_png(["Loading dashboard..."], frame1)
            _render_text_png([f"AWS_ACCESS_KEY_ID={SYNTHETIC_AWS}"], frame2)

            ff = subprocess.run(
                [
                    "ffmpeg",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-framerate",
                    "1",
                    "-i",
                    str(tmp_dir / "f%d.png"),
                    str(gif_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ff.returncode, 0, ff.stderr)

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "shotguard",
                    "scan",
                    str(gif_path),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            report = json.loads(proc.stdout)
            aws_findings = [
                f for f in report["findings"] if f["rule_id"] == "aws-access-key"
            ]
            self.assertTrue(aws_findings, report)
            self.assertEqual(aws_findings[0]["frame"], 2)


if __name__ == "__main__":
    unittest.main()
