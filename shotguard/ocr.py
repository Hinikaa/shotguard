from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from shotguard.rules import Finding, Rule, scan_text

IMAGE_EXTENSIONS: frozenset[str] = frozenset(
    {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}
)
VIDEO_EXTENSIONS: frozenset[str] = frozenset({".gif", ".mp4", ".webm", ".mov"})


def ocr_image(path: Path, lang: str = "eng", psm: int = 6) -> str:
    if shutil.which("tesseract") is None:
        raise RuntimeError(
            "tesseract binary not found in PATH; install tesseract-ocr"
        )
    proc = subprocess.run(
        ["tesseract", str(path), "stdout", "-l", lang, "--psm", str(psm)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip() or f"exit code {proc.returncode}"
        raise RuntimeError(f"tesseract failed for {path}: {err}")
    return proc.stdout


def extract_frames(
    media_path: Path, out_dir: Path, max_frames: int = 10
) -> list[Path]:
    if max_frames < 1:
        raise ValueError("max_frames must be >= 1")
    if shutil.which("ffmpeg") is None:
        raise RuntimeError(
            "ffmpeg binary not found in PATH; install ffmpeg to scan GIF/video files"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    out_pattern = str(out_dir / "frame_%04d.png")

    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", str(media_path)]
    if media_path.suffix.lower() == ".gif":
        # GIF decoders often repeat frames to hit a default rate; drop duplicates.
        cmd.extend(["-vf", "mpdecimate", "-fps_mode", "vfr"])
    else:
        cmd.extend(["-vf", "fps=1,mpdecimate", "-fps_mode", "vfr"])
    cmd.extend(["-frames:v", str(max_frames), out_pattern])

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        err = proc.stderr.strip() or f"exit code {proc.returncode}"
        raise RuntimeError(f"ffmpeg failed for {media_path}: {err}")

    return sorted(out_dir.glob("frame_*.png"))[:max_frames]


def scan_media_file(
    path: Path,
    rules: list[Rule],
    max_frames: int = 10,
    lang: str = "eng",
) -> list[Finding]:
    suffix = path.suffix.lower()
    if suffix in IMAGE_EXTENSIONS:
        text = ocr_image(path, lang=lang)
        return scan_text(text, rules, source=str(path), frame=None)

    if suffix in VIDEO_EXTENSIONS:
        findings: list[Finding] = []
        with tempfile.TemporaryDirectory(prefix="shotguard_frames_") as tmp:
            frames = extract_frames(path, Path(tmp), max_frames=max_frames)
            for frame_idx, frame_path in enumerate(frames, start=1):
                text = ocr_image(frame_path, lang=lang)
                findings.extend(
                    scan_text(text, rules, source=str(path), frame=frame_idx)
                )
        return findings

    raise ValueError(f"Unsupported media file extension: {path.suffix or '<none>'}")
