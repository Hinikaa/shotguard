# Contributing to shotguard

## Requirements

- Python 3.11+ (standard library only for runtime and tests)
- `tesseract` (`tesseract-ocr` on Debian/Ubuntu, `tesseract` on Homebrew/Arch)
- `ffmpeg` (optional, required for `.gif`, `.mp4`, `.webm`, and `.mov` scanning)

## Development Setup

```bash
git clone https://github.com/Hinikaa/shotguard.git
cd shotguard
python3 -m unittest discover -s tests -v
```

## Guidelines

- Keep runtime dependencies at zero (Python 3.11+ stdlib + external `tesseract`/`ffmpeg` binaries only).
- Invoke subprocesses exclusively with argument lists (`subprocess.run([...])`); never interpolate shell strings.
- Never include raw, unredacted secret values in logs, comments, JSON output, or SARIF reports.
- Add positive and negative tests for every new rule or parser behavior.
