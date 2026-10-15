"""Create fictional, non-executed training data. Run from any directory."""
from pathlib import Path
import zipfile

ENTRIES = [
    ("README.txt", "SYNTHETIC TRAINING DATA. Nothing here should be executed. Lens detects lexical indicators, including comments.\n"),
    ("setup.ps1.txt", '# TRAINING ONLY: these comments illustrate review signals.\n# Example: Invoke-WebRequest https://downloads.example.invalid/package.txt\n# Example: Start-Process viewer.exe -Verb RunAs\nWrite-Output "Training fixture"\n'),
    ("photo.jpg.exe", "MZ — fictional marker fixture; not a valid Windows executable."),
    ("nested/notes.txt", "Ordinary notes with no matching review signals.\n"),
]


def main():
    destination = Path(__file__).resolve().parent.parent / "examples" / "training.zip"
    destination.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, content in ENTRIES:
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            archive.writestr(info, content.encode("utf-8"))
    print(destination)


if __name__ == "__main__":
    main()
