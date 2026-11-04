"""Helpers used by the FileDesk web service."""
import subprocess

UPLOAD_DIR = "uploads"


def file_size(filename):
    """Return the size in bytes of an uploaded file, as reported by `wc -c`."""
    cmd = f"wc -c {UPLOAD_DIR}/{filename}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        return None
    return int(result.stdout.split()[0])


def safe_name(filename):
    """Return True if the filename looks like a plain upload name."""
    return bool(filename) and "/" not in filename and not filename.startswith(".")
