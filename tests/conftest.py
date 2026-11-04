import os
import sys
import tempfile
from pathlib import Path

os.environ["VULNIGO_DATA_DIR"] = tempfile.mkdtemp(prefix="vg_test_")
os.environ["VULTR_INFERENCE_API_KEY"] = ""  # tests never call a real model
os.environ["APPROVAL_TIMEOUT"] = "5"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
