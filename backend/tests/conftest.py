import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
_TMP = tempfile.mkdtemp(prefix="eaf_tests_")
os.environ["EAF_DATA_DIR"] = _TMP          # tests never touch the real data/ directory
os.environ["EAF_DB_PATH"] = os.path.join(_TMP, "test.db")

import pytest  # noqa: E402

from backend.app import create_app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    return create_app().test_client()


def post(client, url, payload=None):
    r = client.post(url, json=payload or {})
    return r.status_code, r.get_json()
