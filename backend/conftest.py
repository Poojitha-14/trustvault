import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["TRUSTVAULT_DB"] = os.path.join(_tmp, "test.db")
os.environ["TRUSTVAULT_STORAGE"] = os.path.join(_tmp, "files")