"""Self-check for login tokens and password hashing.
Run from newcrime/backend:  python scripts/test_auth.py"""
import base64, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import deps

h = deps.hash_password("s3cret")
assert h.startswith("pbkdf2$") and deps.check_password("s3cret", h) and not deps.check_password("x", h)
assert deps.check_password("password", "password")              # legacy plaintext row
t = deps.make_token({"id": 7, "role": "sub_inspector", "district": "Mysuru"})
assert deps.read_token(t)["role"] == "sub_inspector"
sig = t.split(".")[1]
forged = base64.urlsafe_b64encode(json.dumps({"id": 7, "role": "dgp", "exp": time.time() + 99}).encode()).decode()
assert deps.read_token(f"{forged}.{sig}") is None                # role swap rejected
assert deps.read_token("") is None and deps.read_token("garbage") is None
deps.TOKEN_TTL = -1
assert deps.read_token(deps.make_token({"id": 1})) is None        # expired
print("ok")
