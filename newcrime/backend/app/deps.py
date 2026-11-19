"""Request context: identifies the calling officer from a signed login token.

Login issues an HMAC-signed token carrying the officer's id, role and
territory; every request is checked against SECRET_KEY, so a client can't
claim a role it wasn't given. Used for PII masking, RBAC and audit logging.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

from fastapi import HTTPException, Request

# role -> capability matrix (single source of truth, shared with auth router)
# Full Karnataka State Police hierarchy
ROLE_MATRIX = {
    "constable": {
        "rank": "Police Constable",
        "screens": ["dashboard", "chat", "cases", "work", "alerts"],
        "can_view_pii": False, "can_view_sql": False, "can_export": False,
        "can_view_audit": False, "can_investigate": False, "scope": "station",
        "command_level": None,
    },
    "head_constable": {
        "rank": "Head Constable",
        "screens": ["dashboard", "chat", "cases", "work", "alerts"],
        "can_view_pii": False, "can_view_sql": False, "can_export": False,
        "can_view_audit": False, "can_investigate": False, "scope": "station",
        "command_level": None,
    },
    "asi": {
        "rank": "Assistant Sub-Inspector",
        "screens": ["dashboard", "chat", "cases", "work", "alerts", "network"],
        "can_view_pii": False, "can_view_sql": False, "can_export": False,
        "can_view_audit": False, "can_investigate": True, "scope": "station",
        "command_level": None,
    },
    "sub_inspector": {
        "rank": "Sub-Inspector",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial", "alerts", "victims"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": False, "can_investigate": True, "scope": "assigned",
        "command_level": None,
    },
    "pi": {
        "rank": "Police Inspector",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "alerts", "patterns", "victims", "approvals", "audit"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "station",
        "command_level": "station",
    },
    "sho": {
        "rank": "Station House Officer",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "alerts", "patterns", "victims", "approvals", "audit"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "station",
        "command_level": "station",
    },
    "ci": {
        "rank": "Circle Inspector",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "alerts", "patterns", "victims", "approvals", "socio", "audit"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "subdivision",
        "command_level": "subdivision",
    },
    "acp": {
        "rank": "Assistant Commissioner of Police",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "patterns", "socio", "forecasting", "alerts", "audit", "victims", "approvals"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "subdivision",
        "command_level": "subdivision",
    },
    "dsp": {
        "rank": "Dy. Superintendent of Police",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "patterns", "socio", "forecasting", "alerts", "audit", "victims", "approvals"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "subdivision",
        "command_level": "subdivision",
    },
    "sp": {
        "rank": "Superintendent of Police",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "patterns", "socio", "forecasting", "alerts", "audit", "victims", "approvals"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "district",
        "command_level": "district",
    },
    "dig": {
        "rank": "Deputy Inspector General",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "patterns", "socio", "forecasting", "alerts", "audit", "victims", "approvals"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "range",
        "command_level": "range",
    },
    "ig": {
        "rank": "Inspector General of Police",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "patterns", "socio", "forecasting", "alerts", "audit", "victims", "approvals"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "range",
        "command_level": "range",
    },
    "addl_dgp": {
        "rank": "Additional DGP",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "patterns", "socio", "forecasting", "alerts", "audit", "victims", "approvals"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "state",
        "command_level": "state",
    },
    "dgp": {
        "rank": "Director General of Police",
        "screens": ["dashboard", "chat", "cases", "work", "network", "profiling", "financial",
                    "patterns", "socio", "forecasting", "alerts", "audit", "victims", "approvals"],
        "can_view_pii": True, "can_view_sql": True, "can_export": True,
        "can_view_audit": True, "can_investigate": True, "scope": "state",
        "command_level": "state",
    },
    "analyst": {
        "rank": "Intelligence Analyst",
        "screens": ["dashboard", "chat", "patterns", "socio", "forecasting", "network", "victims"],
        "can_view_pii": False, "can_view_sql": True, "can_export": True,
        "can_view_audit": False, "can_investigate": False, "scope": "district",
        "command_level": None,
    },
}
DEFAULT_ROLE = "sub_inspector"


class Ctx:
    def __init__(self, user_id, name, role, district=None, subdivision=None, range_name=None):
        self.user_id = user_id
        self.name = name or "Unknown"
        self.role = role if role in ROLE_MATRIX else DEFAULT_ROLE
        self.caps = ROLE_MATRIX[self.role]
        self.district = district
        self.subdivision = subdivision
        self.range_name = range_name

    @property
    def can_view_pii(self) -> bool:
        return self.caps["can_view_pii"]

    @property
    def scope(self) -> str:
        return self.caps["scope"]

    @property
    def command_level(self):
        return self.caps.get("command_level")

    def district_filter(self):
        """District(s) the officer may see, or None for state-wide."""
        if self.scope == "state":
            return None
        if self.scope == "range":
            from .geo import get_range_districts
            return get_range_districts(self.range_name) if self.range_name else self.district
        return self.district  # district / subdivision / station / assigned all narrow to their district

    def districts_in_scope(self):
        """Return list of districts the officer can access."""
        if self.scope == "state":
            from .geo import KARNATAKA_DISTRICTS
            return list(KARNATAKA_DISTRICTS.keys())
        if self.scope == "range":
            from .geo import get_range_districts
            return get_range_districts(self.range_name) if self.range_name else [self.district]
        return [self.district] if self.district else []

    def can_access_district(self, district) -> bool:
        """Whether this officer's territory covers `district`.

        Fail-closed: an officer below state scope with no district assigned
        gets nothing rather than everything.
        """
        if self.scope == "state":
            return True
        return district in set(self.districts_in_scope())

    def scope_rows(self, rows, field: str = "district"):
        """Drop rows outside the officer's territory.

        Works for both Catalyst dict rows and SQLAlchemy model instances so
        the two code paths can't drift apart.
        """
        if self.scope == "state":
            return rows
        allowed = set(self.districts_in_scope())
        return [r for r in rows
                if (r.get(field) if isinstance(r, dict) else getattr(r, field, None))
                in allowed]

    def districts_with_neighbors(self):
        """Return own district(s) + neighboring districts."""
        from .geo import get_neighbors
        own = self.districts_in_scope()
        neighbors = []
        for d in own:
            neighbors.extend(get_neighbors(d))
        return list(set(own + neighbors))


# ── tokens & passwords (stdlib only) ──────────────────────────────────
TOKEN_TTL = 12 * 3600


def _sign(body: str) -> str:
    from .config import settings
    return hmac.new(settings.secret_key.encode(), body.encode(), hashlib.sha256).hexdigest()


def make_token(user: dict) -> str:
    claims = {k: user.get(k) for k in
              ("id", "full_name", "role", "district", "subdivision", "range_name")}
    claims["exp"] = int(time.time()) + TOKEN_TTL
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
    return f"{body}.{_sign(body)}"


def read_token(token: str) -> dict | None:
    body, _, sig = (token or "").partition(".")
    if not body or not hmac.compare_digest(sig, _sign(body)):
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(body))
    except ValueError:
        return None
    return claims if claims.get("exp", 0) > time.time() else None


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def check_password(pw: str, stored: str) -> bool:
    if not stored.startswith("pbkdf2$"):
        # legacy plaintext row from an older DB; login rehashes it
        return hmac.compare_digest(pw.encode(), stored.encode())
    _, salt, digest = stored.split("$")
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000)
    return hmac.compare_digest(dk.hex(), digest)


def get_ctx(request: Request) -> Ctx:
    """401 unless the request carries a valid token.

    The query-string form exists only for file downloads, which the browser
    loads through <a>/<img>/<iframe> and so can't attach a header to.
    """
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    if not token and request.url.path.endswith("/download"):
        token = request.query_params.get("token", "")
    claims = read_token(token)
    if claims is None:
        raise HTTPException(401, "login required")
    return Ctx(claims.get("id"), claims.get("full_name"), claims.get("role"),
               claims.get("district"), claims.get("subdivision"),
               claims.get("range_name"))


def require_login(request: Request) -> None:
    get_ctx(request)


def mask_pii(value, show: bool, keep: int = 1):
    """Mask a PII string unless `show`. Keeps first `keep` chars."""
    if show or value is None:
        return value
    s = str(value)
    if not s:
        return s
    if len(s) <= keep:
        return "+" * 4
    return s[:keep] + "+" * max(4, len(s) - keep)
