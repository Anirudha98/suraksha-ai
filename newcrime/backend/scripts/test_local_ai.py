"""Self-check for the SQLite AI-query path and the local forecast.
Run from newcrime/backend:  python scripts/test_local_ai.py"""
import os, shutil, sqlite3, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
db = os.path.join(tempfile.mkdtemp(), "t.db")
shutil.copy("crimeintel.db", db)
os.environ["DATABASE_URL"] = f"sqlite:///{db}"

from datetime import date
from app.services import nlq, forecast

# read-only runner: allowed table works, secrets and writes are refused
n = sqlite3.connect(db).execute("select count(*) from cases where crime_type='Theft'").fetchone()[0]
assert nlq._sqlite_query("SELECT COUNT(ROWID) FROM cases WHERE crime_type = 'Theft'")[0]["COUNT(ROWID)"] == n
for bad in ("SELECT password FROM cases, users",
            "SELECT * FROM cases WHERE id IN (SELECT id FROM users)",
            "DELETE FROM cases"):
    try:
        nlq._sqlite_query(bad); raise SystemExit(f"NOT BLOCKED: {bad}")
    except sqlite3.DatabaseError:
        pass
assert "TABLE cases:" in nlq._sqlite_schema() and "TABLE users" not in nlq._sqlite_schema()

class FakeLLM:  # stands in for Groq/Gemini returning query JSON
    provider, available, last_error = "openai", True, None
    def __init__(self, sql): self.sql = sql
    def generate_query(self, q, schema): return {"intent": "count_cases", "zcql": self.sql}
    def narrate(self, q, f, lang): return "AI: " + f
nlq.get_llm = lambda: FakeLLM("SELECT COUNT(ROWID) FROM cases WHERE crime_type = 'Theft'")
r = nlq.answer_question(None, "how many thefts?")
assert r["answer"] == f"AI: Count: {n}.", r["answer"]          # narrated once, not twice
nlq.get_llm = lambda: FakeLLM("SELECT password FROM cases, users")
from app.database import SessionLocal
r = nlq.answer_question(SessionLocal(), "passwords?")
assert "password" not in str(r).lower().replace("passwords?", ""), r  # fell back, no leak

# forecast: rising history projects upward, band never negative
rows = forecast.project([0, 1, 2, 3, 4, 5], date(2026, 1, 1), 3)
assert [x["date"] for x in rows] == ["2026-01-02", "2026-01-03", "2026-01-04"]
assert rows[0]["predicted_count"] == 6.0 and rows[0]["lower_bound"] >= 0
assert forecast.get_forecast(horizon_days=30) and forecast.last_error is None
print("ok")
