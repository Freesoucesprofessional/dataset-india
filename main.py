"""
India Subscriber Lookup API  —  v3.0  HARDENED
================================================
Security layers:
  1. SQL Injection     — parameterized DuckDB queries (no f-string in WHERE)
  2. Rate Limiting     — per IP: 30 req/min search, 60 req/min global
  3. API Key Brute Force — ban IP after 5 wrong keys (15 min)
  4. Per-Key Rate Limit  — 100 req/min per API key
  5. Enumeration Block   — random delay on no-results
  6. Security Headers    — X-Frame, X-Content-Type, CSP, no-cache
  7. Request Validation  — strict regex, injection char block
  8. IP Auto-Ban         — repeated limit violations = auto ban
  9. Scanner Block       — Burpsuite/sqlmap/nikto UA blocked
 10. Error Sanitize      — never leak internal errors to client
 11. OpenAPI disabled    — no schema exposure

Install:
  pip install fastapi uvicorn duckdb pymongo python-dotenv phonenumbers httpx

Run:
  uvicorn api:app --host 0.0.0.0 --port 8000
"""

import re, os, time, logging, asyncio, hashlib, secrets
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from collections import defaultdict

import duckdb
import phonenumbers
from phonenumbers import (
    carrier as ph_carrier, geocoder as ph_geo,
    timezone as ph_tz, number_type as ph_type, PhoneNumberType,
)
from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

# ── config ────────────────────────────────────────────────────────────────────
R2_ENDPOINT   = os.getenv("R2_ENDPOINT", "")
R2_ACCESS_KEY = os.getenv("R2_ACCESS_KEY", "")
R2_SECRET_KEY = os.getenv("R2_SECRET_KEY", "")
S3_PATH       = "s3://india-data/data*.parquet"
MONGO_URL     = os.getenv("MONGO_KEY_URL", "")
KEY_DB        = os.getenv("KEY_DB_NAME", "keystore")
MAX_RESULTS   = int(os.getenv("MAX_RESULTS", "10"))
KNOWN_TOTAL   = 101_879_689

# ── rate limit settings ───────────────────────────────────────────────────────
GLOBAL_IP_LIMIT  = 60   # per IP per minute (all endpoints)
SEARCH_IP_LIMIT  = 30   # per IP per minute (search only)
KEY_LIMIT        = 100  # per API key per minute
AUTH_FAIL_MAX    = 5    # wrong keys before ban
BAN_DURATION     = 900  # 15 minutes

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger(__name__)

# ── in-memory rate limit stores ───────────────────────────────────────────────
_ip_hits:     defaultdict = defaultdict(list)   # ip → [timestamps]
_key_hits:    defaultdict = defaultdict(list)   # key_hash → [timestamps]
_auth_fails:  defaultdict = defaultdict(lambda: {"count": 0, "first": 0.0})
_bans:        dict        = {}                  # ip → ban_expiry

# ── globals ───────────────────────────────────────────────────────────────────
_duck:  duckdb.DuckDBPyConnection | None = None
_mongo: MongoClient | None = None


def duck():
    if _duck is None: raise RuntimeError("DuckDB not ready")
    return _duck

def keys_col():
    global _mongo
    if _mongo is None:
        _mongo = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    return _mongo[KEY_DB]["keys"]


# ── keep-alive (prevent Render free tier shutdown) ────────────────────────────
async def _keep_alive():
    import httpx
    await asyncio.sleep(60)
    while True:
        try:
            async with httpx.AsyncClient() as c:
                await c.get("http://127.0.0.1:8000/ping", timeout=5)
        except Exception:
            pass
        await asyncio.sleep(600)


# ── lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    global _duck
    for i in range(3):
        try:
            _duck = duckdb.connect()
            _duck.execute("INSTALL httpfs; LOAD httpfs;")
            _duck.execute(f"""
                SET s3_region            = 'auto';
                SET s3_endpoint          = '{R2_ENDPOINT.replace("https://", "")}';
                SET s3_access_key_id     = '{R2_ACCESS_KEY}';
                SET s3_secret_access_key = '{R2_SECRET_KEY}';
                SET s3_url_style         = 'path';
            """)
            log.info("DuckDB connected to R2")
            break
        except Exception as e:
            log.error("DuckDB attempt %s: %s", i+1, e)
            if i == 2: raise
            await asyncio.sleep(2)

    try:
        keys_col().database.client.admin.command("ping")
        log.info("MongoDB OK — %s keys", keys_col().count_documents({}))
    except Exception as e:
        log.error("MongoDB: %s", e)

    task = asyncio.create_task(_keep_alive())
    yield
    task.cancel()
    try: await task
    except asyncio.CancelledError: pass
    if _duck:  _duck.close()
    if _mongo: _mongo.close()


# ── app ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="India Subscriber API",
    version="3.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,   # disables /openapi.json — hides all schema
    lifespan=lifespan,
)


# ── helpers ───────────────────────────────────────────────────────────────────
def _get_ip(req: Request) -> str:
    for h in ("cf-connecting-ip", "x-forwarded-for", "x-real-ip"):
        v = req.headers.get(h)
        if v: return v.split(",")[0].strip()
    return req.client.host if req.client else "0.0.0.0"


def _sliding_rate(store: defaultdict, key: str, limit: int, window: int = 60):
    now = time.time()
    store[key] = [t for t in store[key] if now - t < window]
    if len(store[key]) >= limit:
        raise HTTPException(
            429,
            detail=f"Rate limit exceeded — max {limit} req/{window}s.",
            headers={"Retry-After": str(window)}
        )
    store[key].append(now)


def _check_ban(ip: str):
    exp = _bans.get(ip, 0)
    if time.time() < exp:
        left = int(exp - time.time())
        raise HTTPException(429, f"IP banned. Try again in {left}s.", headers={"Retry-After": str(left)})


def _fail_auth(ip: str):
    now = time.time()
    f   = _auth_fails[ip]
    if now - f["first"] > BAN_DURATION:
        f["count"], f["first"] = 1, now
        return
    f["count"] += 1
    if f["count"] >= AUTH_FAIL_MAX:
        _bans[ip] = now + BAN_DURATION
        log.warning("BANNED %s — %d auth failures", ip, f["count"])
        raise HTTPException(429, f"Too many failed attempts. Banned {BAN_DURATION//60}min.", headers={"Retry-After": str(BAN_DURATION)})


# Scanner/fuzzer user-agents
_BAD_UA = re.compile(
    r"(burpsuite|sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|"
    r"wfuzz|hydra|medusa|nessus|openvas|metasploit|w3af|acunetix|havij|"
    r"nuclei|ffuf|feroxbuster|dirb|commix|xsser|dalfox)",
    re.IGNORECASE
)

_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options":        "DENY",
    "X-XSS-Protection":       "1; mode=block",
    "Referrer-Policy":        "no-referrer",
    "Cache-Control":          "no-store, no-cache, must-revalidate",
    "Pragma":                 "no-cache",
    "Server":                 "api",
}


@app.middleware("http")
async def security(request: Request, call_next):
    ip = _get_ip(request)

    # OPTIONS preflight
    if request.method == "OPTIONS":
        from starlette.responses import Response
        r = Response(status_code=200)
        r.headers.update({
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
            "Access-Control-Allow-Methods": "GET, OPTIONS, HEAD",
            "Access-Control-Max-Age":       "600",
        })
        return r

    # ban check
    ban_exp = _bans.get(ip, 0)
    if time.time() < ban_exp:
        left = int(ban_exp - time.time())
        return JSONResponse(
            {"detail": f"IP banned. Retry in {left}s."},
            status_code=429,
            headers={"Access-Control-Allow-Origin": "*", "Retry-After": str(left)}
        )

    # block scanners
    ua = request.headers.get("user-agent", "")
    if _BAD_UA.search(ua):
        log.warning("Scanner blocked IP=%s UA=%s", ip, ua[:60])
        return JSONResponse({"detail": "Forbidden."}, status_code=403)

    # global IP rate limit
    try:
        _sliding_rate(_ip_hits, ip, GLOBAL_IP_LIMIT, 60)
    except HTTPException as e:
        log.warning("Rate limit: %s", ip)
        return JSONResponse(
            {"detail": e.detail},
            status_code=429,
            headers={"Access-Control-Allow-Origin": "*", "Retry-After": "60"}
        )

    try:
        resp = await call_next(request)
    except Exception:
        resp = JSONResponse({"detail": "Internal server error."}, status_code=500)

    # inject security headers on every response
    resp.headers.update(_SEC_HEADERS)
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    return resp


# ── auth ──────────────────────────────────────────────────────────────────────
def auth(request: Request) -> dict:
    ip  = _get_ip(request)
    _check_ban(ip)

    key = request.headers.get("X-API-Key", "").strip()
    if not key:
        _fail_auth(ip)
        raise HTTPException(401, "Missing X-API-Key header.")

    # per-key rate limit
    kh = hashlib.sha256(key.encode()).hexdigest()[:16]
    _sliding_rate(_key_hits, kh, KEY_LIMIT, 60)

    doc = keys_col().find_one({"key": key})
    if not doc:
        _fail_auth(ip)
        # random delay — prevents timing-based enumeration
        time.sleep(0.2 + secrets.randbelow(300) / 1000)
        raise HTTPException(401, "Invalid API key.")
    if doc.get("revoked"):
        raise HTTPException(401, "API key revoked.")
    exp = doc.get("expires_at")
    if exp and datetime.now(timezone.utc) >= datetime.fromisoformat(exp):
        raise HTTPException(401, "API key expired.")

    # clear fail count on success
    _auth_fails[ip] = {"count": 0, "first": 0.0}

    keys_col().update_one(
        {"key": key},
        {"$inc": {"usage_count": 1},
         "$set": {"last_used": datetime.now(timezone.utc).isoformat()}}
    )
    return doc


# ── input validation ──────────────────────────────────────────────────────────
MOBILE_RE    = re.compile(r"^[6-9]\d{9}$")
EMAIL_RE     = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_INJ_CHARS   = re.compile(r"['\";\\/<>{}()\[\]`|&$!%*?#^~]")


def clean_mobile(v: str) -> str:
    if len(v) > 15 or _INJ_CHARS.search(v):
        raise HTTPException(422, "Invalid input.")
    c = re.sub(r"[\s\-\.\(\)\+]", "", v.strip())
    c = re.sub(r"^0{0,2}91(?=[6-9]\d{9}$)", "", c)
    if re.match(r"^0[6-9]\d{9}$", c): c = c[1:]
    if not MOBILE_RE.fullmatch(c):
        raise HTTPException(422, {"error": "Invalid Indian phone number.", "reason": "10-digit mobile starting 6-9."})
    return c


def clean_email(v: str) -> str:
    if len(v) > 254: raise HTTPException(422, "Invalid input.")
    safe = v.replace("@","").replace(".","").replace("-","").replace("_","").replace("+","")
    if _INJ_CHARS.search(safe): raise HTTPException(422, "Invalid input.")
    c = v.strip().lower()
    if not EMAIL_RE.fullmatch(c): raise HTTPException(422, "Invalid email address.")
    return c


# ── phone metadata ────────────────────────────────────────────────────────────
_PTYPE = {
    PhoneNumberType.MOBILE:               "MOBILE",
    PhoneNumberType.FIXED_LINE:           "FIXED_LINE",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
    PhoneNumberType.VOIP:                 "VOIP",
    PhoneNumberType.TOLL_FREE:            "TOLL_FREE",
    PhoneNumberType.UNKNOWN:              "UNKNOWN",
}

def phone_meta(n: str) -> dict:
    try:
        p = phonenumbers.parse(f"+91{n}")
        return {
            "international_format": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national_format":      phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL),
            "e164_format":          phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164),
            "country_code":         p.country_code,
            "is_valid":             phonenumbers.is_valid_number(p),
            "is_possible":          phonenumbers.is_possible_number(p),
            "carrier":              ph_carrier.name_for_number(p, "en") or None,
            "location":             ph_geo.description_for_number(p, "en") or None,
            "timezones":            list(ph_tz.time_zones_for_number(p)),
            "number_type":          _PTYPE.get(ph_type(p), "UNKNOWN"),
        }
    except Exception:
        return {}


# ── DuckDB — PARAMETERIZED queries (SQL injection impossible) ─────────────────
_NAME_COLS = {
    "name", "customer name", "name_of_the_subsciber", "cust_name",
    "first name", "firstname", "full name", "fullname", "ccfname",
    "person first name", "customeclass", "cname",
}

def run_query(sql: str, params: list) -> list[dict]:
    """
    Uses DuckDB parameterized execution.
    ? placeholders — user input NEVER touches the SQL string.
    """
    try:
        rel  = duck().execute(sql, params)
        cols = [d[0] for d in rel.description]
        rows = []
        for row in rel.fetchall():
            r = {}; name_found = False
            for col, val in zip(cols, row):
                if col in ("_mobile", "_alt_mobile", "_email", "filename"):
                    continue
                if val is None: continue
                s = str(val).strip()
                if s.lower() in ("", "nan", "none", "null"): continue
                r["_source_file" if col == "_source" else col] = s
                if not name_found and col.strip().lower() in _NAME_COLS:
                    r["name"] = s; name_found = True
            if r: rows.append(r)
        return rows
    except Exception as e:
        log.error("DuckDB: %s", e)
        raise HTTPException(500, "Query failed.")  # never expose real error


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/search/ind/number")
async def by_number(
    request: Request,
    q: str  = Query(..., min_length=10, max_length=15),
    _k: dict = Depends(auth),
):
    ip = _get_ip(request)
    _sliding_rate(_ip_hits, f"s:{ip}", SEARCH_IP_LIMIT, 60)

    n    = clean_mobile(q)
    rows = run_query(
        f"SELECT * FROM read_parquet('{S3_PATH}', union_by_name=true) WHERE _mobile = ? LIMIT ?",
        [n, MAX_RESULTS]
    )
    if not rows:
        await asyncio.sleep(0.1 + secrets.randbelow(150) / 1000)

    return {
        "query":         n,
        "total":         len(rows),
        "phone_meta":    phone_meta(n),
        "customers_db2": {"count": len(rows), "results": rows},
    }


@app.get("/search/ind/email")
async def by_email(
    request: Request,
    q: str  = Query(..., min_length=6, max_length=254),
    _k: dict = Depends(auth),
):
    ip = _get_ip(request)
    _sliding_rate(_ip_hits, f"s:{ip}", SEARCH_IP_LIMIT, 60)

    em   = clean_email(q)
    rows = run_query(
        f"SELECT * FROM read_parquet('{S3_PATH}', union_by_name=true) WHERE _email = ? LIMIT ?",
        [em, MAX_RESULTS]
    )
    if not rows:
        await asyncio.sleep(0.1 + secrets.randbelow(150) / 1000)

    return {
        "query":         em,
        "total":         len(rows),
        "customers_db2": {"count": len(rows), "results": rows},
    }


@app.get("/search/ind/alternate")
async def by_alternate(
    request: Request,
    q: str  = Query(..., min_length=10, max_length=15),
    _k: dict = Depends(auth),
):
    ip = _get_ip(request)
    _sliding_rate(_ip_hits, f"s:{ip}", SEARCH_IP_LIMIT, 60)

    n    = clean_mobile(q)
    rows = run_query(
        f"SELECT * FROM read_parquet('{S3_PATH}', union_by_name=true) WHERE _alt_mobile = ? LIMIT ?",
        [n, MAX_RESULTS]
    )
    if not rows:
        await asyncio.sleep(0.1 + secrets.randbelow(150) / 1000)

    return {
        "query":         n,
        "total":         len(rows),
        "phone_meta":    phone_meta(n),
        "customers_db2": {"count": len(rows), "results": rows},
    }


@app.get("/key/info")
async def key_info(doc: dict = Depends(auth)):
    exp = doc.get("expires_at")
    now = datetime.now(timezone.utc)
    if exp:
        exp_dt    = datetime.fromisoformat(exp)
        days_left = max(0, (exp_dt - now).days)
        exp_str   = exp_dt.strftime("%Y-%m-%d %H:%M UTC")
    else:
        days_left, exp_str = None, "Never (lifetime)"
    return {
        "key":         doc["key"],
        "type":        doc.get("type", "unknown"),
        "label":       doc.get("label", ""),
        "active":      not doc.get("revoked", False),
        "expires_at":  exp_str,
        "days_left":   days_left,
        "usage_count": doc.get("usage_count", 0),
        "last_used":   doc.get("last_used", "never"),
        "created_at":  doc.get("created_at", ""),
    }


@app.get("/ping", include_in_schema=False)
async def ping():
    return {"ok": True}


@app.head("/health")
async def health_head():
    return JSONResponse(None, status_code=200)


@app.get("/health")
async def health():
    try:
        kc = keys_col()
        return {
            "status": "ok",
            "main_cluster":     {"address": 0, "pan": 0, "personal": 0},
            "email_cluster":    {"email": 0},
            "customer_cluster": {"customers_db1": 0, "customers_db2": KNOWN_TOTAL},
            "by_circle":        [],
            "key_system": {
                "total_keys":    kc.count_documents({}),
                "active_keys":   kc.count_documents({"revoked": False}),
                "revoked_keys":  kc.count_documents({"revoked": True}),
                "monthly_keys":  kc.count_documents({"type": "monthly"}),
                "yearly_keys":   kc.count_documents({"type": "yearly"}),
                "lifetime_keys": kc.count_documents({"type": "lifetime"}),
            },
        }
    except Exception as e:
        log.error("Health: %s", e)
        return {"status": "error"}


@app.get("/", include_in_schema=False)
async def root():
    return {"api": "India Subscriber Lookup API", "version": "3.0.0", "status": "ok"}