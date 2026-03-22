"""
India Subscriber Lookup API  —  v4.0
512MB Render free tier compatible.

Strategy:
  - NO index preloaded in RAM at startup
  - Each query fetches only 1 small index part from R2 (~10MB avg)
  - Then fetches only the matching data files
  - Max RAM per query: ~150MB (idx_98 worst case)
"""

import re, os, logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

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

# ── config ────────────────────────────────────────────────
R2_ENDPOINT   = os.getenv("R2_ENDPOINT", "")
R2_ACCESS_KEY = os.getenv("R2_ACCESS_KEY", "")
R2_SECRET_KEY = os.getenv("R2_SECRET_KEY", "")
BUCKET        = "india-data"
INDEX_PARTS   = "index_parts"
MONGO_URL     = os.getenv("MONGO_KEY_URL", "")
KEY_DB        = os.getenv("KEY_DB_NAME", "keystore")
MAX_RESULTS   = int(os.getenv("MAX_RESULTS", "10"))
KNOWN_TOTAL   = 99_413_949

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger(__name__)

# ── globals ───────────────────────────────────────────────
_duck:  duckdb.DuckDBPyConnection | None = None
_mongo: MongoClient | None = None


def duck():
    if _duck is None:
        raise RuntimeError("DuckDB not ready")
    return _duck


def keys_col():
    global _mongo
    if _mongo is None:
        _mongo = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    return _mongo[KEY_DB]["keys"]


# ── lifespan ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    global _duck

    # in-memory only — no index preload
    _duck = duckdb.connect()
    _duck.execute("SET memory_limit = '350MB';")
    _duck.execute("SET threads = 1;")
    _duck.execute("INSTALL httpfs; LOAD httpfs;")
    _duck.execute(f"""
        SET s3_region            = 'auto';
        SET s3_endpoint          = '{R2_ENDPOINT.replace("https://", "")}';
        SET s3_access_key_id     = '{R2_ACCESS_KEY}';
        SET s3_secret_access_key = '{R2_SECRET_KEY}';
        SET s3_url_style         = 'path';
    """)
    log.info("DuckDB ready — on-demand index mode ✅")

    try:
        keys_col().database.client.admin.command("ping")
        n = keys_col().count_documents({})
        log.info("MongoDB OK — %s keys", n)
    except Exception as e:
        log.error("MongoDB: %s", e)

    yield
    if _duck:  _duck.close()
    if _mongo: _mongo.close()


# ── app ───────────────────────────────────────────────────
app = FastAPI(
    title="India Subscriber API",
    version="4.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


# ── CORS ──────────────────────────────────────────────────
@app.middleware("http")
async def cors(request: Request, call_next):
    if request.method == "OPTIONS":
        from starlette.responses import Response
        r = Response(status_code=200)
        r.headers.update({
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
            "Access-Control-Max-Age":       "600",
        })
        return r
    try:
        resp = await call_next(request)
    except Exception as exc:
        resp = JSONResponse({"detail": str(exc)}, status_code=500)
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, HEAD"
    return resp


# ── auth ──────────────────────────────────────────────────
def auth(request: Request) -> dict:
    key = request.headers.get("X-API-Key", "").strip()
    if not key:
        raise HTTPException(401, "Missing X-API-Key header.")
    doc = keys_col().find_one({"key": key})
    if not doc:
        raise HTTPException(401, "Invalid API key.")
    if doc.get("revoked"):
        raise HTTPException(401, "API key revoked.")
    exp = doc.get("expires_at")
    if exp and datetime.now(timezone.utc) >= datetime.fromisoformat(exp):
        raise HTTPException(401, "API key expired.")
    keys_col().update_one(
        {"key": key},
        {"$inc": {"usage_count": 1},
         "$set": {"last_used": datetime.now(timezone.utc).isoformat()}}
    )
    return doc


# ── validation ────────────────────────────────────────────
MOBILE_RE = re.compile(r"^[6-9]\d{9}$")
EMAIL_RE  = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def clean_mobile(v: str) -> str:
    c = re.sub(r"[\s\-\.\(\)\+]", "", v.strip())
    c = re.sub(r"^0{0,2}91(?=[6-9]\d{9}$)", "", c)
    if re.match(r"^0[6-9]\d{9}$", c):
        c = c[1:]
    if not MOBILE_RE.fullmatch(c):
        raise HTTPException(422, {
            "error":   "Invalid Indian phone number.",
            "input":   v,
            "reason":  "Must be 10-digit Indian mobile starting 6-9.",
            "accepted_formats": [
                "9811063283", "+919811063283",
                "919811063283", "09811063283",
            ],
        })
    return c


def clean_email(v: str) -> str:
    c = v.strip().lower()
    if not EMAIL_RE.fullmatch(c):
        raise HTTPException(422, f"'{v}' is not a valid email address.")
    return c


# ── phone metadata ────────────────────────────────────────
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
    except Exception as e:
        log.warning("phone_meta: %s", e)
        return {}


# ── name cols ─────────────────────────────────────────────
_NAME_COLS = {
    "name", "customer name", "name_of_the_subsciber", "cust_name",
    "first name", "firstname", "full name", "fullname", "ccfname",
    "person first name", "customeclass", "cname",
}


# ── core: find files via index part ───────────────────────
def find_files_by_mobile(mobile: str) -> list[str]:
    """Fetch only the small index part for this prefix."""
    prefix   = mobile[:2]
    idx_url  = f"s3://{BUCKET}/{INDEX_PARTS}/idx_{prefix}.parquet"
    try:
        rows = duck().execute(f"""
            SELECT DISTINCT _file
            FROM read_parquet('{idx_url}')
            WHERE _mobile = ?
            LIMIT 20
        """, [mobile]).fetchall()
        return [r[0] for r in rows]
    except Exception as e:
        log.error("find_files_by_mobile: %s", e)
        return []


def find_files_by_alt(mobile: str) -> list[str]:
    """Alt mobile — search by prefix of alt number."""
    prefix  = mobile[:2]
    idx_url = f"s3://{BUCKET}/{INDEX_PARTS}/idx_{prefix}.parquet"
    try:
        rows = duck().execute(f"""
            SELECT DISTINCT _file
            FROM read_parquet('{idx_url}')
            WHERE _alt_mobile = ?
            LIMIT 20
        """, [mobile]).fetchall()
        return [r[0] for r in rows]
    except Exception as e:
        log.error("find_files_by_alt: %s", e)
        return []


def find_files_by_email(email: str) -> list[str]:
    """Email — must scan all index parts (not partitioned by email)."""
    idx_url = f"s3://{BUCKET}/{INDEX_PARTS}/idx_*.parquet"
    try:
        rows = duck().execute(f"""
            SELECT DISTINCT _file
            FROM read_parquet('{idx_url}', union_by_name=true)
            WHERE _email = ?
            LIMIT 20
        """, [email]).fetchall()
        return [r[0] for r in rows]
    except Exception as e:
        log.error("find_files_by_email: %s", e)
        return []


def fetch_rows(files: list[str], col: str, val: str) -> list[dict]:
    """Fetch full rows from R2 for only the matching data files."""
    if not files:
        return []

    s3_files  = [f"s3://{BUCKET}/{f}" for f in files]
    file_list = ", ".join(f"'{f}'" for f in s3_files)

    try:
        rel  = duck().execute(f"""
            SELECT * FROM read_parquet([{file_list}], union_by_name=true)
            WHERE {col} = ?
            LIMIT {MAX_RESULTS}
        """, [val])
        cols = [d[0] for d in rel.description]
        rows = []

        for row in rel.fetchall():
            r = {}
            name_found = False
            for c, v in zip(cols, row):
                if c in ("_mobile", "_alt_mobile", "_email", "filename"):
                    continue
                if v is None:
                    continue
                s = str(v).strip()
                if s.lower() in ("", "nan", "none", "null"):
                    continue
                display_col = "_source_file" if c == "_source" else c
                r[display_col] = s
                if not name_found and c.strip().lower() in _NAME_COLS:
                    r["name"] = s
                    name_found = True
            if r:
                rows.append(r)

        return rows
    except Exception as e:
        log.error("fetch_rows: %s", e)
        raise HTTPException(500, f"Query error: {e}")


# ── search endpoints ──────────────────────────────────────

@app.get("/search/ind/number", tags=["Search"])
async def by_number(
    q:  str  = Query(..., min_length=10, max_length=15, example="9811063283"),
    _k: dict = Depends(auth),
):
    n     = clean_mobile(q)
    files = find_files_by_mobile(n)
    rows  = fetch_rows(files, "_mobile", n)
    return {
        "query":      n,
        "total":      len(rows),
        "phone_meta": phone_meta(n),
        "customers_db2": {"count": len(rows), "results": rows},
    }


@app.get("/search/ind/email", tags=["Search"])
async def by_email(
    q:  str  = Query(..., min_length=6, max_length=254, example="test@gmail.com"),
    _k: dict = Depends(auth),
):
    em    = clean_email(q)
    files = find_files_by_email(em)
    rows  = fetch_rows(files, "_email", em)
    return {
        "query": em,
        "total": len(rows),
        "customers_db2": {"count": len(rows), "results": rows},
    }


@app.get("/search/ind/alternate", tags=["Search"])
async def by_alternate(
    q:  str  = Query(..., min_length=10, max_length=15, example="9810766029"),
    _k: dict = Depends(auth),
):
    n     = clean_mobile(q)
    files = find_files_by_alt(n)
    rows  = fetch_rows(files, "_alt_mobile", n)
    return {
        "query":      n,
        "total":      len(rows),
        "phone_meta": phone_meta(n),
        "customers_db2": {"count": len(rows), "results": rows},
    }


# ── key info ──────────────────────────────────────────────
@app.get("/key/info", tags=["Key"])
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


# ── health ────────────────────────────────────────────────
@app.head("/health")
async def health_head():
    return JSONResponse(None, status_code=200)


@app.get("/health", tags=["Info"])
async def health():
    try:
        kc = keys_col()
        return {
            "status": "ok",
            "main_cluster":  {"address": 0, "pan": 0, "personal": 0},
            "email_cluster": {"email": 0},
            "customer_cluster": {
                "customers_db1": 0,
                "customers_db2": KNOWN_TOTAL,
            },
            "by_circle": [],
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
        return {"status": "error", "detail": str(e)}


# ── root ──────────────────────────────────────────────────
@app.get("/", tags=["Info"])
async def root():
    return {
        "api":           "India Subscriber Lookup API",
        "version":       "4.0.0",
        "total_records": KNOWN_TOTAL,
        "endpoints": {
            "by_number":    "GET /search/ind/number?q=9811063283",
            "by_email":     "GET /search/ind/email?q=test@gmail.com",
            "by_alternate": "GET /search/ind/alternate?q=9810766029",
            "key_info":     "GET /key/info",
            "health":       "GET /health",
        },
    }