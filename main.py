"""
India Subscriber Lookup API  —  v2.0
======================================
Matches frontend shape in TerminalSearch.tsx / api.ts exactly.

Frontend expects from /search/ind/number:
  {
    query, total, phone_meta,
    customers_db2: { count, results: [ raw row dicts ] }
  }

Frontend expects from /health:
  {
    status, main_cluster, email_cluster,
    customer_cluster: { customers_db1, customers_db2 },
    by_circle, key_system
  }

Install:
  pip install fastapi uvicorn duckdb pymongo python-dotenv phonenumbers

.env:
  R2_ENDPOINT   = https://<account>.r2.cloudflarestorage.com
  R2_ACCESS_KEY = ...
  R2_SECRET_KEY = ...
  MONGO_KEY_URL = mongodb+srv://...
  KEY_DB_NAME   = keystore
  MAX_RESULTS   = 10

Run:
  uvicorn api:app --host 0.0.0.0 --port 8000
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

# ── config ────────────────────────────────────────────────────────────────────
R2_ENDPOINT   = os.getenv("R2_ENDPOINT", "")
R2_ACCESS_KEY = os.getenv("R2_ACCESS_KEY", "")
R2_SECRET_KEY = os.getenv("R2_SECRET_KEY", "")
S3_PATH       = "s3://india-data/data*.parquet"
MONGO_URL     = os.getenv("MONGO_KEY_URL", "")
KEY_DB        = os.getenv("KEY_DB_NAME", "keystore")
MAX_RESULTS   = int(os.getenv("MAX_RESULTS", "10"))

# total rows in your database (22.17 Crore)
# used as fallback if DuckDB COUNT(*) is slow
KNOWN_TOTAL   = 93_614_386

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger(__name__)

# ── globals ───────────────────────────────────────────────────────────────────
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


# ── lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    global _duck
    _duck = duckdb.connect()
    _duck.execute("INSTALL httpfs; LOAD httpfs;")
    _duck.execute(f"""
        SET s3_region            = 'auto';
        SET s3_endpoint          = '{R2_ENDPOINT.replace("https://", "")}';
        SET s3_access_key_id     = '{R2_ACCESS_KEY}';
        SET s3_secret_access_key = '{R2_SECRET_KEY}';
        SET s3_url_style         = 'path';
    """)
    log.info("DuckDB → R2  %s", S3_PATH)

    try:
        keys_col().database.client.admin.command("ping")
        n = keys_col().count_documents({})
        log.info("MongoDB keystore OK  —  %s keys", n)
    except Exception as e:
        log.error("MongoDB: %s", e)

    yield

    if _duck:   _duck.close()
    if _mongo:  _mongo.close()


# ── app ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="India Subscriber API",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


# ── CORS (every response including errors) ────────────────────────────────────
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


# ── auth ──────────────────────────────────────────────────────────────────────
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


# ── validation ────────────────────────────────────────────────────────────────
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
    except Exception as e:
        log.warning("phone_meta: %s", e)
        return {}


# ── DuckDB query ──────────────────────────────────────────────────────────────
def run_query(sql: str) -> list[dict]:
    """Execute SQL, return list of clean dicts (no None/nan values)."""
    try:
        rel  = duck().execute(sql)
        cols = [d[0] for d in rel.description]
        rows = []
        for row in rel.fetchall():
            r = {}
            for col, val in zip(cols, row):
                # skip internal search columns — don't expose to frontend
                if col in ("_mobile", "_alt_mobile", "_email"):
                    continue
                # clean up empty/null values
                if val is None:
                    continue
                s = str(val).strip()
                if s.lower() in ("", "nan", "none", "null"):
                    continue
                r[col] = s
            if r:
                rows.append(r)
        return rows
    except Exception as e:
        log.error("DuckDB: %s\nSQL: %s", e, sql[:200])
        raise HTTPException(500, f"Query error: {e}")


# ── search endpoints ──────────────────────────────────────────────────────────

@app.get("/search/ind/number", tags=["Search"])
async def by_number(
    q:   str  = Query(..., min_length=10, max_length=15, example="9811063283"),
    _k: dict  = Depends(auth),
):
    """
    Search by primary mobile number.
    Returns: { query, total, phone_meta, customers_db2: { count, results } }
    Frontend merges this with old API and renders under CUSTOMER DB2 card.
    """
    n    = clean_mobile(q)
    rows = run_query(f"""
        SELECT * FROM read_parquet('{S3_PATH}', union_by_name=true, filename=true)
        WHERE _mobile = '{n}'
        LIMIT {MAX_RESULTS}
    """)

    return {
        "query":      n,
        "total":      len(rows),
        "phone_meta": phone_meta(n),
        "customers_db2": {
            "count":   len(rows),
            "results": rows,
        },
    }


@app.get("/search/ind/email", tags=["Search"])
async def by_email(
    q:   str  = Query(..., min_length=6, max_length=254, example="test@gmail.com"),
    _k: dict  = Depends(auth),
):
    """
    Search by email address.
    Returns: { query, total, customers_db2: { count, results } }
    """
    em   = clean_email(q)
    rows = run_query(f"""
        SELECT * FROM read_parquet('{S3_PATH}', union_by_name=true, filename=true)
        WHERE _email = '{em}'
        LIMIT {MAX_RESULTS}
    """)

    return {
        "query": em,
        "total": len(rows),
        "customers_db2": {
            "count":   len(rows),
            "results": rows,
        },
    }


@app.get("/search/ind/alternate", tags=["Search"])
async def by_alternate(
    q:   str  = Query(..., min_length=10, max_length=15, example="9810766029"),
    _k: dict  = Depends(auth),
):
    """
    Search by alternate / second mobile number.
    Returns: { query, total, phone_meta, customers_db2: { count, results } }
    """
    n    = clean_mobile(q)
    rows = run_query(f"""
        SELECT * FROM read_parquet('{S3_PATH}', union_by_name=true, filename=true)
        WHERE _alt_mobile = '{n}'
        LIMIT {MAX_RESULTS}
    """)

    return {
        "query":      n,
        "total":      len(rows),
        "phone_meta": phone_meta(n),
        "customers_db2": {
            "count":   len(rows),
            "results": rows,
        },
    }


# ── key info ──────────────────────────────────────────────────────────────────

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


# ── health ────────────────────────────────────────────────────────────────────

@app.head("/health")
async def health_head():
    return JSONResponse(None, status_code=200)


@app.get("/health", tags=["Info"])
async def health():
    """
    Returns shape matching HealthStats interface in api.ts.
    customers_db2 = your 22.17 Crore rows.
    Frontend merges this with old API's counts.
    """
    try:
        # use known total as fast response — avoids slow COUNT(*) on 22 Cr rows
        # uncomment the line below if you want live count (slower):
        # total = duck().execute(f"SELECT COUNT(*) FROM read_parquet('{S3_PATH}', union_by_name=true, filename=true)").fetchone()[0]
        total = KNOWN_TOTAL

        kc = keys_col()
        return {
            "status": "ok",
            # zeroed — old API owns these collections
            "main_cluster":  {"address": 0, "pan": 0, "personal": 0},
            "email_cluster": {"email": 0},
            # this is what frontend renders as "CUSTOMER DB2"
            "customer_cluster": {
                "customers_db1": 0,
                "customers_db2": total,   # 22,17,00,000
            },
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


# ── root ──────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Info"])
async def root():
    return {
        "api":          "India Subscriber Lookup API",
        "version":      "2.0.0",
        "total_records": KNOWN_TOTAL,
        "endpoints": {
            "by_number":    "GET /search/ind/number?q=9811063283",
            "by_email":     "GET /search/ind/email?q=test@gmail.com",
            "by_alternate": "GET /search/ind/alternate?q=9810766029",
            "key_info":     "GET /key/info",
            "health":       "GET /health",
        },
    }