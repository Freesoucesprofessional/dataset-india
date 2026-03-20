"""
India Subscriber Lookup API — Standalone
==========================================
- DuckDB + Cloudflare R2  → data (india-data/data*.parquet)
- MongoDB keystore DB      → API key validation only
- Auth: X-API-Key header
"""

import re
import os
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import duckdb
from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

R2_ENDPOINT   = os.getenv("R2_ENDPOINT")
R2_ACCESS_KEY = os.getenv("R2_ACCESS_KEY")
R2_SECRET_KEY = os.getenv("R2_SECRET_KEY")
S3_PATH       = "s3://india-data/data*.parquet"

MONGO_KEY_URL = os.getenv("MONGO_KEY_URL")   # same connection string as old API
KEY_DB_NAME   = os.getenv("KEY_DB_NAME", "keystore")

MAX_RESULTS   = int(os.getenv("MAX_RESULTS", "10"))

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# DuckDB
# ─────────────────────────────────────────────────────────────────────────────

duck_con = None

def get_duck():
    global duck_con
    if duck_con is None:
        raise RuntimeError("DuckDB not initialised")
    return duck_con

# ─────────────────────────────────────────────────────────────────────────────
# MongoDB — keys only
# ─────────────────────────────────────────────────────────────────────────────

_key_client: MongoClient | None = None

def get_keys_col() -> Collection:
    global _key_client
    if _key_client is None:
        _key_client = MongoClient(MONGO_KEY_URL, serverSelectionTimeoutMS=5000)
    return _key_client[KEY_DB_NAME]["keys"]

# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app):
    global duck_con

    duck_con = duckdb.connect()
    duck_con.execute("INSTALL httpfs; LOAD httpfs;")
    duck_con.execute(f"""
        SET s3_region='auto';
        SET s3_endpoint='{R2_ENDPOINT.replace("https://", "")}';
        SET s3_access_key_id='{R2_ACCESS_KEY}';
        SET s3_secret_access_key='{R2_SECRET_KEY}';
        SET s3_url_style='path';
    """)
    logger.info("✓ DuckDB → R2 india-data/data*.parquet")

    try:
        col = get_keys_col()
        col.database.client.admin.command("ping")
        logger.info("✓ MongoDB keystore — %s keys", col.count_documents({}))
    except Exception as e:
        logger.error("✗ MongoDB: %s", e)

    yield

    if duck_con:
        duck_con.close()
    if _key_client:
        _key_client.close()

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="India Subscriber API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

# CORS added first so it wraps ALL responses including 401/422/500
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Force CORS headers on every response — including error responses
# FastAPI CORSMiddleware sometimes strips headers from non-200 responses
@app.middleware("http")
async def force_cors(request: Request, call_next):
    if request.method == "OPTIONS":
        from fastapi.responses import Response as FR
        r = FR(status_code=200)
        r.headers["Access-Control-Allow-Origin"]  = "*"
        r.headers["Access-Control-Allow-Headers"] = "*"
        r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, HEAD"
        return r
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, HEAD"
    return response

# ─────────────────────────────────────────────────────────────────────────────
# Auth — X-API-Key
# ─────────────────────────────────────────────────────────────────────────────

def verify_api_key(request: Request) -> dict:
    raw = request.headers.get("X-API-Key", "").strip()
    if not raw:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header.")

    col = get_keys_col()
    doc = col.find_one({"key": raw})
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    if doc.get("revoked"):
        raise HTTPException(status_code=401, detail="API key has been revoked.")

    expiry = doc.get("expires_at")
    if expiry and datetime.now(timezone.utc) >= datetime.fromisoformat(expiry):
        raise HTTPException(status_code=401, detail="API key has expired.")

    # track usage
    col.update_one(
        {"key": raw},
        {"$inc": {"usage_count": 1},
         "$set": {"last_used": datetime.now(timezone.utc).isoformat()}},
    )
    return doc

# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────

IND_PHONE_REGEX = re.compile(r"^[6-9]\d{9}$")
EMAIL_REGEX     = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

def validate_ind_phone(value: str) -> str:
    """
    Normalises any Indian number format to 10 digits.
    Accepted:
      9811063283        (10 digits, plain)
      +919811063283     (+91 prefix)
      919811063283      (91 prefix, 12 digits)
      09811063283       (leading 0)
      +91 98110 63283   (spaces/dashes stripped)
    Rejects any non-Indian or invalid number.
    """
    # strip spaces, dashes, dots, brackets, plus sign
    cleaned = re.sub(r"[\s\-\.\(\)\+]", "", value.strip())

    # strip country code 91 (handles: 91XXXXXXXXXX or 091XXXXXXXXXX or 0091XXXXXXXXXX)
    if re.match(r"^0{0,2}91[6-9]\d{9}$", cleaned):
        cleaned = re.sub(r"^0{0,2}91", "", cleaned)

    # strip single leading 0 (e.g. 09811063283 → 9811063283)
    if re.match(r"^0[6-9]\d{9}$", cleaned):
        cleaned = cleaned[1:]

    if not IND_PHONE_REGEX.fullmatch(cleaned):
        raise HTTPException(
            status_code=422,
            detail={
                "error":            "Invalid Indian phone number.",
                "input":            value,
                "reason":           "Must be a valid 10-digit Indian mobile starting with 6, 7, 8, or 9.",
                "accepted_formats": [
                    "9811063283",
                    "+919811063283",
                    "919811063283",
                    "09811063283",
                    "+91 98110 63283",
                ],
            },
        )
    return cleaned
def validate_email(value: str) -> str:
    cleaned = value.strip()
    if not EMAIL_REGEX.fullmatch(cleaned):
        raise HTTPException(422, detail=f"'{value}' is not a valid email address.")
    return cleaned.lower()

# ─────────────────────────────────────────────────────────────────────────────
# DuckDB query helper
# ─────────────────────────────────────────────────────────────────────────────

def duck_query(sql: str) -> list[dict]:
    try:
        rel  = get_duck().execute(sql)
        cols = [d[0] for d in rel.description]
        return [
            {col: (str(val) if val is not None else None)
             for col, val in zip(cols, row)}
            for row in rel.fetchall()
        ]
    except Exception as e:
        logger.error("DuckDB error: %s", e)
        raise HTTPException(status_code=500, detail=f"Query error: {str(e)}")

# ─────────────────────────────────────────────────────────────────────────────
# Search endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/search/ind/number", tags=["Search"])
async def search_by_phone(
    request: Request,
    q: str = Query(..., min_length=10, max_length=15, example="9811063283"),
    _k: dict = Depends(verify_api_key),
):
    """Search by primary phone number. Returns customers_db2 shape for frontend."""
    n = validate_ind_phone(q)
    rows = duck_query(f"""
        SELECT telephone_number, name_of_the_subsciber AS name, date_of_birth AS dob,
               father_s_husband_s_name AS father_husband_name,
               address1, address2, address3, city, postal, state,
               alternate_phone_no AS alternate_phone, e_mail_id AS email,
               gender, connection_type, service_provider, circle,
               imsi_no, bank_name, bank_a_c_no
        FROM read_parquet('{S3_PATH}')
        WHERE CAST(telephone_number AS VARCHAR) LIKE '%{n[-10:]}'
        LIMIT {MAX_RESULTS}
    """)
    if not rows:
        raise HTTPException(404, detail=f"No record found for: {n}")
    from phonenumbers import parse as ph_parse, format_number, PhoneNumberFormat, is_valid_number, is_possible_number
    from phonenumbers import carrier as ph_carrier, geocoder as ph_geo
    from phonenumbers import timezone as ph_tz, number_type as ph_type
    phone_meta = get_phone_meta(n)
    return {
        "query":         n,
        "total":         len(rows),
        "phone_meta":    phone_meta,
        "customers_db2": {"count": len(rows), "results": rows},
    }


@app.get("/search/ind/email", tags=["Search"])
async def search_by_email(
    request: Request,
    q: str = Query(..., min_length=6, max_length=254, example="test@gmail.com"),
    _k: dict = Depends(verify_api_key),
):
    """Search by email. Returns customers_db2 shape for frontend."""
    em = validate_email(q)
    rows = duck_query(f"""
        SELECT telephone_number, name_of_the_subsciber AS name, date_of_birth AS dob,
               address1, address2, city, state,
               alternate_phone_no AS alternate_phone, e_mail_id AS email,
               gender, connection_type, service_provider, circle
        FROM read_parquet('{S3_PATH}')
        WHERE LOWER(CAST(e_mail_id AS VARCHAR)) = '{em}'
        LIMIT {MAX_RESULTS}
    """)
    if not rows:
        raise HTTPException(404, detail=f"No record found for: {em}")
    return {
        "query":         em,
        "total":         len(rows),
        "customers_db2": {"count": len(rows), "results": rows},
    }


@app.get("/search/ind/alternate", tags=["Search"])
async def search_by_alternate(
    request: Request,
    q: str = Query(..., min_length=10, max_length=15, example="9810766029"),
    _k: dict = Depends(verify_api_key),
):
    """Search by alternate phone. Returns customers_db2 shape for frontend."""
    n = validate_ind_phone(q)
    rows = duck_query(f"""
        SELECT telephone_number, name_of_the_subsciber AS name, date_of_birth AS dob,
               address1, address2, city, state,
               alternate_phone_no AS alternate_phone, e_mail_id AS email,
               gender, connection_type, service_provider, circle
        FROM read_parquet('{S3_PATH}')
        WHERE CAST(alternate_phone_no AS VARCHAR) LIKE '%{n[-10:]}'
        LIMIT {MAX_RESULTS}
    """)
    if not rows:
        raise HTTPException(404, detail=f"No record found for alternate: {n}")
    phone_meta = get_phone_meta(n)
    return {
        "query":         n,
        "total":         len(rows),
        "phone_meta":    phone_meta,
        "customers_db2": {"count": len(rows), "results": rows},
    }



# ─────────────────────────────────────────────────────────────────────────────
# Key info
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/key/info", tags=["Key"])
async def key_info(key_doc: dict = Depends(verify_api_key)):
    """Check your API key status, expiry and usage."""
    expiry = key_doc.get("expires_at")
    now    = datetime.now(timezone.utc)
    if expiry:
        exp_dt      = datetime.fromisoformat(expiry)
        days_left   = max(0, (exp_dt - now).days)
        expires_str = exp_dt.strftime("%Y-%m-%d %H:%M UTC")
    else:
        days_left, expires_str = None, "Never (lifetime)"
    return {
        "key":         key_doc["key"],
        "type":        key_doc.get("type", "unknown"),
        "label":       key_doc.get("label", ""),
        "active":      True,
        "expires_at":  expires_str,
        "days_left":   days_left,
        "usage_count": key_doc.get("usage_count", 0),
        "last_used":   key_doc.get("last_used", "never"),
        "created_at":  key_doc.get("created_at", ""),
    }

# ─────────────────────────────────────────────────────────────────────────────
# Health & stats (public)
# ─────────────────────────────────────────────────────────────────────────────

@app.head("/health")
async def health_head():
    return JSONResponse(content=None, status_code=200)


@app.get("/health", tags=["Info"])
async def health():
    """
    Returns HealthStats shape matching the frontend interface exactly.
    India data goes into customer_cluster.customers_db2.
    main_cluster and email_cluster are zeroed (those are old-API collections).
    """
    try:
        total = get_duck().execute(
            f"SELECT COUNT(*) FROM read_parquet('{S3_PATH}')"
        ).fetchone()[0]

        by_circle = get_duck().execute(f"""
            SELECT circle, COUNT(*) as cnt
            FROM read_parquet('{S3_PATH}')
            GROUP BY circle ORDER BY cnt DESC LIMIT 10
        """).fetchall()

        kc = get_keys_col()
        return {
            "status": "ok",
            # zeroed — these collections live on the old API
            "main_cluster":  {"address": 0, "pan": 0, "personal": 0},
            "email_cluster": {"email": 0},
            # India telecom data goes here → frontend DBCard "CUSTOMER DB2" renders it
            "customer_cluster": {
                "customers_db1": 0,
                "customers_db2": total,
            },
            "by_circle": [{"circle": r[0], "count": r[1]} for r in by_circle],
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


@app.get("/", tags=["Info"])
async def root():
    return {
        "api":     "India Subscriber Lookup API",
        "version": "1.0.0",
        "status":  "ok",
        "endpoints": {
            "search_by_phone":     "GET /search/ind/number?q=9811063283",
            "search_by_email":     "GET /search/ind/email?q=test@gmail.com",
            "search_by_alternate": "GET /search/ind/alternate?q=9810766029",
            "key_info":            "GET /key/info",
            "health":              "GET /health",
        },
    }