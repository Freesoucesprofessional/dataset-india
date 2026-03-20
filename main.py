"""
Subscriber Data API — FastAPI + DuckDB + Cloudflare R2
Multi-country support: pass ?country=india to search india-data bucket, etc.
"""

import os
import duckdb
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

# ─── CONFIG (set these as Environment Variables on Render) ────────────────────
R2_ENDPOINT   = os.getenv("R2_ENDPOINT")
R2_ACCESS_KEY = os.getenv("R2_ACCESS_KEY")
R2_SECRET_KEY = os.getenv("R2_SECRET_KEY")
# ─────────────────────────────────────────────────────────────────────────────

# ─── SUPPORTED COUNTRIES → bucket names ──────────────────────────────────────
# To add a new country in future, just add one line here!
COUNTRY_BUCKETS = {
    "india":     "india-data",
    "pakistan":  "pakistan-data",
    "usa":       "usa-data",
    "uk":        "uk-data",
    "uae":       "uae-data",
    # "bangladesh": "bangladesh-data",  ← just uncomment to add more
}
DEFAULT_COUNTRY = "india"
PARQUET_PATTERN = "data*.parquet"   # same pattern for ALL buckets
# ─────────────────────────────────────────────────────────────────────────────

con = None

def get_s3_path(country: str) -> str:
    country = country.lower().strip()
    if country not in COUNTRY_BUCKETS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown country '{country}'. Available: {list(COUNTRY_BUCKETS.keys())}"
        )
    bucket = COUNTRY_BUCKETS[country]
    return f"s3://{bucket}/{PARQUET_PATTERN}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global con
    con = duckdb.connect()
    con.execute("INSTALL httpfs; LOAD httpfs;")
    con.execute(f"""
        SET s3_region='auto';
        SET s3_endpoint='{R2_ENDPOINT.replace("https://", "")}';
        SET s3_access_key_id='{R2_ACCESS_KEY}';
        SET s3_secret_access_key='{R2_SECRET_KEY}';
        SET s3_url_style='path';
    """)
    print("DuckDB connected to R2 ✓")
    yield
    con.close()

app = FastAPI(
    title="Subscriber Lookup API",
    description="""
Search telecom subscriber records across multiple countries.

**Always pass `?country=` parameter.**

Examples:
- `/search/phone?number=9811063283&country=india`
- `/search/email?email=test@gmail.com&country=india`
- `/search/phone?number=03001234567&country=pakistan`
    """,
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

def row_to_dict(row, columns):
    return {col: (str(val) if val is not None else None) for col, val in zip(columns, row)}


@app.get("/", tags=["Health"])
def root():
    return {
        "status": "ok",
        "message": "Subscriber API is running",
        "available_countries": list(COUNTRY_BUCKETS.keys())
    }


@app.get("/countries", tags=["Info"])
def list_countries():
    """Returns all supported countries and their R2 bucket names."""
    return {"countries": [{"country": k, "bucket": v} for k, v in COUNTRY_BUCKETS.items()]}


@app.get("/search/phone", tags=["Search"])
def search_by_phone(
    number:  str = Query(..., example="9811063283"),
    country: str = Query(DEFAULT_COUNTRY, example="india")
):
    """Search by primary telephone number."""
    s3_path = get_s3_path(country)
    try:
        result = con.execute(f"""
            SELECT telephone_number, name_of_the_subsciber, date_of_birth,
                   father_s_husband_s_name, address1, address2, address3,
                   city, postal, state, alternate_phone_no, e_mail_id,
                   gender, connection_type, service_provider, circle,
                   imsi_no, bank_name, bank_a_c_no
            FROM read_parquet('{s3_path}')
            WHERE CAST(telephone_number AS VARCHAR) = '{number}'
            LIMIT 5
        """).fetchall()
        cols = ["telephone_number","name","dob","father_husband_name",
                "address1","address2","address3","city","postal","state",
                "alternate_phone","email","gender","connection_type",
                "service_provider","circle","imsi","bank_name","bank_ac"]
        if not result:
            raise HTTPException(status_code=404, detail=f"No record found for {number} in {country}")
        return {"country": country, "count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/search/email", tags=["Search"])
def search_by_email(
    email:   str = Query(..., example="test@gmail.com"),
    country: str = Query(DEFAULT_COUNTRY, example="india")
):
    """Search by email address (case-insensitive)."""
    s3_path = get_s3_path(country)
    try:
        result = con.execute(f"""
            SELECT telephone_number, name_of_the_subsciber, date_of_birth,
                   address1, address2, city, state,
                   alternate_phone_no, e_mail_id, gender,
                   connection_type, service_provider, circle
            FROM read_parquet('{s3_path}')
            WHERE LOWER(CAST(e_mail_id AS VARCHAR)) = LOWER('{email}')
            LIMIT 10
        """).fetchall()
        cols = ["telephone_number","name","dob","address1","address2","city","state",
                "alternate_phone","email","gender","connection_type","service_provider","circle"]
        if not result:
            raise HTTPException(status_code=404, detail=f"No record found for {email} in {country}")
        return {"country": country, "count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/search/alternate", tags=["Search"])
def search_by_alternate(
    number:  str = Query(..., example="9810766029"),
    country: str = Query(DEFAULT_COUNTRY, example="india")
):
    """Search by alternate/secondary phone number."""
    s3_path = get_s3_path(country)
    try:
        result = con.execute(f"""
            SELECT telephone_number, name_of_the_subsciber, date_of_birth,
                   address1, address2, city, state,
                   alternate_phone_no, e_mail_id, gender,
                   connection_type, service_provider, circle
            FROM read_parquet('{s3_path}')
            WHERE CAST(alternate_phone_no AS VARCHAR) = '{number}'
            LIMIT 10
        """).fetchall()
        cols = ["telephone_number","name","dob","address1","address2","city","state",
                "alternate_phone","email","gender","connection_type","service_provider","circle"]
        if not result:
            raise HTTPException(status_code=404, detail=f"No record found for {number} in {country}")
        return {"country": country, "count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/search/name", tags=["Search"])
def search_by_name(
    name:    str = Query(..., example="Ajay"),
    country: str = Query(DEFAULT_COUNTRY, example="india"),
    limit:   int = Query(20, ge=1, le=100)
):
    """Search by name (partial match, case-insensitive)."""
    s3_path = get_s3_path(country)
    try:
        result = con.execute(f"""
            SELECT telephone_number, name_of_the_subsciber, date_of_birth,
                   city, state, alternate_phone_no, e_mail_id,
                   connection_type, circle
            FROM read_parquet('{s3_path}')
            WHERE LOWER(CAST(name_of_the_subsciber AS VARCHAR)) LIKE LOWER('%{name}%')
            LIMIT {limit}
        """).fetchall()
        cols = ["telephone_number","name","dob","city","state",
                "alternate_phone","email","connection_type","circle"]
        if not result:
            raise HTTPException(status_code=404, detail=f"No records for '{name}' in {country}")
        return {"country": country, "count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats", tags=["Info"])
def get_stats(
    country: str = Query(DEFAULT_COUNTRY, example="india")
):
    """Total records + breakdown by circle for a country."""
    s3_path = get_s3_path(country)
    try:
        total = con.execute(f"SELECT COUNT(*) FROM read_parquet('{s3_path}')").fetchone()[0]
        by_circle = con.execute(f"""
            SELECT circle, COUNT(*) as count
            FROM read_parquet('{s3_path}')
            GROUP BY circle ORDER BY count DESC LIMIT 20
        """).fetchall()
        return {
            "country": country,
            "total_records": total,
            "by_circle": [{"circle": r[0], "count": r[1]} for r in by_circle]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))