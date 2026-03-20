"""
Subscriber Data API — FastAPI + DuckDB + Cloudflare R2
Searches telecom subscriber records by phone, email, or alternate phone.
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
R2_BUCKET     = os.getenv("R2_BUCKET", "india-data")
PARQUET_FILE  = os.getenv("PARQUET_FILE", "data*.parquet")   # wildcard = queries ALL data1, data2, data3...
# ─────────────────────────────────────────────────────────────────────────────

S3_PATH = f"s3://{R2_BUCKET}/{PARQUET_FILE}"

con = None

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
    description="Search telecom subscriber records by phone, email, or alternate number.",
    version="1.0.0",
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


# ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "message": "Subscriber API is running"}


# ─── SEARCH BY TELEPHONE NUMBER ───────────────────────────────────────────────
@app.get("/search/phone", tags=["Search"])
def search_by_phone(
    number: str = Query(..., description="Telephone number to search", example="9811063283")
):
    """Search subscriber by their primary telephone number."""
    try:
        result = con.execute(f"""
            SELECT
                "Telephone Number",
                "Name of the Subsciber",
                "Date of birth",
                "Father's/Husband's Name",
                "address1", "address2", "address3",
                "City", "postal", "State",
                "Alternate Phone No",
                "E-mail ID",
                "Gender",
                "Connection Type",
                "Service Provider",
                "Circle",
                "IMSI No",
                "Bank Name",
                "Bank A/C No"
            FROM read_parquet('{S3_PATH}')
            WHERE CAST("Telephone Number" AS VARCHAR) = '{number}'
            LIMIT 5
        """).fetchall()

        cols = [
            "telephone_number","name","dob","father_husband_name",
            "address1","address2","address3","city","postal","state",
            "alternate_phone","email","gender","connection_type",
            "service_provider","circle","imsi","bank_name","bank_ac"
        ]
        if not result:
            raise HTTPException(status_code=404, detail="No record found for this number")
        return {"count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── SEARCH BY EMAIL ──────────────────────────────────────────────────────────
@app.get("/search/email", tags=["Search"])
def search_by_email(
    email: str = Query(..., description="Email address to search", example="ajaykumar949@gmail.com")
):
    """Search subscriber by email address (case-insensitive)."""
    try:
        result = con.execute(f"""
            SELECT
                "Telephone Number",
                "Name of the Subsciber",
                "Date of birth",
                "address1", "address2", "City", "State",
                "Alternate Phone No",
                "E-mail ID",
                "Gender",
                "Connection Type",
                "Service Provider",
                "Circle"
            FROM read_parquet('{S3_PATH}')
            WHERE LOWER(CAST("E-mail ID" AS VARCHAR)) = LOWER('{email}')
            LIMIT 10
        """).fetchall()

        cols = [
            "telephone_number","name","dob",
            "address1","address2","city","state",
            "alternate_phone","email","gender",
            "connection_type","service_provider","circle"
        ]
        if not result:
            raise HTTPException(status_code=404, detail="No record found for this email")
        return {"count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── SEARCH BY ALTERNATE PHONE ────────────────────────────────────────────────
@app.get("/search/alternate", tags=["Search"])
def search_by_alternate(
    number: str = Query(..., description="Alternate phone number", example="9810766029")
):
    """Search subscriber by their alternate/secondary phone number."""
    try:
        result = con.execute(f"""
            SELECT
                "Telephone Number",
                "Name of the Subsciber",
                "Date of birth",
                "address1", "address2", "City", "State",
                "Alternate Phone No",
                "E-mail ID",
                "Gender",
                "Connection Type",
                "Service Provider",
                "Circle"
            FROM read_parquet('{S3_PATH}')
            WHERE CAST("Alternate Phone No" AS VARCHAR) = '{number}'
            LIMIT 10
        """).fetchall()

        cols = [
            "telephone_number","name","dob",
            "address1","address2","city","state",
            "alternate_phone","email","gender",
            "connection_type","service_provider","circle"
        ]
        if not result:
            raise HTTPException(status_code=404, detail="No record found for this alternate number")
        return {"count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── SEARCH BY NAME ───────────────────────────────────────────────────────────
@app.get("/search/name", tags=["Search"])
def search_by_name(
    name: str = Query(..., description="Subscriber name (partial match)", example="Ajay"),
    limit: int = Query(20, ge=1, le=100)
):
    """Search subscriber by name (partial, case-insensitive)."""
    try:
        result = con.execute(f"""
            SELECT
                "Telephone Number",
                "Name of the Subsciber",
                "Date of birth",
                "City", "State",
                "Alternate Phone No",
                "E-mail ID",
                "Connection Type",
                "Circle"
            FROM read_parquet('{S3_PATH}')
            WHERE LOWER(CAST("Name of the Subsciber" AS VARCHAR)) LIKE LOWER('%{name}%')
            LIMIT {limit}
        """).fetchall()

        cols = [
            "telephone_number","name","dob","city","state",
            "alternate_phone","email","connection_type","circle"
        ]
        if not result:
            raise HTTPException(status_code=404, detail="No records found")
        return {"count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── STATS ENDPOINT ───────────────────────────────────────────────────────────
@app.get("/stats", tags=["Info"])
def get_stats():
    """Returns total record count and breakdown by circle/state."""
    try:
        total = con.execute(f"SELECT COUNT(*) FROM read_parquet('{S3_PATH}')").fetchone()[0]
        by_circle = con.execute(f"""
            SELECT "Circle", COUNT(*) as count
            FROM read_parquet('{S3_PATH}')
            GROUP BY "Circle" ORDER BY count DESC LIMIT 20
        """).fetchall()
        return {
            "total_records": total,
            "by_circle": [{"circle": r[0], "count": r[1]} for r in by_circle]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))