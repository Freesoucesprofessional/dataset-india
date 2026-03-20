"""
India Subscriber Lookup API — FastAPI + DuckDB + Cloudflare R2
Searches all data1.parquet, data2.parquet... from india-data bucket
"""

import os
import duckdb
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

# ─── CONFIG (set these as Environment Variables on Render) ────────────────────
R2_ENDPOINT   = os.getenv("R2_ENDPOINT")   # https://751eb801a572aef64f2541d813c95e28.r2.cloudflarestorage.com
R2_ACCESS_KEY = os.getenv("R2_ACCESS_KEY")
R2_SECRET_KEY = os.getenv("R2_SECRET_KEY")
# ─────────────────────────────────────────────────────────────────────────────

# queries ALL data1.parquet, data2.parquet, data3.parquet... automatically
S3_PATH = "s3://india-data/data*.parquet"

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
    print("DuckDB connected to india-data bucket ✓")
    yield
    con.close()

app = FastAPI(
    title="India Subscriber Lookup API",
    description="Search Indian telecom subscriber records by phone, alternate phone, email, or name.",
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
    return {"status": "ok", "message": "India Subscriber API is running"}


# ─── SEARCH BY PHONE ──────────────────────────────────────────────────────────
@app.get("/search/phone", tags=["Search"])
def search_by_phone(
    number: str = Query(..., description="Primary telephone number", example="9811063283")
):
    """Search subscriber by primary telephone number."""
    try:
        result = con.execute(f"""
            SELECT telephone_number, name_of_the_subsciber, date_of_birth,
                   father_s_husband_s_name, address1, address2, address3,
                   city, postal, state, alternate_phone_no, e_mail_id,
                   gender, connection_type, service_provider, circle,
                   imsi_no, bank_name, bank_a_c_no
            FROM read_parquet('{S3_PATH}')
            WHERE CAST(telephone_number AS VARCHAR) = '{number}'
            LIMIT 5
        """).fetchall()
        cols = ["telephone_number","name","dob","father_husband_name",
                "address1","address2","address3","city","postal","state",
                "alternate_phone","email","gender","connection_type",
                "service_provider","circle","imsi","bank_name","bank_ac"]
        if not result:
            raise HTTPException(status_code=404, detail=f"No record found for number: {number}")
        return {"count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── SEARCH BY EMAIL ──────────────────────────────────────────────────────────
@app.get("/search/email", tags=["Search"])
def search_by_email(
    email: str = Query(..., description="Email address", example="test@gmail.com")
):
    """Search subscriber by email (case-insensitive)."""
    try:
        result = con.execute(f"""
            SELECT telephone_number, name_of_the_subsciber, date_of_birth,
                   address1, address2, city, state,
                   alternate_phone_no, e_mail_id, gender,
                   connection_type, service_provider, circle
            FROM read_parquet('{S3_PATH}')
            WHERE LOWER(CAST(e_mail_id AS VARCHAR)) = LOWER('{email}')
            LIMIT 10
        """).fetchall()
        cols = ["telephone_number","name","dob","address1","address2","city","state",
                "alternate_phone","email","gender","connection_type","service_provider","circle"]
        if not result:
            raise HTTPException(status_code=404, detail=f"No record found for email: {email}")
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
    """Search subscriber by alternate/secondary phone number."""
    try:
        result = con.execute(f"""
            SELECT telephone_number, name_of_the_subsciber, date_of_birth,
                   address1, address2, city, state,
                   alternate_phone_no, e_mail_id, gender,
                   connection_type, service_provider, circle
            FROM read_parquet('{S3_PATH}')
            WHERE CAST(alternate_phone_no AS VARCHAR) = '{number}'
            LIMIT 10
        """).fetchall()
        cols = ["telephone_number","name","dob","address1","address2","city","state",
                "alternate_phone","email","gender","connection_type","service_provider","circle"]
        if not result:
            raise HTTPException(status_code=404, detail=f"No record found for alternate: {number}")
        return {"count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── SEARCH BY NAME ───────────────────────────────────────────────────────────
@app.get("/search/name", tags=["Search"])
def search_by_name(
    name:  str = Query(..., description="Subscriber name (partial match)", example="Ajay"),
    limit: int = Query(20, ge=1, le=100)
):
    """Search subscriber by name (partial, case-insensitive)."""
    try:
        result = con.execute(f"""
            SELECT telephone_number, name_of_the_subsciber, date_of_birth,
                   city, state, alternate_phone_no, e_mail_id,
                   connection_type, circle
            FROM read_parquet('{S3_PATH}')
            WHERE LOWER(CAST(name_of_the_subsciber AS VARCHAR)) LIKE LOWER('%{name}%')
            LIMIT {limit}
        """).fetchall()
        cols = ["telephone_number","name","dob","city","state",
                "alternate_phone","email","connection_type","circle"]
        if not result:
            raise HTTPException(status_code=404, detail=f"No records found for name: {name}")
        return {"count": len(result), "results": [row_to_dict(r, cols) for r in result]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── STATS ────────────────────────────────────────────────────────────────────
@app.get("/stats", tags=["Info"])
def get_stats():
    """Total records + breakdown by circle."""
    try:
        total = con.execute(f"SELECT COUNT(*) FROM read_parquet('{S3_PATH}')").fetchone()[0]
        by_circle = con.execute(f"""
            SELECT circle, COUNT(*) as count
            FROM read_parquet('{S3_PATH}')
            GROUP BY circle ORDER BY count DESC LIMIT 20
        """).fetchall()
        return {
            "total_records": total,
            "by_circle": [{"circle": r[0], "count": r[1]} for r in by_circle]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))