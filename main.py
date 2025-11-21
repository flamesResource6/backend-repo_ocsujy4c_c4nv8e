import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

from database import db, create_document, get_documents
from schemas import AdminUser, Service, Offer, Testimonial, Package, BlogPost, ContactSubmission, AuditLog

# Config
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGO = "HS256"
ACCESS_EXPIRE_MIN = int(os.getenv("ACCESS_EXPIRE_MIN", "15"))
REFRESH_EXPIRE_DAYS = int(os.getenv("REFRESH_EXPIRE_DAYS", "7"))
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Travel Agency API")

# HTTPS redirect for auth protection (only if env enforces)
if os.getenv("ENFORCE_HTTPS", "false").lower() == "true":
    app.add_middleware(HTTPSRedirectMiddleware)

app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------- Helpers -----------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_EXPIRE_MIN))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)


def create_refresh_token(sub: str):
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRE_DAYS)
    payload = {"sub": sub, "type": "refresh", "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


async def get_current_admin(request: Request):
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        email = payload.get("sub")
        role = payload.get("role")
        if not email or role != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
        user = db["adminuser"].find_one({"email": email})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ----------------- Models -----------------
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AdminLogin(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    csrf_token: str


class CSRFResponse(BaseModel):
    csrf_token: str


# ----------------- Public Content APIs -----------------
@app.get("/")
def root():
    return {"message": "Travel Agency API running"}


@app.get("/schema")
def get_schema_names():
    return {
        "collections": [
            "adminuser", "service", "offer", "testimonial", "package", "blogpost", "contactsubmission", "auditlog"
        ]
    }


@app.get("/services", response_model=List[Service])
def list_services():
    items = get_documents("service")
    return [Service(**{k: v for k, v in i.items() if k != "_id"}) for i in items]


@app.get("/offers", response_model=List[Offer])
def list_offers():
    items = get_documents("offer", {"active": True})
    return [Offer(**{k: v for k, v in i.items() if k != "_id"}) for i in items]


@app.get("/testimonials", response_model=List[Testimonial])
def list_testimonials():
    items = get_documents("testimonial")
    return [Testimonial(**{k: v for k, v in i.items() if k != "_id"}) for i in items]


@app.get("/packages", response_model=List[Package])
def list_packages():
    items = get_documents("package")
    return [Package(**{k: v for k, v in i.items() if k != "_id"}) for i in items]


@app.get("/blog", response_model=List[BlogPost])
def list_blog():
    items = get_documents("blogpost", {"published": True})
    return [BlogPost(**{k: v for k, v in i.items() if k != "_id"}) for i in items]


@app.post("/contact")
@limiter.limit("5/minute")
async def submit_contact(request: Request, payload: ContactSubmission):
    ip = get_remote_address(request)
    ua = request.headers.get("user-agent", "")
    data = payload.model_dump()
    data.update({"ip": ip, "user_agent": ua})
    create_document("contactsubmission", data)
    create_document("auditlog", {
        "action": "contact_submit",
        "success": True,
        "details": data["email"],
        "ip": ip,
        "user_agent": ua,
    })
    return {"ok": True}


# ----------------- Auth -----------------
@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(request: Request, creds: AdminLogin, response: Response):
    user = db["adminuser"].find_one({"email": creds.email})
    ip = get_remote_address(request)
    ua = request.headers.get("user-agent", "")

    if not user:
        create_document("auditlog", {"action": "login", "success": False, "details": "user not found", "ip": ip, "user_agent": ua})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.get("locked_until") and datetime.now(timezone.utc) < user["locked_until"]:
        raise HTTPException(status_code=423, detail="Account temporarily locked")

    if not verify_password(creds.password, user["password_hash"]):
        db["adminuser"].update_one({"_id": user["_id"]}, {"$inc": {"failed_attempts": 1}})
        create_document("auditlog", {"action": "login", "success": False, "details": "wrong password", "ip": ip, "user_agent": ua, "email": creds.email})
        # Lockout after 5 attempts for 10 minutes
        updated = db["adminuser"].find_one({"_id": user["_id"]})
        if updated.get("failed_attempts", 0) >= 5:
            db["adminuser"].update_one({"_id": user["_id"]}, {"$set": {"locked_until": datetime.now(timezone.utc) + timedelta(minutes=10)}})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # reset counters
    db["adminuser"].update_one({"_id": user["_id"]}, {"$set": {"failed_attempts": 0, "locked_until": None}})

    access = create_access_token({"sub": user["email"], "role": user.get("role", "admin")})
    refresh = create_refresh_token(user["email"]) 

    # CSRF token for refresh endpoint (double submit)
    csrf_token = jwt.encode({"sub": user["email"], "iat": int(datetime.now(timezone.utc).timestamp())}, JWT_SECRET, algorithm=JWT_ALGO)

    # HttpOnly refresh cookie
    cookie_params = {
        "key": "refresh_token",
        "value": refresh,
        "httponly": True,
        "secure": True,
        "samesite": "strict",
        "max_age": REFRESH_EXPIRE_DAYS * 24 * 3600,
        "path": "/auth/refresh",
    }
    if COOKIE_DOMAIN:
        cookie_params["domain"] = COOKIE_DOMAIN
    response.set_cookie(**cookie_params)

    # Set CSRF cookie (readable by JS)
    response.set_cookie(key="csrf_token", value=csrf_token, secure=True, samesite="strict", max_age=REFRESH_EXPIRE_DAYS * 24 * 3600, path="/auth/refresh")

    create_document("auditlog", {"action": "login", "success": True, "email": user["email"], "ip": ip, "user_agent": ua})
    return {"access_token": access}


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(request: Request, response: Response, body: RefreshRequest):
    refresh_cookie = request.cookies.get("refresh_token")
    csrf_cookie = request.cookies.get("csrf_token")

    if not refresh_cookie:
        raise HTTPException(status_code=401, detail="No refresh token")
    if not csrf_cookie or csrf_cookie != body.csrf_token:
        raise HTTPException(status_code=403, detail="CSRF check failed")

    try:
        payload = jwt.decode(refresh_cookie, JWT_SECRET, algorithms=[JWT_ALGO])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        email = payload.get("sub")
        # Check blacklist
        if db["token_blacklist"].find_one({"token": refresh_cookie}):
            raise HTTPException(status_code=401, detail="Token revoked")
        user = db["adminuser"].find_one({"email": email})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        access = create_access_token({"sub": email, "role": user.get("role", "admin")})
        return {"access_token": access}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@app.post("/auth/logout")
async def logout(request: Request, response: Response):
    refresh_cookie = request.cookies.get("refresh_token")
    if refresh_cookie:
        db["token_blacklist"].insert_one({"token": refresh_cookie, "revoked_at": datetime.now(timezone.utc)})
    response.delete_cookie("refresh_token", path="/auth/refresh")
    response.delete_cookie("csrf_token", path="/auth/refresh")
    return {"ok": True}


# ----------------- Admin CRUD (protected) -----------------

def ensure_admin(user=Depends(get_current_admin)):
    return user


# Generic helpers
from fastapi import Body

def strip_id(doc: dict):
    if "_id" in doc:
        doc.pop("_id")
    return doc


@app.post("/admin/services")
def create_service(item: Service = Body(...), _: dict = Depends(ensure_admin)):
    create_document("service", item)
    return {"ok": True}


@app.put("/admin/services/{slug}")
def update_service(slug: str, item: Service = Body(...), _: dict = Depends(ensure_admin)):
    db["service"].update_one({"slug": slug}, {"$set": item.model_dump()})
    return {"ok": True}


@app.delete("/admin/services/{slug}")
def delete_service(slug: str, _: dict = Depends(ensure_admin)):
    db["service"].delete_one({"slug": slug})
    return {"ok": True}


@app.post("/admin/offers")
def create_offer(item: Offer = Body(...), _: dict = Depends(ensure_admin)):
    create_document("offer", item)
    return {"ok": True}


@app.put("/admin/offers/{title}")
def update_offer(title: str, item: Offer = Body(...), _: dict = Depends(ensure_admin)):
    db["offer"].update_one({"title": title}, {"$set": item.model_dump()})
    return {"ok": True}


@app.delete("/admin/offers/{title}")
def delete_offer(title: str, _: dict = Depends(ensure_admin)):
    db["offer"].delete_one({"title": title})
    return {"ok": True}


@app.post("/admin/testimonials")
def create_testimonial(item: Testimonial = Body(...), _: dict = Depends(ensure_admin)):
    create_document("testimonial", item)
    return {"ok": True}


@app.delete("/admin/testimonials/{name}")
def delete_testimonial(name: str, _: dict = Depends(ensure_admin)):
    db["testimonial"].delete_one({"name": name})
    return {"ok": True}


@app.post("/admin/packages")
def create_package(item: Package = Body(...), _: dict = Depends(ensure_admin)):
    create_document("package", item)
    return {"ok": True}


@app.put("/admin/packages/{slug}")
def update_package(slug: str, item: Package = Body(...), _: dict = Depends(ensure_admin)):
    db["package"].update_one({"slug": slug}, {"$set": item.model_dump()})
    return {"ok": True}


@app.delete("/admin/packages/{slug}")
def delete_package(slug: str, _: dict = Depends(ensure_admin)):
    db["package"].delete_one({"slug": slug})
    return {"ok": True}


@app.post("/admin/blog")
def create_blog(item: BlogPost = Body(...), _: dict = Depends(ensure_admin)):
    create_document("blogpost", item)
    return {"ok": True}


@app.put("/admin/blog/{slug}")
def update_blog(slug: str, item: BlogPost = Body(...), _: dict = Depends(ensure_admin)):
    db["blogpost"].update_one({"slug": slug}, {"$set": item.model_dump()})
    return {"ok": True}


@app.delete("/admin/blog/{slug}")
def delete_blog(slug: str, _: dict = Depends(ensure_admin)):
    db["blogpost"].delete_one({"slug": slug})
    return {"ok": True}


@app.get("/admin/contacts/export")
def export_contacts(_: dict = Depends(ensure_admin)):
    items = get_documents("contactsubmission")
    # simple CSV export
    import csv
    from io import StringIO
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["full_name", "phone", "email", "message", "ip", "user_agent", "created_at"])
    for it in items:
        writer.writerow([
            it.get("full_name", ""), it.get("phone", ""), it.get("email", ""),
            it.get("message", ""), it.get("ip", ""), it.get("user_agent", ""),
            it.get("created_at", "")
        ])
    return Response(content=buf.getvalue(), media_type="text/csv")


# Utility: seed an initial admin (only if none). Not exposed publicly in docs.
@app.post("/admin/seed")
def seed_admin(email: EmailStr, password: str, name: str = "Admin"):
    if db["adminuser"].find_one({"email": email}):
        return {"ok": True, "msg": "exists"}
    pw = hash_password(password)
    create_document("adminuser", {"email": email, "name": name, "password_hash": pw, "role": "admin"})
    return {"ok": True}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
