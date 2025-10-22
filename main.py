import os, base64, hashlib, secrets, time
from typing import Optional, List, Dict, Any
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

load_dotenv()

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))
ENFORCE_DOMAIN = os.getenv("ENFORCE_DOMAIN", "").strip().lower()
ADMIN_EMAILS: List[str] = [e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()]

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = ["openid", "email", "profile"]

app = FastAPI(title="OIDC Lab — FastAPI + Google OIDC (PKCE)")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax", https_only=False)
templates = Jinja2Templates(directory="templates")

PLACEHOLDER_STRINGS = {
    "client_id": "ENTER_YOUR_GOOGLE_CLIENT_ID_HERE",
    "client_secret": "ENTER_YOUR_GOOGLE_CLIENT_SECRET_HERE",
    "session": "ENTER_A_LONG_RANDOM_STRING_HERE",
}

def _needs_setup() -> Optional[str]:
    if not CLIENT_ID or PLACEHOLDER_STRINGS["client_id"] in CLIENT_ID:
        return "Missing GOOGLE_CLIENT_ID — open .env and replace the placeholder."
    if not CLIENT_SECRET or CLIENT_SECRET == PLACEHOLDER_STRINGS["client_secret"]:
        return "Missing GOOGLE_CLIENT_SECRET — open .env and replace the placeholder."
    if not SESSION_SECRET or SESSION_SECRET == PLACEHOLDER_STRINGS["session"]:
        return "Missing SESSION_SECRET — open .env and replace with a long random string."
    return None

def _b64url(b: bytes) -> str:
    import base64 as b64
    return b64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _gen_pkce():
    verifier = _b64url(os.urandom(40)).replace("-", "").replace("_", "")
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge

def _is_admin(email: str) -> bool:
    return email.lower() in ADMIN_EMAILS

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    setup_msg = _needs_setup()
    if setup_msg:
        return HTMLResponse(f"""
        <html><body style="font-family:system-ui;margin:3rem;max-width:720px">
          <h1>🔧 OIDC Lab — Setup</h1>
          <p>{setup_msg}</p>
          <p>Edit <code>.env</code> then restart the app.</p>
          <pre>GOOGLE_CLIENT_ID=...  # [enter client id here]
GOOGLE_CLIENT_SECRET=...  # [enter secret here]
SESSION_SECRET=...        # long random string</pre>
        </body></html>""")
    user = request.session.get("user")
    return templates.TemplateResponse("home.html", {"request": request, "user": user, "enforce_domain": ENFORCE_DOMAIN})

@app.get("/login")
def login(request: Request):
    import urllib.parse
    state = secrets.token_urlsafe(24)
    verifier, challenge = _gen_pkce()
    request.session["oauth_state"] = state
    request.session["code_verifier"] = verifier
    request.session["login_ts"] = int(time.time())

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/callback",
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    if ENFORCE_DOMAIN:
        params["hd"] = ENFORCE_DOMAIN
    q = urllib.parse.urlencode(params)
    return RedirectResponse(f"{AUTH_URL}?{q}")

@app.get("/callback")
async def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    if error:
        return HTMLResponse(f"<h3>OAuth error:</h3><pre>{error}</pre>", status_code=400)
    if not code or not state:
        return HTMLResponse("<h3>Missing code/state</h3>", status_code=400)
    if state != request.session.get("oauth_state"):
        return HTMLResponse("<h3>State mismatch</h3>", status_code=400)
    verifier = request.session.get("code_verifier")
    if not verifier:
        return HTMLResponse("<h3>Missing PKCE verifier</h3>", status_code=400)

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{BASE_URL}/callback",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code_verifier": verifier,
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        token_resp = await client.post(TOKEN_URL, data=data)
    if token_resp.status_code != 200:
        return HTMLResponse(f"<h3>Token exchange failed</h3><pre>{token_resp.text}</pre>", status_code=400)

    tokens = token_resp.json()
    idt = tokens.get("id_token")
    if not idt:
        return HTMLResponse("<h3>No ID token returned</h3>", status_code=400)

    try:
        req = grequests.Request()
        claims = id_token.verify_oauth2_token(idt, req, CLIENT_ID)
        if ENFORCE_DOMAIN:
            hd = (claims.get("hd") or "").lower()
            email = (claims.get("email") or "").lower()
            if not (hd == ENFORCE_DOMAIN or email.endswith("@" + ENFORCE_DOMAIN)):
                return HTMLResponse(f"<h3>Access denied</h3><p>Only {ENFORCE_DOMAIN} accounts allowed.</p>", status_code=403)
    except Exception as e:
        return HTMLResponse(f"<h3>ID token verification failed</h3><pre>{e}</pre>", status_code=400)

    request.session.pop("oauth_state", None)
    request.session.pop("code_verifier", None)
    user = {
        "email": claims.get("email"),
        "name": claims.get("name"),
        "picture": claims.get("picture"),
        "hd": claims.get("hd"),
        "claims": claims,
        "is_admin": _is_admin(claims.get("email", "")),
    }
    request.session["user"] = user
    return RedirectResponse(url="/success")

@app.get("/success", response_class=HTMLResponse)
def success(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/")
    return templates.TemplateResponse("success.html", {"request": request, "user": user})

@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/")
    allowed = user.get("is_admin", False)
    return templates.TemplateResponse("admin.html", {"request": request, "allowed": allowed, "user": user})

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")
