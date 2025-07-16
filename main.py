from fastapi import FastAPI, Depends, HTTPException, status, Request, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import secrets
import os

# Generate keys if not exists (in real app, use secure key management)
if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
    os.system("openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048")
    os.system("openssl rsa -pubout -in private_key.pem -out public_key.pem")

# Read keys
with open("private_key.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public_key.pem", "r") as f:
    PUBLIC_KEY = f.read()

# App setup
app = FastAPI(title="JWT Device Auth POC")

# Security setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Mock database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "hashed_password": pwd_context.hash("secret"),
        "devices": {}
    }
}

# Models
class DeviceInfo(BaseModel):
    id: str
    type: str
    user_agent: Optional[str] = None

class TokenData(BaseModel):
    username: str
    device: DeviceInfo

class User(BaseModel):
    username: str
    devices: dict
    hashed_password: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    if username in fake_users_db:
        return User(**fake_users_db[username])
    return None

def create_device_id(request: Request):
    """Generate unique device ID based on request"""
    # In real app, use more robust method (FingerprintJS, device hardware ID, etc.)
    user_agent = request.headers.get("User-Agent", "")
    ip = request.client.host if request.client else "0.0.0.0"
    return secrets.token_hex(8) + "-" + pwd_context.hash(user_agent + ip)[:10]

def get_device_type(request: Request):
    """Simple device type detection"""
    ua = request.headers.get("User-Agent", "").lower()
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "mobile"
    if "tablet" in ua or "ipad" in ua:
        return "tablet"
    return "desktop"

# Authentication
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)

async def get_token_data(token: str = Depends(oauth2_scheme)) -> TokenData:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        device_id = payload.get("device_id")
        device_type = payload.get("device_type")
        user_agent = payload.get("user_agent")
        
        if not all([username, device_id]):
            raise credentials_exception
            
        return TokenData(
            username=username,
            device=DeviceInfo(
                id=device_id,
                type=device_type or "unknown",
                user_agent=user_agent or ""
            )
        )
    except JWTError:
        raise credentials_exception

# API Endpoints
@app.post("/login")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate device info
    device_info = {
        "id": create_device_id(request),
        "type": get_device_type(request),
        "user_agent": request.headers.get("User-Agent")
    }
    
    # Register device for user (in real app, store in DB)
    fake_users_db[user.username]["devices"][device_info["id"]] = {
        "type": device_info["type"],
        "last_login": datetime.utcnow().isoformat()
    }
    
    # Create token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "device_id": device_info["id"],
            "device_type": device_info["type"],
            "user_agent": device_info["user_agent"]
        },
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "device_id": device_info["id"]
    }

@app.get("/profile")
async def user_profile(token_data: TokenData = Depends(get_token_data)):
    # In real app, fetch user data from DB
    return {
        "username": token_data.username,
        "device": token_data.device.dict(),
        "message": f"Authenticated from {token_data.device.type} device"
    }

# Example endpoint requiring device verification 
@app.get("/sensitive-action")
async def sensitive_action(
    token_data: TokenData = Depends(get_token_data),
    confirmation: str = Header(...)
):
    """Example endpoint requiring device verification"""
    # Verify confirmation header exists
    if not confirmation:
        raise HTTPException(status_code=400, detail="Confirmation header required")
    
    # In real app: check device trust level
    if token_data.device.type == "mobile":
        # Mobile devices might require additional verification
        return {"status": "Action performed with mobile device verification"}
    
    return {"status": "Action performed"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)