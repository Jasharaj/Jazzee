from fastapi import APIRouter, HTTPException, Depends, Form
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional
from pydantic import BaseModel, EmailStr
from ..db.mongodb import db
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

router = APIRouter()

# Security configurations
SECRET_KEY = "your-secret-key-here"  # In production, use a secure secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(email: str):
    logger.debug(f"Looking up user with email: {email}")
    if user_dict := await db.users.find_one({"email": email}):
        logger.debug(f"Found user with email: {email}")
        return UserInDB(**user_dict)
    logger.debug(f"No user found with email: {email}")
    return None

async def authenticate_user(email: str, password: str):
    logger.debug(f"Attempting to authenticate user with email: {email}")
    user = await get_user(email)
    if not user:
        logger.debug(f"Authentication failed: no user found with email: {email}")
        return None
    if not verify_password(password, user.hashed_password):
        logger.debug(f"Authentication failed: invalid password for email: {email}")
        return None
    logger.debug(f"Authentication successful for email: {email}")
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = await get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Routes
@router.post("/login")
async def login(request: LoginRequest):
    logger.debug(f"Login attempt for email: {request.email}")
    try:
        user = await authenticate_user(request.email, request.password)
        if not user:
            logger.debug(f"Login failed for email: {request.email}")
            raise HTTPException(
                status_code=401,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        logger.debug(f"Login successful for email: {request.email}")
        return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Login error for email {request.email}: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail="Login failed. Please check your email and password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/register", response_model=User)
async def register(user: UserCreate):
    logger.debug(f"Registration attempt for email: {user.email}")
    # Check if user already exists
    if await get_user(user.email):
        logger.debug(f"Registration failed - email already exists: {user.email}")
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # Create new user
    user_dict = {
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": get_password_hash(user.password),
        "disabled": False
    }
    
    await db.users.insert_one(user_dict)
    logger.debug(f"User registered successfully: {user.email}")
    return User(**user_dict)

@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user
