from datetime import timedelta
from fastapi import APIRouter, HTTPException, Depends, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from ...core.auth import authenticate_user, create_access_token, get_password_hash, get_current_user
from ...models.user import UserCreate, User, Token, UserLogin
from ...database.mongodb import db
import uuid
from datetime import datetime
from typing import Dict, Any

router = APIRouter()

@router.post("/register", response_model=User)
async def register_user(user: UserCreate):
    try:
        # Check if user already exists
        if await db.database["users"].find_one({"email": user.email}):
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        user_dict = user.dict()
        user_dict["id"] = str(uuid.uuid4())
        user_dict["hashed_password"] = get_password_hash(user_dict.pop("password"))
        user_dict["created_at"] = datetime.utcnow()
        user_dict["is_active"] = True
        user_dict["last_login"] = None
        
        # Insert into database
        await db.database["users"].insert_one(user_dict)
        
        # Remove hashed_password from response
        del user_dict["hashed_password"]
        return user_dict
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error creating user: {str(e)}"
        )

@router.post("/login", response_model=Token)
async def login(email: str = Form(...), password: str = Form(...)):
    try:
        user = await authenticate_user(email, password)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Update last login
        await db.database["users"].update_one(
            {"email": user.email},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        access_token_expires = timedelta(minutes=30)
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error during login: {str(e)}"
        )

@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    try:
        return current_user
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching user details: {str(e)}"
        )
