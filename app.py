from datetime import datetime, timedelta
from typing import Annotated, Union
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi import FastAPI

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$3SH9Gj0hYS9j/1jicQRvQ.hcibXuNw1VfyKQWnZ5hBIDDEHC8njh2",
        "disabled": False,
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Google OAuth2 configuration
GOOGLE_CLIENT_ID = "671071079747-1er03q01u8nab6v7o7oq81ao591ms4gl.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_REDIRECT_URI = "http://34.16.183.53.nip.io:8000/login/callback"

oauth2_google = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://accounts.google.com/o/oauth2/token",
    clientId=GOOGLE_CLIENT_ID,
    clientSecret=GOOGLE_CLIENT_SECRET,
    redirectUrl=GOOGLE_REDIRECT_URI,
    scopes={"openid", "profile", "email"},
)

app = FastAPI()

@app.get("/login")
async def login():
    # 将用户重定向到 Google OAuth 登录
    authorization_url = oauth2_scheme.get_authorization_url()
    return {"msg": "重定向到 Google OAuth 登录", "authorization_url": authorization_url}

@app.get("/login/callback")
async def login_callback(code: str):
    # 处理来自 Google OAuth 的回调
    token = await oauth2_scheme.get_access_token(code)
    return {"msg": "来自 Google OAuth 的回调", "token": token}

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"item_id": "Foo", "owner": current_user.username}]

if __name__ == "__main__":
    init_fake_user(
        "sample_user",
        "Sample User",
        "password",
        "sample_user@nowhere.com"
    )

    uvicorn.run(app, host="0.0.0.0", port=8000)
