from datetime import datetime, timedelta
from typing import Union

import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi import FastAPI

# 定义您的函数，以便使用后续的代码
def init_fake_user(user_name, user_full_name, user_pw, user_email):
    # 此处添加初始化用户的逻辑
    pass

def verify_password(plain_password, hashed_password):
    # 保留原有的密码验证逻辑
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    # 保留原有的获取密码哈希逻辑
    return pwd_context.hash(password)

def get_user(db, username: str):
    # 保留原有的获取用户逻辑
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    # 保留原有的用户身份验证逻辑
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# 保留原有的 OAuth2PasswordBearer 配置
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 使用 OAuth2AuthorizationCodeBearer 代替 OAuth2PasswordBearer
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://accounts.google.com/o/oauth2/token",
)

# 保留原有的 Google OAuth2 配置
GOOGLE_CLIENT_ID = "your-google-client-id"
GOOGLE_CLIENT_SECRET = "your-google-client-secret"
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

# 保留原有的 /login 路由，用于跳转到 Google OAuth 登录
@app.get("/login")
async def login():
    authorization_url = oauth2_google.get_authorization_url()
    return RedirectResponse(authorization_url)

# 保留原有的 /login/callback 路由，用于处理 Google OAuth 的回调
@app.get("/login/callback")
async def login_callback(code: str):
    token = await oauth2_google.get_access_token(code)
    return {"msg": "Callback from Google OAuth", "token": token}

# 保留原有的 /token 路由，用于获取访问令牌
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2AuthorizationCodeBearer = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# 保留原有的 /users/me/ 路由，用于获取当前用户信息
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# 保留原有的 /users/me/items/ 路由，用于获取当前用户的物品信息
@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]

if __name__ == "__main__":
    init_fake_user(
        "sample_user",
        "Sample User",
        "password",
        "sample_user@nowhere.com"
    )

    uvicorn.run(app, host="0.0.0.0", port=8000)
