from fastapi import HTTPException, Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Define a secret key for JWT encoding/decoding
SECRET_KEY = "your_secret_key"  # Replace with a secure random key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# Define the password hashing scheme
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory user store for demonstration purposes (replace with a real database)
fake_users_db = {
    "test@example.com": {
        "full_name": "Test User",
        "email": "test@example.com",
        "hashed_password": pwd_context.hash("password123"),
        "disabled": False,
    }
}

# Function to verify the user's credentials
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to get the user from the fake database
def get_user(db, email: str):
    if email in db:
        user_dict = db[email]
        return user_dict

# Function to create a new access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Login endpoint for user authentication
@app.post("/token", tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(fake_users_db, form_data.username)
    if not user or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Dependency to get the current user from the token
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
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, email)
    if user is None:
        raise credentials_exception
    return user
