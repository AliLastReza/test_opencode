import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import models, schemas, security
from .database import Base, SessionLocal, engine, get_db

Base.metadata.create_all(bind=engine)

DEFAULT_USERS = [
    {"username": "admin", "password": "admin"},
    {"username": "user2", "password": "user2"},
]

app = FastAPI(title="Test Open Code - Simple Auth Backend")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@app.on_event("startup")
def seed_default_users():
    db = SessionLocal()
    try:
        for credentials in DEFAULT_USERS:
            exists = (
                db.query(models.User)
                .filter(models.User.username == credentials["username"])
                .first()
            )
            if exists is None:
                db.add(
                    models.User(
                        username=credentials["username"],
                        hashed_password=security.get_password_hash(
                            credentials["password"]
                        ),
                    )
                )
        db.commit()
    finally:
        db.close()


@app.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    exists = db.query(models.User).filter(models.User.username == user.username).first()
    if exists is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    db_user = models.User(
        username=user.username,
        hashed_password=security.get_password_hash(user.password),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/login", response_model=schemas.Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    db_user = (
        db.query(models.User).filter(models.User.username == form_data.username).first()
    )
    if db_user is None or not security.verify_password(
        form_data.password, db_user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {
        "access_token": security.create_access_token(db_user.username),
        "token_type": "bearer",
    }


@app.get("/me")
def read_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        username = security.decode_access_token(token)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    db_user = db.query(models.User).filter(models.User.username == username).first()
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"message": f"Hello, {db_user.username}!"}