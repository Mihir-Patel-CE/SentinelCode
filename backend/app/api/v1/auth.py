from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import verify_password, get_password_hash, create_access_token
from app.models.user import User
from app.models.settings import UserSettings
from app.schemas.auth import UserCreate, UserLogin, UserResponse, Token
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    """Registers a new user account."""
    existing_email = db.query(User).filter(User.email == user_in.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )

    existing_username = db.query(User).filter(User.username == user_in.username).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This username is already taken."
        )

    user = User(
        email=user_in.email,
        username=user_in.username,
        hashed_password=get_password_hash(user_in.password),
        is_active=True
    )
    db.add(user)
    db.flush()

    # Create default settings for user
    settings = UserSettings(user_id=user.id)
    db.add(settings)
    db.commit()
    db.refresh(user)

    return user


@router.post("/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    """Authenticates a user and returns a signed JWT access token."""
    user = db.query(User).filter(
        (User.email == login_data.username_or_email) | (User.username == login_data.username_or_email)
    ).first()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account.")

    access_token = create_access_token(subject=user.id)
    return Token(access_token=access_token, token_type="bearer")


DEMO_USER_EMAIL = "demouser@sentinelcode.dev"
DEMO_USERNAME = "demodev"
DEMO_PASSWORD = "DemoPassword123!"


def ensure_demo_user(db: Session) -> User:
    """
    Idempotently creates or retrieves the standard demo account with default settings.
    """
    user = db.query(User).filter(
        (User.email == DEMO_USER_EMAIL) | (User.username == DEMO_USERNAME)
    ).first()
    if not user:
        user = User(
            email=DEMO_USER_EMAIL,
            username=DEMO_USERNAME,
            hashed_password=get_password_hash(DEMO_PASSWORD),
            is_active=True
        )
        db.add(user)
        db.flush()
        settings = UserSettings(user_id=user.id)
        db.add(settings)
        db.commit()
        db.refresh(user)
    return user


@router.post("/demo-login", response_model=Token)
def demo_login(db: Session = Depends(get_db)):
    """
    Quick 1-click demo login: idempotently ensures the standard demo account exists
    and returns a signed JWT access token.
    """
    user = ensure_demo_user(db)
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Demo account is inactive.")
    access_token = create_access_token(subject=user.id)
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns the profile of the currently logged-in user."""
    return current_user
