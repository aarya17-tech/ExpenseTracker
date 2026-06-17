from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from sqlalchemy import create_engine, String, Float, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.orm import sessionmaker, Session

import jwt
import bcrypt

from datetime import datetime, timedelta, timezone

# ==========================================
# JWT CONFIGURATION
# ==========================================

SECRET_KEY = "my_super_secret_key_for_development"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ==========================================
# PASSWORD FUNCTIONS
# ==========================================

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(
        plain_password.encode("utf-8")[:72],
        hashed_password.encode("utf-8")
    )

def get_password_hash(password):
    return bcrypt.hashpw(
        password.encode("utf-8")[:72],
        bcrypt.gensalt()
    ).decode("utf-8")

def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

# ==========================================
# DATABASE SETUP
# ==========================================

engine = create_engine(
    "sqlite:///expense_tracker.db",
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

class Base(DeclarativeBase):
    pass

# ==========================================
# USER TABLE
# ==========================================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    name: Mapped[str] = mapped_column(
        String(50)
    )

    email: Mapped[str] = mapped_column(
        String(100),
        unique=True
    )

    hashed_password: Mapped[str] = mapped_column(
        String(200)
    )

# ==========================================
# EXPENSE TABLE
# ==========================================

class Expense(Base):
    __tablename__ = "expenses"

    id: Mapped[int] = mapped_column(primary_key=True)

    title: Mapped[str] = mapped_column(
        String(100)
    )

    amount: Mapped[float] = mapped_column(
        Float
    )

    category: Mapped[str] = mapped_column(
        String(50)
    )

    date: Mapped[str] = mapped_column(
        String(30)
    )

    description: Mapped[str] = mapped_column(
        String(300)
    )

Base.metadata.create_all(bind=engine)

# ==========================================
# FASTAPI SETUP
# ==========================================

app = FastAPI()

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)

templates = Jinja2Templates(
    directory="Frontend"
)

# ==========================================
# DATABASE DEPENDENCY
# ==========================================

def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()

# ==========================================
# CURRENT USER
# ==========================================

def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):
    token = request.cookies.get("access_token")

    if not token:
        return None

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        email = payload.get("sub")

        if email is None:
            return None

    except jwt.InvalidTokenError:
        return None

    user = db.scalars(
        select(User).where(User.email == email)
    ).first()

    return user

# ==========================================
# SIGNUP
# ==========================================

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="signup.html"
    )

@app.post("/signup")
def signup_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.scalars(
        select(User).where(User.email == email)
    ).first()

    if existing_user:
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={
                "error": "Email already exists"
            }
        )

    new_user = User(
        name=name,
        email=email,
        hashed_password=get_password_hash(password)
    )

    db.add(new_user)
    db.commit()

    response = RedirectResponse(
        url="/login",
        status_code=303
    )

    return response

# ==========================================
# LOGIN
# ==========================================

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html"
    )

@app.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.scalars(
        select(User).where(User.email == email)
    ).first()

    if not user:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid credentials"
            }
        )

    if not verify_password(
        password,
        user.hashed_password
    ):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid credentials"
            }
        )

    access_token = create_access_token(
        data={"sub": user.email}
    )

    response = RedirectResponse(
        url="/",
        status_code=303
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True
    )

    return response

# ==========================================
# LOGOUT
# ==========================================

@app.get("/logout")
def logout():
    response = RedirectResponse(
        url="/login",
        status_code=303
    )

    response.delete_cookie(
        "access_token"
    )

    return response

# ==========================================
# DASHBOARD
# ==========================================

@app.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expenses = db.scalars(
        select(Expense)
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "expenses": expenses,
            "current_user": current_user
        }
    )

# ==========================================
# CREATE EXPENSE
# ==========================================

@app.get("/create", response_class=HTMLResponse)
def create_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="create.html"
    )

@app.post("/create")
def create_expense(
    title: str = Form(...),
    amount: float = Form(...),
    category: str = Form(...),
    date: str = Form(...),
    description: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = Expense(
        title=title,
        amount=amount,
        category=category,
        date=date,
        description=description
    )

    db.add(expense)
    db.commit()

    return RedirectResponse(
        url="/",
        status_code=303
    )

# ==========================================
# UPDATE EXPENSE
# ==========================================

@app.get("/update/{expense_id}",
         response_class=HTMLResponse)
def update_page(
    request: Request,
    expense_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = db.get(
        Expense,
        expense_id
    )

    return templates.TemplateResponse(
        request=request,
        name="update.html",
        context={
            "expense": expense
        }
    )

@app.post("/update/{expense_id}")
def update_expense(
    expense_id: int,
    title: str = Form(...),
    amount: float = Form(...),
    category: str = Form(...),
    date: str = Form(...),
    description: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = db.get(
        Expense,
        expense_id
    )

    if expense:
        expense.title = title
        expense.amount = amount
        expense.category = category
        expense.date = date
        expense.description = description

        db.commit()

    return RedirectResponse(
        url="/",
        status_code=303
    )

# ==========================================
# DELETE EXPENSE
# ==========================================

@app.get("/delete/{expense_id}")
def delete_expense(
    expense_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = db.get(
        Expense,
        expense_id
    )

    if expense:
        db.delete(expense)
        db.commit()

    return RedirectResponse(
        url="/",
        status_code=303
    )