import os
import smtplib
from datetime import datetime, timedelta
from typing import Optional
from email.message import EmailMessage

from fastapi import FastAPI, Depends, HTTPException, Request, Form, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Table, or_
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURATION ---
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
MAILPIT_SMTP_HOST = os.getenv("MAILPIT_SMTP_HOST", "127.0.0.1")
MAILPIT_SMTP_PORT = int(os.getenv("MAILPIT_SMTP_PORT", 1025))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gmail_clone.db")

# --- DATABASE SETUP ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Many-to-Many relationship table for Users and Groups
group_members = Table(
    'group_members', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('group_id', Integer, ForeignKey('groups.id'))
)

class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    groups = relationship("DBGroup", secondary=group_members, back_populates="members")

class DBGroup(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    group_email = Column(String, unique=True, index=True) # e.g., dev-team@local
    members = relationship("DBUser", secondary=group_members, back_populates="groups")

class DBEmail(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, index=True)
    thread_id = Column(String, index=True) # Groups replies together
    sender = Column(String, index=True)
    recipient = Column(String, index=True)
    subject = Column(String)
    body = Column(Text)
    received_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- AUTH & UTILS ---
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
templates = Jinja2Templates(directory="templates")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user_from_cookie(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token: return None
    try:
        token = token.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(DBUser).filter(DBUser.email == payload.get("sub")).first()
        return user
    except JWTError:
        return None

def require_auth(user: DBUser = Depends(get_current_user_from_cookie)):
    if not user: raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    return user

# --- FASTAPI APP & HTML ROUTES ---
app = FastAPI(title="Gmail Clone UI")

@app.get("/", response_class=HTMLResponse)
def home(request: Request, user: DBUser = Depends(get_current_user_from_cookie)):
    if user: return RedirectResponse(url="/inbox")
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")

@app.post("/auth")
def authenticate(response: Response, email: str = Form(...), password: str = Form(...), action: str = Form(...), db: Session = Depends(get_db)):
    if action == "register":
        if db.query(DBUser).filter(DBUser.email == email).first():
            return RedirectResponse(url="/login?error=Email+exists", status_code=302)
        db.add(DBUser(email=email, hashed_password=pwd_context.hash(password)))
        db.commit()
    
    # Login Flow
    user = db.query(DBUser).filter(DBUser.email == email).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return RedirectResponse(url="/login?error=Invalid+credentials", status_code=302)
    
    token = jwt.encode({"sub": user.email, "exp": datetime.utcnow() + timedelta(days=1)}, SECRET_KEY, algorithm=ALGORITHM)
    response = RedirectResponse(url="/inbox", status_code=302)
    response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True)
    return response

@app.get("/logout")
def logout(response: Response):
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response

@app.get("/inbox", response_class=HTMLResponse)
def inbox_page(request: Request, user: DBUser = Depends(require_auth), db: Session = Depends(get_db)):
    group_emails = [g.group_email for g in user.groups]
    emails = db.query(DBEmail).filter(
        or_(DBEmail.recipient == user.email, DBEmail.recipient.in_(group_emails))
    ).group_by(DBEmail.thread_id).order_by(DBEmail.received_at.desc()).all()
    
    # Update this line
    return templates.TemplateResponse(request, "inbox.html", {"user": user, "emails": emails})

@app.get("/thread/{thread_id}", response_class=HTMLResponse)
def view_thread(request: Request, thread_id: str, user: DBUser = Depends(require_auth), db: Session = Depends(get_db)):
    emails = db.query(DBEmail).filter(DBEmail.thread_id == thread_id).order_by(DBEmail.received_at.asc()).all()
    
    # Update this line
    return templates.TemplateResponse(request, "thread.html", {"user": user, "emails": emails, "thread_id": thread_id})

@app.get("/compose", response_class=HTMLResponse)
def compose_page(request: Request, thread_id: str = None, reply_to: str = None, subj: str = None, user: DBUser = Depends(require_auth)):
    return templates.TemplateResponse(request, "compose.html", {"user": user, "thread_id": thread_id, "reply_to": reply_to, "subj": subj})

@app.post("/send")
def send_email(
    to_email: str = Form(...), subject: str = Form(...), body: str = Form(...), 
    thread_id: str = Form(None), user: DBUser = Depends(require_auth)
):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = user.email
    msg['To'] = to_email
    
    # Generate a new thread ID if not replying
    new_thread_id = thread_id if thread_id else str(datetime.utcnow().timestamp())
    msg.add_header('X-Thread-ID', new_thread_id) # Custom header for tracking threads

    with smtplib.SMTP(MAILPIT_SMTP_HOST, MAILPIT_SMTP_PORT) as server:
        server.send_message(msg)
        
    return RedirectResponse(url="/inbox", status_code=302)

@app.get("/groups", response_class=HTMLResponse)
def groups_page(request: Request, user: DBUser = Depends(require_auth), db: Session = Depends(get_db)):
    all_groups = db.query(DBGroup).all()
    all_users = db.query(DBUser).all()
    return templates.TemplateResponse(request, "groups.html", {"user": user, "groups": all_groups, "users": all_users})

@app.post("/groups/create")
def create_group(name: str = Form(...), group_email: str = Form(...), user: DBUser = Depends(require_auth), db: Session = Depends(get_db)):
    new_group = DBGroup(name=name, group_email=group_email)
    db.add(new_group)
    db.commit()
    return RedirectResponse(url="/groups", status_code=302)

@app.post("/groups/add_member")
def add_member(group_id: int = Form(...), user_id: int = Form(...), user: DBUser = Depends(require_auth), db: Session = Depends(get_db)):
    group = db.query(DBGroup).filter(DBGroup.id == group_id).first()
    member = db.query(DBUser).filter(DBUser.id == user_id).first()
    if group and member and member not in group.members:
        group.members.append(member)
        db.commit()
    return RedirectResponse(url="/groups", status_code=302)

# --- MAILPIT WEBHOOK ---
@app.post("/webhook")
async def mailpit_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.json()
    try:
        sender = payload.get("From", {}).get("Address", "unknown")
        recipient = payload.get("To", [{}])[0].get("Address", "unknown")
        subject = payload.get("Subject", "No Subject")
        body = payload.get("Text", "")
        
        # Extract custom thread ID we injected during /send, or generate a standalone one
        headers = payload.get("Headers", {})
        thread_id = headers.get("X-Thread-ID", [str(datetime.utcnow().timestamp())])[0]

        db.add(DBEmail(thread_id=thread_id, sender=sender, recipient=recipient, subject=subject, body=body))
        db.commit()
        return {"status": "success"}
    except Exception as e:
        print(f"Webhook Error: {e}")
        return {"status": "error"}