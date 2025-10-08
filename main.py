from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
from typing import List, Optional
import os
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import func
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import pandas as pd
import io
from models import (
    DBAppointment, DBUser, DBTransaction,
    AppointmentCreate, AppointmentUpdate, Appointment, TransactionCreate, Transaction,
    UserCreate, User,
    SessionLocal, create_db_and_tables
)

# Configurazione di logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Istanza di FastAPI
app = FastAPI(title="Estetiste API")

# Middleware CORS
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configurazione JWT
SECRET_KEY = os.environ.get("SECRET_KEY", "la_tua_chiave_segreta_super_lunga_e_casuale")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 giorni

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Funzioni di autenticazione
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    # Converti in byte UTF-8 e verifica la lunghezza
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]  # Troncamento manuale
    return pwd_context.hash(password_bytes.decode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Dependency Injection
def get_db():
    global database_initialized
    if not database_initialized:
        create_db_and_tables()
        database_initialized = True
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Non riesco a validare le credenziali",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(DBUser).filter(DBUser.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# Endpoint di autenticazione
@app.post("/register", response_model=dict, tags=["Auth"])
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    logger.info(f"Registering user: {user_data.email}")
    try:
        db_user = db.query(DBUser).filter(DBUser.email == user_data.email).first()
        if db_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email già registrata")
        hashed_password = get_password_hash(user_data.password)
        db_user = DBUser(email=user_data.email, hashed_password=hashed_password)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"user_id": db_user.id, "email": db_user.email}, expires_delta=access_token_expires)
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException as http_exc:
        logger.error(f"HTTP Exception: {str(http_exc)}")
        raise
    except Exception as e:
        logger.error(f"Error in register: {str(e)}")
        raise HTTPException(status_code=500, detail="Errore interno del server")

@app.post("/token", tags=["Auth"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email o password errati")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"user_id": user.id, "email": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User, tags=["Auth"])
def read_users_me(current_user: DBUser = Depends(get_current_user)):
    return current_user

# Endpoint CRUD Appuntamenti
@app.post("/appointments", response_model=Appointment, status_code=status.HTTP_201_CREATED, tags=["Appointments"])
def create_appointment(appointment: AppointmentCreate, db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    db_appointment = DBAppointment(**appointment.model_dump(), user_id=current_user.id)
    db.add(db_appointment)
    db.commit()
    db.refresh(db_appointment)
    return db_appointment

@app.get("/appointments", response_model=List[Appointment], tags=["Appointments"])
def read_appointments(db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    return db.query(DBAppointment).filter(DBAppointment.user_id == current_user.id).all()

@app.put("/appointments/{appointment_id}", response_model=Appointment, tags=["Appointments"])
def update_appointment(appointment_id: int, appointment: AppointmentUpdate, db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    db_appointment = db.query(DBAppointment).filter(DBAppointment.id == appointment_id, DBAppointment.user_id == current_user.id).first()
    if db_appointment is None:
        raise HTTPException(status_code=404, detail="Appuntamento non trovato o non di tua proprietà")
    update_data = appointment.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_appointment, key, value)
    db.commit()
    db.refresh(db_appointment)
    return db_appointment

@app.delete("/appointments/{appointment_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Appointments"])
def delete_appointment(appointment_id: int, db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    db_appointment = db.query(DBAppointment).filter(DBAppointment.id == appointment_id, DBAppointment.user_id == current_user.id).first()
    if db_appointment is None:
        raise HTTPException(status_code=404, detail="Appuntamento non trovato o non di tua proprietà")
    db.delete(db_appointment)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# Endpoint CRUD Transazioni
@app.post("/transactions", response_model=Transaction, status_code=status.HTTP_201_CREATED, tags=["Transactions"])
def create_transaction(transaction: TransactionCreate, db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    db_transaction = DBTransaction(**transaction.model_dump(), user_id=current_user.id)
    db.add(db_transaction)
    db.commit()
    db.refresh(db_transaction)
    return db_transaction

@app.get("/transactions", response_model=List[Transaction], tags=["Transactions"])
def read_transactions(db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    return db.query(DBTransaction).filter(DBTransaction.user_id == current_user.id).all()

@app.put("/transactions/{transaction_id}", response_model=Transaction, tags=["Transactions"])
def update_transaction(transaction_id: int, transaction: TransactionCreate, db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    db_transaction = db.query(DBTransaction).filter(DBTransaction.id == transaction_id, DBTransaction.user_id == current_user.id).first()
    if db_transaction is None:
        raise HTTPException(status_code=404, detail="Transazione non trovata o non di tua proprietà")
    update_data = transaction.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_transaction, key, value)
    db.commit()
    db.refresh(db_transaction)
    return db_transaction

@app.delete("/transactions/{transaction_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Transactions"])
def delete_transaction(transaction_id: int, db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    db_transaction = db.query(DBTransaction).filter(DBTransaction.id == transaction_id, DBTransaction.user_id == current_user.id).first()
    if db_transaction is None:
        raise HTTPException(status_code=404, detail="Transazione non trovata o non di tua proprietà")
    db.delete(db_transaction)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# Endpoint Statistiche
@app.get("/stats", tags=["Stats"])
def get_monthly_stats(year: int = None, month: int = None, db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    if year is None or month is None:
        total_appointments = db.query(DBAppointment).filter(DBAppointment.user_id == current_user.id).count()
        total_transactions = db.query(DBTransaction).filter(DBTransaction.user_id == current_user.id).count()
        total_revenue = db.query(DBTransaction).filter(DBTransaction.user_id == current_user.id).with_entities(func.sum(DBTransaction.amount)).scalar() or 0
        return {
            "total_appointments": total_appointments,
            "total_transactions": total_transactions,
            "total_revenue": round(total_revenue, 2)
        }
    try:
        start_date = datetime(year, month, 1)
        if month == 12:
            end_date = datetime(year + 1, 1, 1)
        else:
            end_date = datetime(year, month + 1, 1)
    except ValueError:
        raise HTTPException(status_code=400, detail="Anno o mese non valido")
    monthly_transactions = db.query(DBTransaction).filter(
        DBTransaction.user_id == current_user.id,
        DBTransaction.date >= start_date,
        DBTransaction.date < end_date
    ).all()
    total_revenue = sum(t.amount for t in monthly_transactions)
    completed_appointments_count = db.query(DBAppointment).filter(
        DBAppointment.user_id == current_user.id,
        DBAppointment.status == "completed",
        DBAppointment.datetime >= start_date,
        DBAppointment.datetime < end_date
    ).count()
    return {
        "start_period": start_date.isoformat(),
        "end_period": end_date.isoformat(),
        "total_revenue": round(total_revenue, 2),
        "completed_appointments_count": completed_appointments_count
    }

# Endpoint Esportazione CSV
@app.get("/export/appointments.csv", tags=["Export"])
def export_appointments_csv(db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    appointments_data = db.query(DBAppointment).filter(DBAppointment.user_id == current_user.id).all()
    data = [{"ID": apt.id, "Nome Cliente": apt.client_name, "Servizio": apt.service_name, "Prezzo": apt.price, "Data e Ora": apt.datetime.isoformat(), "Stato": apt.status} for apt in appointments_data]
    df = pd.DataFrame(data)
    csv_output = io.StringIO()
    df.to_csv(csv_output, index=False, sep=';', encoding='utf-8')
    csv_content = csv_output.getvalue()
    return Response(content=csv_content, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=appointments.csv", "Content-Type": "text/csv; charset=utf-8"})

@app.get("/export/transactions.csv", tags=["Export"])
def export_transactions_csv(db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    transactions_data = db.query(DBTransaction).filter(DBTransaction.user_id == current_user.id).all()
    data = [{"ID": t.id, "Importo": t.amount, "Data": t.date.isoformat(), "Descrizione": t.description or "", "Appuntamento ID": t.appointment_id or ""} for t in transactions_data]
    df = pd.DataFrame(data)
    csv_output = io.StringIO()
    df.to_csv(csv_output, index=False, sep=';', encoding='utf-8')
    csv_content = csv_output.getvalue()
    return Response(content=csv_content, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=transactions.csv", "Content-Type": "text/csv; charset=utf-8"})

# Inizializzazione del database
database_initialized = False
@app.on_event("startup")
async def startup_event():
    global database_initialized
    if not database_initialized:
        create_db_and_tables()
        database_initialized = True