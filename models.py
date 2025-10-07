from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional
import os

# Configurazione del database
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost:5432/dbname").replace("postgres://", "postgresql://", 1)
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelli del database
class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    appointments = relationship("DBAppointment", back_populates="owner")
    transactions = relationship("DBTransaction", back_populates="owner")

class DBAppointment(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    client_name = Column(String, index=True)
    service_name = Column(String)
    price = Column(Float)
    datetime = Column(DateTime, index=True)
    status = Column(String, default="booked")  # booked, completed, cancelled
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    owner = relationship("DBUser", back_populates="appointments")
    transactions = relationship("DBTransaction", back_populates="appointment")

class DBTransaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    amount = Column(Float, nullable=False)
    date = Column(DateTime, index=True, default=datetime.utcnow)
    description = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    appointment_id = Column(Integer, ForeignKey("appointments.id"), nullable=True, index=True)
    owner = relationship("DBUser", back_populates="transactions")
    appointment = relationship("DBAppointment", back_populates="transactions")

# Schemi Pydantic
class AppointmentBase(BaseModel):
    client_name: str
    service_name: str
    price: float
    datetime: datetime
    status: str = "booked"

class AppointmentCreate(AppointmentBase):
    pass

class AppointmentUpdate(AppointmentBase):
    client_name: Optional[str] = None
    service_name: Optional[str] = None
    price: Optional[float] = None
    datetime: Optional[datetime] = None
    status: Optional[str] = None

class Appointment(AppointmentBase):
    id: int
    user_id: int
    class Config:
        from_attributes = True

class TransactionBase(BaseModel):
    amount: float
    date: datetime = datetime.utcnow()
    description: Optional[str] = None
    appointment_id: Optional[int] = None

class TransactionCreate(TransactionBase):
    pass

class Transaction(TransactionBase):
    id: int
    user_id: int
    class Config:
        from_attributes = True

class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool
    class Config:
        from_attributes = True

# Funzione di inizializzazione
def create_db_and_tables():
    Base.metadata.create_all(bind=engine)