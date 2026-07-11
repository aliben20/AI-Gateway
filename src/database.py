from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from datetime import datetime

from src.config import settings

Base = declarative_base()
engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    provider = Column(String, nullable=False)
    encrypted_key = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    usage_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)

class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True)
    endpoint = Column(String, nullable=False)
    provider = Column(String, nullable=False)
    model = Column(String, nullable=False)
    status_code = Column(Integer)
    response_time = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
