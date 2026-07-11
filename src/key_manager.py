import secrets
import string
import re
import hashlib
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime

from src.config import settings
from src.database import APIKey, get_db


def generate_gateway_key() -> str:
    """توليد مفتاح بتنسيق gw_xxxxxx_xxxx_xxxxxxxxxxxxxxxxxxxxxxxx"""
    part1 = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(6))
    part2 = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(4))
    part3 = ''.join(secrets.choice(string.ascii_letters + string.digits + '_-') for _ in range(24))
    return f"gw_{part1}_{part2}_{part3}"


def validate_gateway_key(key: str) -> bool:
    """التحقق من صحة تنسيق المفتاح gw_"""
    return bool(re.match(r'^gw_[A-Za-z0-9]{6}_[A-Za-z0-9]{4}_[A-Za-z0-9_\-]{24}$', key))

_encryption_key = settings.ENCRYPTION_KEY or Fernet.generate_key().decode()
cipher = Fernet(_encryption_key)

def encrypt_key(key: str) -> str:
    return cipher.encrypt(key.encode()).decode()

def decrypt_key(encrypted_key: str) -> str:
    return cipher.decrypt(encrypted_key.encode()).decode()

class KeyManager:
    def __init__(self, db: Session):
        self.db = db

    def add_key(self, name: str, provider: str, key: str) -> APIKey:
        encrypted = encrypt_key(key)
        db_key = APIKey(
            name=name,
            provider=provider,
            encrypted_key=encrypted,
            is_active=True
        )
        self.db.add(db_key)
        self.db.commit()
        self.db.refresh(db_key)
        return db_key

    def get_active_keys(self, provider: Optional[str] = None):
        query = self.db.query(APIKey).filter(APIKey.is_active == True)
        if provider:
            query = query.filter(APIKey.provider == provider)
        return query.all()

    def rotate_key(self, provider: str, strategy: str = "round-robin"):
        keys = self.get_active_keys(provider)
        if not keys:
            return None

        if strategy == "round-robin":
            selected_key = min(keys, key=lambda k: k.usage_count)
        elif strategy == "random":
            import random
            selected_key = random.choice(keys)
        else:
            selected_key = min(keys, key=lambda k: k.usage_count)

        if selected_key:
            selected_key.usage_count += 1
            selected_key.last_used = datetime.utcnow()
            self.db.commit()

        return selected_key

    def deactivate_key(self, key_id: int):
        key = self.db.query(APIKey).filter(APIKey.id == key_id).first()
        if key:
            key.is_active = False
            self.db.commit()
            return True
        return False
