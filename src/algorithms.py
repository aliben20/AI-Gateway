import hashlib, uuid, base64, secrets, hmac, zlib, time, re, string
from datetime import datetime, timedelta

try: import jwt as pyjwt
except ImportError: pyjwt = None

try: import bcrypt as bcrypt_lib
except ImportError: bcrypt_lib = None

try:
    from argon2 import PasswordHasher as Argon2PH
    _argon2 = Argon2PH()
except ImportError: _argon2 = None

try:
    from Crypto.Cipher import AES as AES_cipher
    from Crypto.Util.Padding import pad
except ImportError: AES_cipher = None

try: import rsa as rsa_lib
except ImportError: rsa_lib = None


class AllAlgorithms:
    @staticmethod
    def generate_uuid():
        return {"algorithm": "UUID v4", "key": str(uuid.uuid4()), "format": "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx", "length": 36}

    @staticmethod
    def generate_sha256(data=None):
        if not data: data = secrets.token_hex(16)
        h = hashlib.sha256(data.encode()).hexdigest()
        return {"algorithm": "SHA-256", "key": h, "input": data, "length": 64}

    @staticmethod
    def generate_hmac(secret=None, message=None):
        if not secret: secret = secrets.token_hex(16)
        if not message: message = secrets.token_hex(8)
        h = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        return {"algorithm": "HMAC-SHA256", "key": h, "secret": secret, "message": message, "length": 64}

    @staticmethod
    def generate_base64(data=None):
        if not data: data = secrets.token_bytes(32)
        encoded = base64.b64encode(data).decode()
        return {"algorithm": "Base64", "key": encoded, "original": data.hex() if isinstance(data, bytes) else data, "length": len(encoded)}

    @staticmethod
    def generate_aes(data=None):
        if AES_cipher is None: return {"algorithm": "AES-256", "error": "pycryptodome not installed"}
        if not data: data = secrets.token_hex(16)
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        cipher = AES_cipher.new(key, AES_cipher.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data.encode(), AES_cipher.block_size))
        return {"algorithm": "AES-256", "key": base64.b64encode(encrypted).decode(), "iv": base64.b64encode(iv).decode(), "original": data, "length": len(encrypted)}

    @staticmethod
    def generate_rsa():
        if rsa_lib is None: return {"algorithm": "RSA-2048", "error": "rsa not installed"}
        pub, priv = rsa_lib.newkeys(2048)
        return {"algorithm": "RSA-2048", "public_key": pub.save_pkcs1().decode(), "private_key": priv.save_pkcs1().decode(), "format": "PKCS#1", "length": 2048}

    @staticmethod
    def generate_bcrypt(password=None):
        if bcrypt_lib is None: return {"algorithm": "Bcrypt", "error": "bcrypt not installed"}
        if not password: password = secrets.token_hex(8)
        h = bcrypt_lib.hashpw(password.encode(), bcrypt_lib.gensalt()).decode()
        return {"algorithm": "Bcrypt", "key": h, "password": password, "cost_factor": 12, "length": len(h)}

    @staticmethod
    def generate_argon2(password=None):
        if _argon2 is None: return {"algorithm": "Argon2id", "error": "argon2-cffi not installed"}
        if not password: password = secrets.token_hex(8)
        h = _argon2.hash(password)
        return {"algorithm": "Argon2id", "key": h, "password": password, "params": {"time_cost": 2, "memory_cost": 19456, "parallelism": 1}, "length": len(h)}

    @staticmethod
    def generate_crc32(data=None):
        if not data: data = secrets.token_hex(8)
        crc = zlib.crc32(data.encode()) & 0xffffffff
        return {"algorithm": "CRC-32", "key": hex(crc)[2:].zfill(8), "data": data, "length": 8}

    @staticmethod
    def generate_jwt(payload=None):
        if pyjwt is None: return {"algorithm": "JWT-HS256", "error": "PyJWT not installed"}
        if not payload: payload = {"user_id": secrets.token_hex(8), "role": "admin", "exp": (datetime.utcnow() + timedelta(hours=24)).isoformat()}
        secret = secrets.token_hex(32)
        token = pyjwt.encode(payload, secret, algorithm="HS256")
        return {"algorithm": "JWT-HS256", "key": token, "payload": payload, "secret": secret, "expires_in": "24 hours", "length": len(token)}

    @staticmethod
    def generate_api_key(prefix="gw", length=32):
        chars = string.ascii_letters + string.digits
        random_part = ''.join(secrets.choice(chars) for _ in range(length))
        key = f"{prefix}_{random_part}"
        return {"algorithm": "API Key (مخصص)", "key": key, "prefix": prefix, "format": f"{prefix}_xxx...", "length": len(key)}

    @staticmethod
    def generate_nanoid(size=21):
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
        nid = ''.join(secrets.choice(alphabet) for _ in range(size))
        return {"algorithm": "Nano ID", "key": nid, "size": size, "length": len(nid)}

    @staticmethod
    def generate_otp(length=6):
        otp = ''.join(secrets.choice('0123456789') for _ in range(length))
        return {"algorithm": "OTP (Numeric)", "key": otp, "length": length, "expires_in": "60 seconds"}

    @staticmethod
    def generate_random_token(token_type="hex", length=32):
        if token_type == "hex": token = secrets.token_hex(length)
        elif token_type == "urlsafe": token = secrets.token_urlsafe(length)
        else: token = secrets.token_bytes(length).hex()
        return {"algorithm": f"Random-{token_type.upper()}", "key": token, "type": token_type, "length": len(token)}

    @staticmethod
    def generate_hash_with_timestamp(data=None):
        if not data: data = secrets.token_hex(8)
        ts = int(time.time())
        h = hashlib.sha256(f"{data}{ts}".encode()).hexdigest()
        return {"algorithm": "Hash with Timestamp", "key": h, "data": data, "timestamp": ts, "timestamp_iso": datetime.fromtimestamp(ts).isoformat(), "length": 64}


ALGORITHMS_LIST = [
    {"id": "uuid", "name": "UUID v4", "category": "معرفات", "desc": "معرف عالمي فريد"},
    {"id": "sha256", "name": "SHA-256", "category": "هاش", "desc": "هاش آمن 256 بت"},
    {"id": "hmac", "name": "HMAC-SHA256", "category": "هاش", "desc": "هاش مع مفتاح سري"},
    {"id": "base64", "name": "Base64", "category": "تشفير", "desc": "تشفير قابل للفك"},
    {"id": "aes", "name": "AES-256", "category": "تشفير متماثل", "desc": "تشفير متماثل 256 بت"},
    {"id": "rsa", "name": "RSA-2048", "category": "تشفير غير متماثل", "desc": "مفاتيح عامة/خاصة"},
    {"id": "bcrypt", "name": "Bcrypt", "category": "هاش آمن", "desc": "هاش بطيء لكلمات المرور"},
    {"id": "argon2", "name": "Argon2id", "category": "هاش آمن", "desc": "أقوى خوارزمية هاش"},
    {"id": "crc32", "name": "CRC-32", "category": "تحقق", "desc": "تحقق من سلامة البيانات"},
    {"id": "jwt", "name": "JWT-HS256", "category": "مصادقة", "desc": "JSON Web Token"},
    {"id": "api_key", "name": "API Key (مخصص)", "category": "مفاتيح API", "desc": "مفتاح بادئة مخصصة"},
    {"id": "nanoid", "name": "Nano ID", "category": "معرفات", "desc": "معرف صغير آمن"},
    {"id": "otp", "name": "OTP (رقمي)", "category": "مؤقت", "desc": "كلمة مرور لمرة واحدة"},
    {"id": "random", "name": "عشوائي (متنوع)", "category": "عشوائي", "desc": "رموز عشوائية"},
    {"id": "timestamp_hash", "name": "هاش مع طابع زمني", "category": "هاش", "desc": "هاش + وقت التوليد"},
]

ALGORITHM_PARAMS = {
    "sha256": [{"key": "data", "label": "البيانات", "type": "text", "placeholder": "اختياري"}],
    "hmac": [
        {"key": "secret", "label": "المفتاح السري", "type": "text", "placeholder": "اختياري"},
        {"key": "message", "label": "الرسالة", "type": "text", "placeholder": "اختياري"}
    ],
    "base64": [{"key": "data", "label": "البيانات", "type": "text", "placeholder": "اختياري"}],
    "aes": [{"key": "data", "label": "البيانات للتشفير", "type": "text", "placeholder": "اختياري"}],
    "bcrypt": [{"key": "password", "label": "كلمة المرور", "type": "text", "placeholder": "اختياري"}],
    "argon2": [{"key": "password", "label": "كلمة المرور", "type": "text", "placeholder": "اختياري"}],
    "api_key": [
        {"key": "prefix", "label": "البادئة", "type": "text", "default": "gw"},
        {"key": "length", "label": "الطول", "type": "number", "default": 32}
    ],
    "nanoid": [{"key": "size", "label": "الحجم", "type": "number", "default": 21}],
    "otp": [{"key": "length", "label": "الطول", "type": "number", "default": 6}],
    "random": [
        {"key": "type", "label": "النوع", "type": "select", "options": ["hex", "urlsafe", "bytes"], "default": "hex"},
        {"key": "length", "label": "الطول", "type": "number", "default": 32}
    ],
    "jwt": [{"key": "payload", "label": "الحمولة (JSON)", "type": "textarea", "placeholder": '{"user_id":"123","role":"admin"}'}],
    "timestamp_hash": [{"key": "data", "label": "البيانات", "type": "text", "placeholder": "اختياري"}]
}


def run_algorithm(algo_id, params=None):
    if params is None: params = {}
    p = params
    m = {
        "uuid": lambda: AllAlgorithms.generate_uuid(),
        "sha256": lambda: AllAlgorithms.generate_sha256(p.get("data")),
        "hmac": lambda: AllAlgorithms.generate_hmac(p.get("secret"), p.get("message")),
        "base64": lambda: AllAlgorithms.generate_base64(p.get("data")),
        "aes": lambda: AllAlgorithms.generate_aes(p.get("data")),
        "rsa": lambda: AllAlgorithms.generate_rsa(),
        "bcrypt": lambda: AllAlgorithms.generate_bcrypt(p.get("password")),
        "argon2": lambda: AllAlgorithms.generate_argon2(p.get("password")),
        "crc32": lambda: AllAlgorithms.generate_crc32(p.get("data")),
        "jwt": lambda: AllAlgorithms.generate_jwt(p.get("payload")),
        "api_key": lambda: AllAlgorithms.generate_api_key(p.get("prefix", "gw"), int(p.get("length", 32))),
        "nanoid": lambda: AllAlgorithms.generate_nanoid(int(p.get("size", 21))),
        "otp": lambda: AllAlgorithms.generate_otp(int(p.get("length", 6))),
        "random": lambda: AllAlgorithms.generate_random_token(p.get("type", "hex"), int(p.get("length", 32))),
        "timestamp_hash": lambda: AllAlgorithms.generate_hash_with_timestamp(p.get("data"))
    }
    func = m.get(algo_id)
    if not func: raise ValueError(f"خوارزمية غير معروفة: {algo_id}")
    result = func()
    return result
