import hashlib, uuid, base64, secrets, hmac, zlib, time, re, string, json, struct
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

try: import jwt as pyjwt
except: pyjwt = None
try: import bcrypt as bcrypt_lib
except: bcrypt_lib = None
try:
    from argon2 import PasswordHasher as Argon2PH
    _argon2 = Argon2PH()
except: _argon2 = None
_crypto_ok = True
try: from Crypto.Cipher import AES
except: _crypto_ok = False
try: from Crypto.Cipher import DES
except: DES = None
try: from Crypto.Cipher import DES3
except: DES3 = None
try: from Crypto.Cipher import Blowfish
except: Blowfish = None
try: from Crypto.Cipher import ChaCha20
except: ChaCha20 = None
try: from Crypto.Cipher import ARC4
except: ARC4 = None
try: from Crypto.Cipher import IDEA
except: IDEA = 'MISSING'
try: from Crypto.Util.Padding import pad
except: pad = None
try: from Crypto.PublicKey import DSA
except: DSA = None
try: from Crypto.PublicKey import ECC
except: ECC = None
try: import rsa as rsa_lib
except: rsa_lib = None
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except: ed25519 = None
try: import pyotp as pyotp_lib
except: pyotp_lib = None
try: from base58 import b58encode
except: b58encode = None
try: import brotli as brotli_lib
except: brotli_lib = None
try: import lzma as lzma_lib
except: lzma_lib = None
try: import zstandard as zstd_lib
except: zstd_lib = None
try: import bson as bson_lib
except: bson_lib = None
try: import yaml as yaml_lib
except: yaml_lib = None
try: import toml as toml_lib
except: toml_lib = None
try: import gmssl
except: gmssl = None
try: import sympy
except: sympy = None
try: import ipaddress
except: ipaddress = None


class AlgorithmEngine:

    # ==================== 1. HASH (15) ====================
    @staticmethod
    def hash_md5(data=None):
        if not data: data = secrets.token_hex(8)
        return {"algorithm": "MD5", "key": hashlib.md5(data.encode()).hexdigest(), "length": 32, "category": "هاش"}

    @staticmethod
    def hash_sha1(data=None):
        if not data: data = secrets.token_hex(8)
        return {"algorithm": "SHA-1", "key": hashlib.sha1(data.encode()).hexdigest(), "length": 40, "category": "هاش"}

    @staticmethod
    def hash_sha256(data=None):
        if not data: data = secrets.token_hex(8)
        return {"algorithm": "SHA-256", "key": hashlib.sha256(data.encode()).hexdigest(), "length": 64, "category": "هاش"}

    @staticmethod
    def hash_sha512(data=None):
        if not data: data = secrets.token_hex(8)
        return {"algorithm": "SHA-512", "key": hashlib.sha512(data.encode()).hexdigest(), "length": 128, "category": "هاش"}

    @staticmethod
    def hash_bcrypt(password=None):
        if bcrypt_lib is None: return {"algorithm": "Bcrypt", "error": "bcrypt not installed", "category": "هاش"}
        if not password: password = secrets.token_hex(8)
        hashed = bcrypt_lib.hashpw(password.encode(), bcrypt_lib.gensalt())
        return {"algorithm": "Bcrypt", "key": hashed.decode(), "password": password, "length": 60, "category": "هاش"}

    @staticmethod
    def hash_argon2(password=None):
        if _argon2 is None: return {"algorithm": "Argon2id", "error": "argon2 not installed", "category": "هاش"}
        if not password: password = secrets.token_hex(8)
        return {"algorithm": "Argon2id", "key": _argon2.hash(password), "password": password, "length": 95, "category": "هاش"}

    @staticmethod
    def hash_scrypt(password=None):
        if not password: password = secrets.token_hex(8)
        salt = secrets.token_hex(8)
        result = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=64)
        return {"algorithm": "Scrypt", "key": result.hex(), "salt": salt, "length": 128, "category": "هاش"}

    @staticmethod
    def hash_pbkdf2(password=None):
        if not password: password = secrets.token_hex(8)
        salt = secrets.token_hex(8)
        result = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, dklen=32)
        return {"algorithm": "PBKDF2-SHA256", "key": result.hex(), "iterations": 100000, "length": 64, "category": "هاش"}

    @staticmethod
    def hash_crc32(data=None):
        if not data: data = secrets.token_hex(8)
        crc = zlib.crc32(data.encode()) & 0xffffffff
        return {"algorithm": "CRC-32", "key": hex(crc)[2:].zfill(8), "length": 8, "category": "هاش"}

    @staticmethod
    def hash_crc64(data=None):
        if not data: data = secrets.token_hex(8)
        crc = zlib.crc32(data.encode()) & 0xffffffff
        crc64 = (crc << 32) | zlib.crc32(data[::-1].encode()) & 0xffffffff
        return {"algorithm": "CRC-64", "key": hex(crc64)[2:].zfill(16), "length": 16, "category": "هاش"}

    @staticmethod
    def hash_ripemd160(data=None):
        if not data: data = secrets.token_hex(8)
        h = hashlib.new('ripemd160', data.encode())
        return {"algorithm": "RIPEMD-160", "key": h.hexdigest(), "length": 40, "category": "هاش"}

    @staticmethod
    def hash_whirlpool(data=None):
        if not data: data = secrets.token_hex(8)
        h = hashlib.new('whirlpool', data.encode())
        return {"algorithm": "Whirlpool", "key": h.hexdigest(), "length": 128, "category": "هاش"}

    @staticmethod
    def hash_tiger(data=None):
        if not data: data = secrets.token_hex(8)
        h = hashlib.new('tiger', data.encode())
        return {"algorithm": "Tiger", "key": h.hexdigest(), "length": 48, "category": "هاش"}

    @staticmethod
    def hash_gost(data=None):
        if not data: data = secrets.token_hex(8)
        h = hashlib.new('gost', data.encode())
        return {"algorithm": "GOST", "key": h.hexdigest(), "length": 64, "category": "هاش"}

    @staticmethod
    def hash_sm3(data=None):
        if gmssl is None: return {"algorithm": "SM3", "error": "gmssl not installed", "category": "هاش"}
        if not data: data = secrets.token_hex(8)
        return {"algorithm": "SM3", "key": gmssl.sm3.sm3_hash(list(data.encode())), "length": 64, "category": "هاش"}

    # ==================== 2. SYMMETRIC (10) ====================
    @staticmethod
    def _sym_encrypt(algo_name, key_size, iv_size, cipher_cls, data=None, block_size=16):
        if cipher_cls is None: return {"algorithm": algo_name, "error": "الخوارزمية غير متوفرة", "category": "تشفير متماثل"}
        if not pad: return {"algorithm": algo_name, "error": "pycryptodome not installed", "category": "تشفير متماثل"}
        if not data: data = secrets.token_hex(8)
        key = secrets.token_bytes(key_size)
        iv = secrets.token_bytes(iv_size)
        cipher = cipher_cls.new(key, cipher_cls.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data.encode(), block_size))
        return {"algorithm": algo_name, "key": base64.b64encode(encrypted).decode(), "iv": base64.b64encode(iv).decode(), "original": data, "length": len(encrypted), "category": "تشفير متماثل"}

    @staticmethod
    def encrypt_aes128(data=None):
        return AlgorithmEngine._sym_encrypt("AES-128-CBC", 16, 16, AES, data, 16)

    @staticmethod
    def encrypt_aes192(data=None):
        return AlgorithmEngine._sym_encrypt("AES-192-CBC", 24, 16, AES, data, 16)

    @staticmethod
    def encrypt_aes256(data=None):
        return AlgorithmEngine._sym_encrypt("AES-256-CBC", 32, 16, AES, data, 16)

    @staticmethod
    def encrypt_des(data=None):
        return AlgorithmEngine._sym_encrypt("DES-CBC", 8, 8, DES, data, 8)

    @staticmethod
    def encrypt_3des(data=None):
        return AlgorithmEngine._sym_encrypt("3DES-CBC", 24, 8, DES3, data, 8)

    @staticmethod
    def encrypt_blowfish(data=None):
        return AlgorithmEngine._sym_encrypt("Blowfish-CBC", 16, 8, Blowfish, data, 8)

    @staticmethod
    def encrypt_twofish(data=None):
        return AlgorithmEngine._sym_encrypt("Twofish (AES)", 16, 16, AES, data, 16)

    @staticmethod
    def encrypt_chacha20(data=None):
        if ChaCha20 is None: return {"algorithm": "ChaCha20", "error": "pycryptodome not installed", "category": "تشفير متماثل"}
        if not data: data = secrets.token_hex(8)
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted = cipher.encrypt(data.encode())
        return {"algorithm": "ChaCha20", "key": base64.b64encode(encrypted).decode(), "nonce": base64.b64encode(nonce).decode(), "length": len(encrypted), "category": "تشفير متماثل"}

    @staticmethod
    def encrypt_rc4(data=None):
        if ARC4 is None: return {"algorithm": "RC4", "error": "pycryptodome not installed", "category": "تشفير متماثل"}
        if not data: data = secrets.token_hex(8)
        key = secrets.token_bytes(16)
        cipher = ARC4.new(key)
        encrypted = cipher.encrypt(data.encode())
        return {"algorithm": "RC4", "key": base64.b64encode(encrypted).decode(), "length": len(encrypted), "category": "تشفير متماثل"}

    @staticmethod
    def encrypt_idea(data=None):
        if IDEA == 'MISSING': return {"algorithm": "IDEA (محاكاة)", "key": secrets.token_hex(32), "original": data or secrets.token_hex(4), "length": 32, "category": "تشفير متماثل"}
        return AlgorithmEngine._sym_encrypt("IDEA-CBC", 16, 8, IDEA, data, 8)

    # ==================== 3. ASYMMETRIC (8) ====================
    @staticmethod
    def generate_rsa1024():
        if rsa_lib is None: return {"algorithm": "RSA-1024", "error": "rsa not installed", "category": "تشفير غير متماثل"}
        pub, priv = rsa_lib.newkeys(1024)
        return {"algorithm": "RSA-1024", "public_key": pub.save_pkcs1().decode(), "private_key": priv.save_pkcs1().decode(), "key_size": 1024, "category": "تشفير غير متماثل"}

    @staticmethod
    def generate_rsa2048():
        if rsa_lib is None: return {"algorithm": "RSA-2048", "error": "rsa not installed", "category": "تشفير غير متماثل"}
        pub, priv = rsa_lib.newkeys(2048)
        return {"algorithm": "RSA-2048", "public_key": pub.save_pkcs1().decode(), "private_key": priv.save_pkcs1().decode(), "key_size": 2048, "category": "تشفير غير متماثل"}

    @staticmethod
    def generate_rsa4096():
        if rsa_lib is None: return {"algorithm": "RSA-4096", "error": "rsa not installed", "category": "تشفير غير متماثل"}
        pub, priv = rsa_lib.newkeys(4096)
        return {"algorithm": "RSA-4096", "public_key": pub.save_pkcs1().decode(), "private_key": priv.save_pkcs1().decode(), "key_size": 4096, "category": "تشفير غير متماثل"}

    @staticmethod
    def generate_dsa():
        if DSA is None: return {"algorithm": "DSA-2048", "error": "pycryptodome not installed", "category": "تشفير غير متماثل"}
        key = DSA.generate(2048)
        return {"algorithm": "DSA-2048", "public_key": key.public_key().export_key().decode(), "private_key": key.export_key().decode(), "key_size": 2048, "category": "تشفير غير متماثل"}

    @staticmethod
    def generate_ecdsa():
        if ECC is None: return {"algorithm": "ECDSA-P256", "error": "pycryptodome not installed", "category": "تشفير غير متماثل"}
        key = ECC.generate(curve='P-256')
        return {"algorithm": "ECDSA-P256", "public_key": key.public_key().export_key().decode(), "private_key": key.export_key().decode(), "curve": "P-256", "category": "تشفير غير متماثل"}

    @staticmethod
    def generate_ed25519():
        if ed25519 is None: return {"algorithm": "Ed25519", "error": "cryptography not installed", "category": "تشفير غير متماثل"}
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        return {"algorithm": "Ed25519", "public_key": pub.public_bytes_raw().hex(), "private_key": priv.private_bytes_raw().hex(), "category": "تشفير غير متماثل"}

    @staticmethod
    def generate_elgamal():
        return {"algorithm": "ElGamal-1024 (محاكاة)", "public_key": secrets.token_hex(64), "private_key": secrets.token_hex(32), "key_size": 1024, "category": "تشفير غير متماثل"}

    # ==================== 4. IDS (10) ====================
    @staticmethod
    def generate_uuid1():
        return {"algorithm": "UUID v1", "key": str(uuid.uuid1()), "length": 36, "category": "معرفات"}

    @staticmethod
    def generate_uuid2():
        return {"algorithm": "UUID v2 (محاكاة)", "key": str(uuid.uuid1()), "length": 36, "category": "معرفات"}

    @staticmethod
    def generate_uuid3():
        return {"algorithm": "UUID v3 (MD5)", "key": str(uuid.uuid3(uuid.NAMESPACE_DNS, "example.com")), "length": 36, "category": "معرفات"}

    @staticmethod
    def generate_uuid4():
        return {"algorithm": "UUID v4", "key": str(uuid.uuid4()), "length": 36, "category": "معرفات"}

    @staticmethod
    def generate_uuid5():
        return {"algorithm": "UUID v5 (SHA-1)", "key": str(uuid.uuid5(uuid.NAMESPACE_DNS, "example.com")), "length": 36, "category": "معرفات"}

    @staticmethod
    def generate_uuid6():
        ts = int(time.time() * 1000)
        return {"algorithm": "UUID v6 (محاكاة)", "key": f"{ts:x}-{secrets.token_hex(4)}-{secrets.token_hex(4)}", "length": 36, "category": "معرفات"}

    @staticmethod
    def generate_uuid7():
        ts = int(time.time() * 1000)
        return {"algorithm": "UUID v7 (محاكاة)", "key": f"{ts:x}-{secrets.token_hex(4)}-{secrets.token_hex(4)}-{secrets.token_hex(4)}", "length": 36, "category": "معرفات"}

    @staticmethod
    def generate_nanoid(size=21):
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
        nid = ''.join(secrets.choice(alphabet) for _ in range(size))
        return {"algorithm": "Nano ID", "key": nid, "size": size, "length": len(nid), "category": "معرفات"}

    @staticmethod
    def generate_snowflake():
        ts = int(time.time() * 1000)
        snowflake = (ts << 22) | (secrets.randbits(10) << 12) | secrets.randbits(12)
        return {"algorithm": "Snowflake ID", "key": str(snowflake), "length": len(str(snowflake)), "category": "معرفات"}

    @staticmethod
    def generate_ulid():
        ts = int(time.time() * 1000)
        return {"algorithm": "ULID", "key": f"{ts:x}-{secrets.token_hex(10)}", "length": 27, "category": "معرفات"}

    # ==================== 5. TOKENS (12) ====================
    @staticmethod
    def generate_jwt(payload=None):
        if pyjwt is None: return {"algorithm": "JWT-HS256", "error": "PyJWT not installed", "category": "رموز"}
        if not payload: payload = {"user_id": secrets.token_hex(8), "role": "admin", "exp": (datetime.utcnow() + timedelta(hours=24)).isoformat()}
        secret = secrets.token_hex(32)
        token = pyjwt.encode(payload, secret, algorithm="HS256")
        if isinstance(token, bytes): token = token.decode()
        return {"algorithm": "JWT-HS256", "key": token, "payload": payload, "secret": secret, "expires": "24h", "length": len(token), "category": "رموز"}

    @staticmethod
    def generate_jws():
        return {"algorithm": "JWS (محاكاة)", "key": f"eyJhbGciOiJIUzI1NiJ9.{base64.urlsafe_b64encode(json.dumps({'data': secrets.token_hex(4)}).encode()).decode().rstrip('=')}.{secrets.token_hex(16)}", "category": "رموز"}

    @staticmethod
    def generate_jwe():
        return {"algorithm": "JWE (محاكاة)", "key": f"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.{secrets.token_hex(32)}.{secrets.token_hex(16)}.{secrets.token_hex(32)}", "category": "رموز"}

    @staticmethod
    def generate_otp(length=6):
        otp = ''.join(secrets.choice('0123456789') for _ in range(length))
        return {"algorithm": "OTP (Numeric)", "key": otp, "length": length, "expires_in": "60s", "category": "رموز"}

    @staticmethod
    def generate_totp():
        if pyotp_lib is None: return {"algorithm": "TOTP", "error": "pyotp not installed", "category": "رموز"}
        secret = pyotp_lib.random_base32()
        totp = pyotp_lib.TOTP(secret)
        return {"algorithm": "TOTP", "key": totp.now(), "secret": secret, "interval": 30, "category": "رموز"}

    @staticmethod
    def generate_hotp():
        if pyotp_lib is None: return {"algorithm": "HOTP", "error": "pyotp not installed", "category": "رموز"}
        secret = pyotp_lib.random_base32()
        hotp = pyotp_lib.HOTP(secret)
        return {"algorithm": "HOTP", "key": hotp.at(0), "secret": secret, "counter": 0, "category": "رموز"}

    @staticmethod
    def generate_api_key(prefix="gw", length=32):
        chars = string.ascii_letters + string.digits
        rand = ''.join(secrets.choice(chars) for _ in range(length))
        return {"algorithm": "API Key", "key": f"{prefix}_{rand}", "prefix": prefix, "length": len(prefix) + 1 + length, "category": "رموز"}

    @staticmethod
    def generate_secret_key(length=64):
        return {"algorithm": "Secret Key", "key": secrets.token_hex(length), "length": length * 2, "category": "رموز"}

    @staticmethod
    def generate_refresh_token(length=32):
        return {"algorithm": "Refresh Token", "key": secrets.token_urlsafe(length), "length": len(secrets.token_urlsafe(length)), "category": "رموز"}

    @staticmethod
    def generate_access_token(length=32):
        return {"algorithm": "Access Token", "key": secrets.token_hex(length), "length": length * 2, "category": "رموز"}

    @staticmethod
    def generate_bearer_token():
        token = secrets.token_urlsafe(32)
        return {"algorithm": "Bearer Token", "key": f"Bearer {token}", "token": token, "length": len(token) + 7, "category": "رموز"}

    @staticmethod
    def generate_basic_auth():
        username = secrets.token_hex(4)
        password = secrets.token_hex(8)
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"algorithm": "Basic Auth", "key": f"Basic {encoded}", "username": username, "password": password, "category": "رموز"}

    # ==================== 6. ENCODINGS (8) ====================
    @staticmethod
    def encode_base64(data=None):
        if not data: data = secrets.token_hex(8)
        encoded = base64.b64encode(data.encode()).decode()
        return {"algorithm": "Base64", "key": encoded, "original": data, "length": len(encoded), "category": "تشفير"}

    @staticmethod
    def encode_base64url(data=None):
        if not data: data = secrets.token_hex(8)
        encoded = base64.urlsafe_b64encode(data.encode()).decode().rstrip('=')
        return {"algorithm": "Base64URL", "key": encoded, "original": data, "length": len(encoded), "category": "تشفير"}

    @staticmethod
    def encode_base32(data=None):
        if not data: data = secrets.token_hex(8)
        encoded = base64.b32encode(data.encode()).decode()
        return {"algorithm": "Base32", "key": encoded, "original": data, "length": len(encoded), "category": "تشفير"}

    @staticmethod
    def encode_base58(data=None):
        if b58encode is None: return {"algorithm": "Base58", "error": "base58 not installed", "category": "تشفير"}
        if not data: data = secrets.token_hex(8)
        encoded = b58encode(data.encode()).decode()
        return {"algorithm": "Base58", "key": encoded, "original": data, "length": len(encoded), "category": "تشفير"}

    @staticmethod
    def encode_base62(data=None):
        if not data: data = secrets.token_hex(8)
        chars = string.ascii_letters + string.digits
        result = ''.join(chars[ord(c) % len(chars)] for c in data)
        return {"algorithm": "Base62", "key": result, "original": data, "length": len(result), "category": "تشفير"}

    @staticmethod
    def encode_base85(data=None):
        if not data: data = secrets.token_hex(8)
        encoded = base64.b85encode(data.encode()).decode()
        return {"algorithm": "Base85 (ASCII85)", "key": encoded, "original": data, "length": len(encoded), "category": "تشفير"}

    @staticmethod
    def encode_url(data=None):
        from urllib.parse import quote
        if not data: data = "hello world! @#$"
        encoded = quote(data)
        return {"algorithm": "URL Encoding", "key": encoded, "original": data, "length": len(encoded), "category": "تشفير"}

    @staticmethod
    def encode_html(data=None):
        from html import escape
        if not data: data = "<div class='test'>Hello & Welcome</div>"
        encoded = escape(data)
        return {"algorithm": "HTML Encoding", "key": encoded, "original": data, "length": len(encoded), "category": "تشفير"}

    # ==================== 7. COMPRESSION (6) ====================
    @staticmethod
    def compress_gzip(data=None):
        import gzip
        if not data: data = secrets.token_hex(16)
        compressed = gzip.compress(data.encode())
        return {"algorithm": "GZIP", "key": base64.b64encode(compressed).decode(), "original_length": len(data), "compressed_length": len(compressed), "ratio": f"{len(compressed)/len(data)*100:.1f}%", "category": "ضغط"}

    @staticmethod
    def compress_zlib(data=None):
        if not data: data = secrets.token_hex(16)
        compressed = zlib.compress(data.encode())
        return {"algorithm": "ZLIB", "key": base64.b64encode(compressed).decode(), "original_length": len(data), "compressed_length": len(compressed), "ratio": f"{len(compressed)/len(data)*100:.1f}%", "category": "ضغط"}

    @staticmethod
    def compress_deflate(data=None):
        if not data: data = secrets.token_hex(16)
        compressed = zlib.compress(data.encode())[2:-4]
        return {"algorithm": "DEFLATE", "key": base64.b64encode(compressed).decode(), "original_length": len(data), "compressed_length": len(compressed), "ratio": f"{len(compressed)/len(data)*100:.1f}%", "category": "ضغط"}

    @staticmethod
    def compress_brotli(data=None):
        if brotli_lib is None: return {"algorithm": "Brotli", "error": "brotli not installed", "category": "ضغط"}
        if not data: data = secrets.token_hex(16)
        compressed = brotli_lib.compress(data.encode())
        return {"algorithm": "Brotli", "key": base64.b64encode(compressed).decode(), "original_length": len(data), "compressed_length": len(compressed), "ratio": f"{len(compressed)/len(data)*100:.1f}%", "category": "ضغط"}

    @staticmethod
    def compress_lzma(data=None):
        if not data: data = secrets.token_hex(16)
        compressed = lzma_lib.compress(data.encode())
        return {"algorithm": "LZMA", "key": base64.b64encode(compressed).decode(), "original_length": len(data), "compressed_length": len(compressed), "ratio": f"{len(compressed)/len(data)*100:.1f}%", "category": "ضغط"}

    @staticmethod
    def compress_zstd(data=None):
        if zstd_lib is None: return {"algorithm": "ZSTD", "error": "zstandard not installed", "category": "ضغط"}
        if not data: data = secrets.token_hex(16)
        comp = zstd_lib.ZstdCompressor(level=3)
        compressed = comp.compress(data.encode())
        return {"algorithm": "ZSTD", "key": base64.b64encode(compressed).decode(), "original_length": len(data), "compressed_length": len(compressed), "ratio": f"{len(compressed)/len(data)*100:.1f}%", "category": "ضغط"}

    # ==================== 8. HMAC (6) ====================
    @staticmethod
    def hmac_md5(key=None, message=None):
        if not key: key = secrets.token_hex(8)
        if not message: message = secrets.token_hex(8)
        h = hmac.new(key.encode(), message.encode(), hashlib.md5)
        return {"algorithm": "HMAC-MD5", "key": h.hexdigest(), "length": 32, "category": "توقيع"}

    @staticmethod
    def hmac_sha1(key=None, message=None):
        if not key: key = secrets.token_hex(8)
        if not message: message = secrets.token_hex(8)
        h = hmac.new(key.encode(), message.encode(), hashlib.sha1)
        return {"algorithm": "HMAC-SHA1", "key": h.hexdigest(), "length": 40, "category": "توقيع"}

    @staticmethod
    def hmac_sha256(key=None, message=None):
        if not key: key = secrets.token_hex(8)
        if not message: message = secrets.token_hex(8)
        h = hmac.new(key.encode(), message.encode(), hashlib.sha256)
        return {"algorithm": "HMAC-SHA256", "key": h.hexdigest(), "length": 64, "category": "توقيع"}

    @staticmethod
    def hmac_sha512(key=None, message=None):
        if not key: key = secrets.token_hex(8)
        if not message: message = secrets.token_hex(8)
        h = hmac.new(key.encode(), message.encode(), hashlib.sha512)
        return {"algorithm": "HMAC-SHA512", "key": h.hexdigest(), "length": 128, "category": "توقيع"}

    @staticmethod
    def hmac_ripemd160(key=None, message=None):
        if not key: key = secrets.token_hex(8)
        if not message: message = secrets.token_hex(8)
        h = hmac.new(key.encode(), message.encode(), hashlib.new('ripemd160'))
        return {"algorithm": "HMAC-RIPEMD160", "key": h.hexdigest(), "length": 40, "category": "توقيع"}

    @staticmethod
    def hmac_blake2b(key=None, message=None):
        if not key: key = secrets.token_hex(8)
        if not message: message = secrets.token_hex(8)
        h = hmac.new(key.encode(), message.encode(), hashlib.blake2b)
        return {"algorithm": "HMAC-Blake2b", "key": h.hexdigest(), "length": 64, "category": "توقيع"}

    # ==================== 9. RANDOM (10) ====================
    @staticmethod
    def random_hex(length=32):
        return {"algorithm": "Random Hex", "key": secrets.token_hex(length), "length": length * 2, "category": "عشوائي"}

    @staticmethod
    def random_bytes(length=32):
        return {"algorithm": "Random Bytes", "key": secrets.token_bytes(length).hex(), "length": length, "category": "عشوائي"}

    @staticmethod
    def random_urlsafe(length=32):
        return {"algorithm": "Random URL-safe", "key": secrets.token_urlsafe(length), "length": len(secrets.token_urlsafe(length)), "category": "عشوائي"}

    @staticmethod
    def random_int(min_val=0, max_val=100):
        return {"algorithm": "Random Integer", "key": str(secrets.randbelow(max_val - min_val + 1) + min_val), "min": min_val, "max": max_val, "category": "عشوائي"}

    @staticmethod
    def random_password(length=12):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return {"algorithm": "Random Password", "key": ''.join(secrets.choice(chars) for _ in range(length)), "length": length, "category": "عشوائي"}

    @staticmethod
    def random_pin(length=4):
        return {"algorithm": "Random PIN", "key": ''.join(secrets.choice('0123456789') for _ in range(length)), "length": length, "category": "عشوائي"}

    @staticmethod
    def random_otp(length=6):
        return {"algorithm": "Random OTP", "key": ''.join(secrets.choice('0123456789') for _ in range(length)), "length": length, "category": "عشوائي"}

    @staticmethod
    def random_passphrase(words=6):
        wordlist = ["apple", "banana", "cherry", "date", "elder", "fig", "grape", "honey", "ice", "juice", "kiwi", "lemon", "mango", "nectar", "orange", "peach", "quince", "rasp", "straw", "tanger", "ultra", "violet", "water", "xenon", "yield", "zebra", "alpha", "beta", "delta", "gamma"]
        return {"algorithm": "Random Passphrase", "key": '-'.join(secrets.choice(wordlist) for _ in range(words)), "words": words, "category": "عشوائي"}

    @staticmethod
    def random_color():
        return {"algorithm": "Random Color (HEX)", "key": '#' + ''.join(secrets.choice('0123456789ABCDEF') for _ in range(6)), "category": "عشوائي"}

    @staticmethod
    def random_lorem(words=10):
        lorem = "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua".split()
        return {"algorithm": "Lorem Ipsum", "key": ' '.join(secrets.choice(lorem) for _ in range(words)), "category": "عشوائي"}

    # ==================== 10. DATA FORMAT (8) ====================
    @staticmethod
    def format_json():
        data = {"id": secrets.token_hex(4), "name": "test", "data": {"active": True, "count": secrets.randbelow(100)}}
        return {"algorithm": "JSON", "key": json.dumps(data, indent=2), "length": len(json.dumps(data)), "category": "تنسيق"}

    @staticmethod
    def format_xml():
        data = {"root": {"id": secrets.token_hex(4), "value": secrets.token_hex(4), "active": "true"}}
        xml = "<root>\n"
        for k, v in data.items():
            if isinstance(v, dict):
                xml += f"  <{k}>\n"
                for sk, sv in v.items():
                    xml += f"    <{sk}>{sv}</{sk}>\n"
                xml += f"  </{k}>\n"
            else:
                xml += f"  <{k}>{v}</{k}>\n"
        xml += "</root>"
        return {"algorithm": "XML", "key": xml, "length": len(xml), "category": "تنسيق"}

    @staticmethod
    def format_yaml():
        if yaml_lib is None: return {"algorithm": "YAML", "error": "PyYAML not installed", "category": "تنسيق"}
        data = {"id": secrets.token_hex(4), "data": {"value": secrets.token_hex(4), "active": True}}
        return {"algorithm": "YAML", "key": yaml_lib.dump(data, default_flow_style=False), "length": len(yaml_lib.dump(data)), "category": "تنسيق"}

    @staticmethod
    def format_toml():
        if toml_lib is None: return {"algorithm": "TOML", "error": "toml not installed", "category": "تنسيق"}
        data = {"id": secrets.token_hex(4), "data": {"value": secrets.token_hex(4), "count": secrets.randbelow(100)}}
        return {"algorithm": "TOML", "key": toml_lib.dumps(data), "length": len(toml_lib.dumps(data)), "category": "تنسيق"}

    @staticmethod
    def format_csv():
        import csv
        from io import StringIO
        data = [["id", "name", "active"], [secrets.token_hex(4), "test", "true"]]
        output = StringIO()
        writer = csv.writer(output)
        writer.writerows(data)
        return {"algorithm": "CSV", "key": output.getvalue(), "rows": len(data), "category": "تنسيق"}

    @staticmethod
    def format_ini():
        data = {"section": {"key1": secrets.token_hex(4), "key2": secrets.token_hex(4)}}
        ini = ""
        for s, vals in data.items():
            ini += f"[{s}]\n"
            for k, v in vals.items():
                ini += f"{k}={v}\n"
        return {"algorithm": "INI", "key": ini, "length": len(ini), "category": "تنسيق"}

    @staticmethod
    def format_properties():
        data = {"property1": secrets.token_hex(4), "property2": secrets.token_hex(4)}
        return {"algorithm": "Java Properties", "key": "\n".join(f"{k}={v}" for k, v in data.items()), "category": "تنسيق"}

    @staticmethod
    def format_bson():
        if bson_lib is None: return {"algorithm": "BSON", "error": "bson not installed", "category": "تنسيق"}
        data = {"id": secrets.token_hex(4), "data": secrets.token_hex(4)}
        binary = bson_lib.dumps(data)
        return {"algorithm": "BSON", "key": base64.b64encode(binary).decode(), "length": len(binary), "category": "تنسيق"}

    # ==================== 11. CONVERSIONS (10) ====================
    @staticmethod
    def convert_bin_to_hex(binary=None):
        if not binary: binary = format(secrets.randbits(32), 'b')
        return {"algorithm": "Binary to Hex", "input": binary, "key": hex(int(binary, 2))[2:], "category": "تحويل"}

    @staticmethod
    def convert_hex_to_bin(hex_str=None):
        if not hex_str: hex_str = secrets.token_hex(4)
        return {"algorithm": "Hex to Binary", "input": hex_str, "key": bin(int(hex_str, 16))[2:], "category": "تحويل"}

    @staticmethod
    def convert_dec_to_hex(decimal=None):
        if decimal is None: decimal = secrets.randbits(16)
        return {"algorithm": "Decimal to Hex", "input": str(decimal), "key": hex(decimal)[2:], "category": "تحويل"}

    @staticmethod
    def convert_rgb_to_hex(r=None, g=None, b=None):
        if r is None: r = secrets.randbelow(256)
        if g is None: g = secrets.randbelow(256)
        if b is None: b = secrets.randbelow(256)
        return {"algorithm": "RGB to HEX", "input": f"rgb({r},{g},{b})", "key": f"#{r:02x}{g:02x}{b:02x}", "category": "تحويل"}

    @staticmethod
    def convert_hex_to_rgb(hex_str=None):
        if not hex_str: hex_str = '#' + ''.join(secrets.choice('0123456789ABCDEF') for _ in range(6))
        h = hex_str.lstrip('#')
        r, g, b = tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
        return {"algorithm": "HEX to RGB", "input": h, "key": f"rgb({r},{g},{b})", "category": "تحويل"}

    @staticmethod
    def convert_unix_to_date(timestamp=None):
        if not timestamp: timestamp = int(time.time())
        return {"algorithm": "Unix to Date", "input": str(timestamp), "key": datetime.fromtimestamp(timestamp).isoformat(), "category": "تحويل"}

    @staticmethod
    def convert_date_to_unix(date_str=None):
        if not date_str: date_str = datetime.now().isoformat()
        dt = datetime.fromisoformat(date_str)
        return {"algorithm": "Date to Unix", "input": date_str, "key": str(int(dt.timestamp())), "category": "تحويل"}

    @staticmethod
    def convert_ip_to_int(ip=None):
        if ipaddress is None: return {"algorithm": "IP to Integer", "error": "ipaddress not available", "category": "تحويل"}
        if not ip: ip = f"{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}"
        ip_int = int(ipaddress.IPv4Address(ip))
        return {"algorithm": "IP to Integer", "input": ip, "key": str(ip_int), "category": "تحويل"}

    @staticmethod
    def convert_int_to_ip(ip_int=None):
        if ipaddress is None: return {"algorithm": "Integer to IP", "error": "ipaddress not available", "category": "تحويل"}
        if ip_int is None: ip_int = secrets.randbits(32)
        return {"algorithm": "Integer to IP", "input": str(ip_int), "key": str(ipaddress.IPv4Address(ip_int)), "category": "تحويل"}

    @staticmethod
    def convert_cidr_to_range(cidr=None):
        if ipaddress is None: return {"algorithm": "CIDR to Range", "error": "ipaddress not available", "category": "تحويل"}
        if not cidr: cidr = f"192.168.{secrets.randbelow(256)}.0/24"
        network = ipaddress.IPv4Network(cidr, strict=False)
        return {"algorithm": "CIDR to IP Range", "input": cidr, "key": f"{network.network_address} - {network.broadcast_address}", "hosts": network.num_addresses, "category": "تحويل"}

    # ==================== 12. CHECKSUM (5) ====================
    @staticmethod
    def checksum_8(data=None):
        if not data: data = secrets.token_hex(8)
        cs = sum(data.encode()) % 256
        return {"algorithm": "Checksum-8", "key": hex(cs)[2:].zfill(2), "length": 2, "category": "ضوابط"}

    @staticmethod
    def checksum_16(data=None):
        if not data: data = secrets.token_hex(8)
        cs = sum(data.encode()) % 65536
        return {"algorithm": "Checksum-16", "key": hex(cs)[2:].zfill(4), "length": 4, "category": "ضوابط"}

    @staticmethod
    def checksum_32(data=None):
        if not data: data = secrets.token_hex(8)
        cs = sum(data.encode()) % 4294967296
        return {"algorithm": "Checksum-32", "key": hex(cs)[2:].zfill(8), "length": 8, "category": "ضوابط"}

    @staticmethod
    def checksum_fletcher16(data=None):
        if not data: data = secrets.token_hex(8)
        s1 = s2 = 0
        for c in data.encode():
            s1 = (s1 + c) % 255
            s2 = (s2 + s1) % 255
        cs = (s2 << 8) | s1
        return {"algorithm": "Fletcher-16", "key": hex(cs)[2:].zfill(4), "length": 4, "category": "ضوابط"}

    @staticmethod
    def checksum_adler32(data=None):
        if not data: data = secrets.token_hex(8)
        return {"algorithm": "Adler-32", "key": hex(zlib.adler32(data.encode()) & 0xffffffff)[2:].zfill(8), "length": 8, "category": "ضوابط"}


# ==================== DYNAMIC REGISTRY ====================
def _discover_algos():
    algos = []
    for name in sorted(dir(AlgorithmEngine)):
        if name.startswith('_'): continue
        attr = getattr(AlgorithmEngine, name)
        if callable(attr):
            try:
                result = attr()
                cat = result.get("category", "أخرى")
                has_error = "error" in result
                desc = {"هاش": "توليد هاش آمن", "تشفير متماثل": "تشفير وفك تشفير", "تشفير غير متماثل": "مفاتيح عامة/خاصة",
                        "معرفات": "معرفات فريدة", "رموز": "رموز مصادقة", "تشفير": "ترميز بيانات",
                        "ضغط": "ضغط البيانات", "توقيع": "توقيع رقمي", "عشوائي": "قيم عشوائية",
                        "تنسيق": "تنسيق بيانات", "تحويل": "تحويل بين الأنظمة", "ضوابط": "مجموع تدقيق"}.get(cat, "")
                algos.append({"id": name, "name": result.get("algorithm", name), "category": cat, "desc": desc, "hasError": has_error})
            except: pass
    return algos


def _get_algo_params(algo_id):
    param_map = {
        "hash_md5": [{"key": "data", "label": "البيانات", "type": "text", "placeholder": "اترك فارغاً لتوليد عشوائي"}],
        "hash_sha1": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_sha256": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_sha512": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_bcrypt": [{"key": "password", "label": "كلمة المرور", "type": "text"}],
        "hash_argon2": [{"key": "password", "label": "كلمة المرور", "type": "text"}],
        "hash_scrypt": [{"key": "password", "label": "كلمة المرور", "type": "text"}],
        "hash_pbkdf2": [{"key": "password", "label": "كلمة المرور", "type": "text"}],
        "hash_crc32": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_crc64": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_ripemd160": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_whirlpool": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_tiger": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_gost": [{"key": "data", "label": "البيانات", "type": "text"}],
        "hash_sm3": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_aes128": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_aes192": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_aes256": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_des": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_3des": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_blowfish": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_twofish": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_chacha20": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_rc4": [{"key": "data", "label": "البيانات", "type": "text"}],
        "encrypt_idea": [{"key": "data", "label": "البيانات", "type": "text"}],
        "generate_nanoid": [{"key": "size", "label": "الحجم", "type": "number", "default": 21}],
        "generate_api_key": [{"key": "prefix", "label": "البادئة", "type": "text", "default": "gw"}, {"key": "length", "label": "الطول", "type": "number", "default": 32}],
        "generate_otp": [{"key": "length", "label": "الطول", "type": "number", "default": 6}],
        "generate_jwt": [{"key": "payload", "label": "الحمولة (JSON)", "type": "textarea"}],
        "generate_secret_key": [{"key": "length", "label": "الطول", "type": "number", "default": 64}],
        "generate_refresh_token": [{"key": "length", "label": "الطول", "type": "number", "default": 32}],
        "generate_access_token": [{"key": "length", "label": "الطول", "type": "number", "default": 32}],
        "random_hex": [{"key": "length", "label": "الطول", "type": "number", "default": 32}],
        "random_bytes": [{"key": "length", "label": "الطول", "type": "number", "default": 32}],
        "random_urlsafe": [{"key": "length", "label": "الطول", "type": "number", "default": 32}],
        "random_int": [{"key": "min_val", "label": "الحد الأدنى", "type": "number", "default": 0}, {"key": "max_val", "label": "الحد الأقصى", "type": "number", "default": 100}],
        "random_password": [{"key": "length", "label": "الطول", "type": "number", "default": 12}],
        "random_pin": [{"key": "length", "label": "الطول", "type": "number", "default": 4}],
        "random_otp": [{"key": "length", "label": "الطول", "type": "number", "default": 6}],
        "random_passphrase": [{"key": "words", "label": "عدد الكلمات", "type": "number", "default": 6}],
        "random_lorem": [{"key": "words", "label": "عدد الكلمات", "type": "number", "default": 10}],
        "convert_rgb_to_hex": [{"key": "r", "label": "Red", "type": "number", "default": 255}, {"key": "g", "label": "Green", "type": "number", "default": 128}, {"key": "b", "label": "Blue", "type": "number", "default": 0}],
        "convert_unix_to_date": [{"key": "timestamp", "label": "Unix Timestamp", "type": "number"}],
        "convert_date_to_unix": [{"key": "date_str", "label": "التاريخ (ISO)", "type": "text"}],
        "convert_bin_to_hex": [{"key": "binary", "label": "الرقم الثنائي", "type": "text"}],
        "convert_hex_to_bin": [{"key": "hex_str", "label": "الرقم السداسي", "type": "text"}],
        "convert_dec_to_hex": [{"key": "decimal", "label": "الرقم العشري", "type": "number", "default": 255}],
        "format_toml": [],
        "format_bson": [],
    }
    return param_map.get(algo_id, [])


ALGORITHMS_LIST = _discover_algos()
ALGORITHM_PARAMS = {a["id"]: _get_algo_params(a["id"]) for a in ALGORITHMS_LIST}

CATEGORIES = [
    {"id": "هاش", "name": "هاش (Hash)", "icon": "🔐", "count": 0},
    {"id": "تشفير متماثل", "name": "تشفير متماثل (Symmetric)", "icon": "🔑", "count": 0},
    {"id": "تشفير غير متماثل", "name": "تشفير غير متماثل (Asymmetric)", "icon": "🔏", "count": 0},
    {"id": "معرفات", "name": "معرفات (IDs)", "icon": "🆔", "count": 0},
    {"id": "رموز", "name": "رموز (Tokens)", "icon": "🎫", "count": 0},
    {"id": "تشفير", "name": "ترميز (Encodings)", "icon": "🔡", "count": 0},
    {"id": "ضغط", "name": "ضغط (Compression)", "icon": "📦", "count": 0},
    {"id": "توقيع", "name": "توقيع رقمي (HMAC)", "icon": "✍️", "count": 0},
    {"id": "عشوائي", "name": "عشوائي (Random)", "icon": "🎲", "count": 0},
    {"id": "تنسيق", "name": "تنسيق بيانات (Format)", "icon": "📋", "count": 0},
    {"id": "تحويل", "name": "تحويلات (Conversions)", "icon": "🔄", "count": 0},
    {"id": "ضوابط", "name": "ضوابط (Checksums)", "icon": "✅", "count": 0},
]

for cat in CATEGORIES:
    cat["count"] = sum(1 for a in ALGORITHMS_LIST if a["category"] == cat["id"])


def run_algorithm(algo_id, params=None):
    if params is None: params = {}
    method = getattr(AlgorithmEngine, algo_id, None)
    if not method:
        raise ValueError(f"خوارزمية غير معروفة: {algo_id}")
    result = method(**params)
    return result
