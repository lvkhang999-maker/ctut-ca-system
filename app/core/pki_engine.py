# app/core/pki_engine.py
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

STORAGE_CA = "storage/ca"
STORAGE_USERS = "storage/users"
os.makedirs(STORAGE_CA, exist_ok=True)
os.makedirs(STORAGE_USERS, exist_ok=True)

class PKIEngine:
    @staticmethod
    def init_root_ca():
        root_key_path = os.path.join(STORAGE_CA, "root_private.pem")
        root_cert_path = os.path.join(STORAGE_CA, "root_cert.pem")
        
        if os.path.exists(root_key_path) and os.path.exists(root_cert_path):
            return "[!] Hệ thống Root CA của trường đã tồn tại."

        root_key = ec.generate_private_key(ec.SECP256R1())
        root_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CTUT"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CTUT Root CA v1")
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False
            ), critical=True)
            .sign(root_key, hashes.SHA256())
        )
        
        with open(root_key_path, "wb") as f:
            f.write(root_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ))
        with open(root_cert_path, "wb") as f:
            f.write(root_cert.public_bytes(serialization.Encoding.PEM))
        return "[+] Khởi tạo thành công điểm neo tin cậy CTUT Root CA."

    @staticmethod
    def issue_user_certificate(user_id: str, user_password: str, common_name: str, email: str):
        user_key = ec.generate_private_key(ec.SECP256R1())
        encrypted_user_key = user_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(user_password.encode())
        )
        
        user_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CTUT"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.USER_ID, user_id)
        ])
        
        with open(os.path.join(STORAGE_CA, "root_private.pem"), "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(os.path.join(STORAGE_CA, "root_cert.pem"), "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
            
        now = datetime.datetime.now(datetime.timezone.utc)
        user_cert = (
            x509.CertificateBuilder()
            .subject_name(user_subject)
            .issuer_name(root_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
            .sign(root_key, hashes.SHA256())
        )
        
        with open(os.path.join(STORAGE_USERS, f"{user_id}_private.pem"), "wb") as f:
            f.write(encrypted_user_key)
        with open(os.path.join(STORAGE_USERS, f"{user_id}_cert.pem"), "wb") as f:
            f.write(user_cert.public_bytes(serialization.Encoding.PEM))
            
        return "[+] Đã sinh khóa và cấp phát chứng thư X.509 v3."