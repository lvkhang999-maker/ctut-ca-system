# app/main.py
import os
import sys
import sqlite3
import datetime
import socket
import random
import uuid
import zipfile


from typing import List
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext


# Khởi tạo ngữ cảnh bảo mật băm mật khẩu, sử dụng thuật toán bcrypt mặc định
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Cloud Infrastructure Security Patch: Force Global IPV4 Resolution
_orig_getaddrinfo = socket.getaddrinfo
def _patched_getaddrinfo(host, port, family=0, *args, **kwargs):
    return _orig_getaddrinfo(host, port, socket.AF_INET, *args, **kwargs)
socket.getaddrinfo = _patched_getaddrinfo

from fastapi import FastAPI, HTTPException, Form, UploadFile, File, Request, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, FileResponse
from contextlib import asynccontextmanager
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)

if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from app.core.pki_engine import PKIEngine
from app.core.pdf_engine import PDFEngine
from app.core.auth_engine import AuthEngine

DB_DIR = os.path.join(PROJECT_ROOT, "storage", "db")
DB_PATH = os.path.join(DB_DIR, "audit_logs.db")
USER_STORAGE = os.path.join(PROJECT_ROOT, "storage", "users")
CA_DIR = os.path.join(PROJECT_ROOT, "storage", "ca")

# =========================================================================
# ADVANCED SESSION MEMORY INTEGRATION
# Bộ nhớ RAM đệm toàn cục lưu vết trạng thái vượt qua 2FA của Giảng viên.
# Tránh lỗi dính trùng lặp OTP hoặc hết hạn Token khi chuyển tiếp sang Bước 3.
# =========================================================================
_user_active_sessions = {}  # Cấu trúc lưu vết: { "user_id": True/False }

_sandbox_otps = {}
_orig_generate_otp = AuthEngine.generate_otp
_orig_verify_otp = AuthEngine.verify_otp

def patched_generate_otp(user_id):
    try:
        return _orig_generate_otp(user_id)
    except Exception as e:
        otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
        _sandbox_otps[user_id] = otp
        raise ValueError(f"SANDBOX_MODE:{otp}")

def patched_verify_otp(user_id, otp):
    if user_id in _sandbox_otps and _sandbox_otps[user_id] == otp:
        return True
    return _orig_verify_otp(user_id, otp)

AuthEngine.generate_otp = patched_generate_otp
AuthEngine.verify_otp = patched_verify_otp

def init_audit_db():
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs(USER_STORAGE, exist_ok=True)
    os.makedirs(CA_DIR, exist_ok=True)
    
    root_key_path = os.path.join(CA_DIR, "root_private.pem")
    root_cert_path = os.path.join(CA_DIR, "root_cert.pem")
    
    if not os.path.exists(root_key_path) or not os.path.exists(root_cert_path):
        private_key = ec.generate_private_key(ec.SECP256R1())
        with open(root_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CTUT"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CTUT Root Certificate Authority")
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )
        with open(root_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        conn.execute("PRAGMA journal_mode=DELETE;")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS verification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                filename TEXT,
                status TEXT,
                signer TEXT,
                client_ip TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_roles (
                username TEXT PRIMARY KEY,
                password TEXT,
                role TEXT,
                is_active INTEGER DEFAULT 1
            )
        """)
        try:
            cursor.execute("ALTER TABLE admin_roles ADD COLUMN is_active INTEGER DEFAULT 1")
        except sqlite3.OperationalError:
            pass

        hashed_super = pwd_context.hash("ctut@2026")
        hashed_admin = pwd_context.hash("123456") 
        cursor.execute("INSERT OR IGNORE INTO admin_roles VALUES ('superadmin', ?, 'SUPER_ADMIN', 1)", (hashed_super,))
        cursor.execute("INSERT OR IGNORE INTO admin_roles VALUES ('admincds', ?, 'ADMIN', 1)", (hashed_admin,))
        conn.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_audit_db()
    yield

app = FastAPI(
    title="Hệ thống Hạ tầng Chữ ký số nội bộ CTUT", 
    description="Sản phẩm Nghiên cứu Khoa học - Trung tâm Chuyển đổi số trường ĐH KT-CN Cần Thơ",
    version="3.1.0",
    lifespan=lifespan
)

STATIC_DIR = os.path.join(CURRENT_DIR, "static")
app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static"
)

def verify_admin_privilege(username, password, required_role=None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Bước 1: Chỉ lọc tìm tài khoản theo Username
        cursor.execute("SELECT * FROM admin_roles WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        # Bước 2: Sử dụng thuật toán so sánh an toàn, chống tấn công timing-attack
        if not user or not pwd_context.verify(password, user["password"]):
            raise HTTPException(status_code=403, detail="Sai thông tin tài khoản hoặc mật khẩu quản trị.")
            
        if user["is_active"] == 0:
            raise HTTPException(status_code=403, detail="Tài khoản quản trị này đã bị vô hiệu hóa quyền truy cập.")
        if required_role == "SUPER_ADMIN" and user["role"] != "SUPER_ADMIN":
            raise HTTPException(status_code=403, detail="Thao tác thất bại. Tính năng này yêu cầu đặc quyền Super Admin.")
        return user["role"]

# =========================================================================
# TRỤC ĐIỀU PHỐI API GATEWAY
# =========================================================================

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def get_portal_interface():
    html_path = os.path.join(CURRENT_DIR, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>Hệ thống đang khởi tạo giao diện Front-end...</h3>"

@app.post("/api/v1/admin/toggle-active")
async def admin_toggle_active(
    target_user: str = Form(...),
    admin_user: str = Form(...),
    admin_pass: str = Form(...)
):
    current_role = verify_admin_privilege(admin_user, admin_pass)
    if admin_user == target_user:
        raise HTTPException(status_code=400, detail="Hệ thống từ chối lệnh tự vô hiệu hóa tài khoản chính mình.")
        
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT role, is_active FROM admin_roles WHERE username = ?", (target_user,))
        target = cursor.fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản mục tiêu.")
        if current_role == "ADMIN" and target["role"] == "SUPER_ADMIN":
            raise HTTPException(status_code=403, detail="Yêu cầu từ chối. Bạn không có quyền thay đổi trạng thái của Super Admin.")
            
        new_status = 0 if target["is_active"] == 1 else 1
        cursor.execute("UPDATE admin_roles SET is_active = ? WHERE username = ?", (new_status, target_user))
        
        status_txt = "VÔ HIỆU HÓA" if new_status == 0 else "KÍCH HOẠT LẠI"
        cursor.execute("""
            INSERT INTO verification_logs (timestamp, filename, status, signer, client_ip)
            VALUES (?, 'Hạ tầng hệ thống', ?, ?, '127.0.0.1')
        """, (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"TRẠNG THÁI [{status_txt}]", target_user))
        conn.commit()
        
    return {"status": "success", "message": f"Đã thực hiện {status_txt} thành công tài khoản '{target_user}'."}

@app.post("/api/v1/admin/assign-role")
async def admin_assign_role(
    target_user: str = Form(...),
    target_pass: str = Form(...),
    assigned_role: str = Form(...),
    admin_user: str = Form(...),
    admin_pass: str = Form(...)
):
    verify_admin_privilege(admin_user, admin_pass, required_role="SUPER_ADMIN")
    if assigned_role not in ["SUPER_ADMIN", "ADMIN"]:
        raise HTTPException(status_code=400, detail="Vai trò gán không hợp lệ.")
        
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO verification_logs (timestamp, filename, status, signer, client_ip)
                VALUES (?, 'Hạ tầng hệ thống', ?, ?, '127.0.0.1')
            """, (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"ỦY QUYỀN [{assigned_role}]", target_user))
            
            hashed_target_pass = pwd_context.hash(target_pass)
            cursor.execute("""
        INSERT INTO admin_roles (username, password, role, is_active) VALUES (?, ?, ?, 1)
        ON CONFLICT(username) DO UPDATE SET password=excluded.password, role=excluded.role
    """, (target_user, hashed_target_pass, assigned_role))
            conn.commit()
        return {"status": "success", "message": f"Đã phê duyệt cấp đặc quyền {assigned_role} thành công cho tài khoản '{target_user}'."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/admin/audit-history")
async def get_admin_audit_history(
    admin_user: str = Query(...), 
    admin_pass: str = Query(...)
):
    verify_admin_privilege(admin_user, admin_pass)
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, status, signer, client_ip 
                FROM verification_logs 
                WHERE filename = 'Hạ tầng hệ thống' 
                ORDER BY id DESC LIMIT 500
            """)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/user/register")
async def register_user(
    user_id: str = Form(...), 
    password: str = Form(...), 
    common_name: str = Form(...), 
    email: str = Form(...),
    admin_user: str = Form(...),
    admin_pass: str = Form(...)
):
    verify_admin_privilege(admin_user, admin_pass, required_role="SUPER_ADMIN")
    try:
        msg = PKIEngine.issue_user_certificate(user_id, password, common_name, email)
        return {"status": "success", "message": msg}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/admin/users")
async def admin_list_users(
    admin_user: str = Query(...), 
    admin_pass: str = Query(...)
):
    verify_admin_privilege(admin_user, admin_pass)
    users_list = []
    if not os.path.exists(USER_STORAGE):
        return users_list
        
    for file in os.listdir(USER_STORAGE):
        if file.endswith("_cert.pem"):
            user_id = file.replace("_cert.pem", "")
            cert_path = os.path.join(USER_STORAGE, file)
            try:
                with open(cert_path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn = cn_attrs[0].value if cn_attrs else user_id
                email_str = "-"
                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    emails = san.value.get_values_for_type(x509.RFC822Name)
                    if emails:
                        email_str = emails[0]
                except Exception:
                    pass
                users_list.append({"user_id": user_id, "common_name": cn, "email": email_str})
            except Exception:
                pass
    return users_list

@app.get("/api/v1/admin/roles-list")
async def admin_list_roles(
    admin_user: str = Query(...), 
    admin_pass: str = Query(...)
):
    verify_admin_privilege(admin_user, admin_pass)
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT username, role, is_active FROM admin_roles ORDER BY role DESC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/admin/update-user")
async def admin_update_user(
    user_id: str = Form(...),
    new_common_name: str = Form(...),
    new_email: str = Form(...),
    admin_user: str = Form(...),
    admin_pass: str = Form(...),
    new_password: str = Form(None)
):
    verify_admin_privilege(admin_user, admin_pass)
    cert_path = os.path.join(USER_STORAGE, f"{user_id}_cert.pem")
    key_path = os.path.join(USER_STORAGE, f"{user_id}_private.pem")
    root_key_path = os.path.join(CA_DIR, "root_private.pem")
    root_cert_path = os.path.join(CA_DIR, "root_cert.pem")
    
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="Thực thể mục tiêu không tồn tại.")
        
    try:
        if new_password and new_password.strip():
            private_key = ec.generate_private_key(ec.SECP256R1())
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(new_password.encode())
                ))
            pub_key = private_key.public_key()
            pass 
        else:
            with open(cert_path, "rb") as f:
                old_cert = x509.load_pem_x509_certificate(f.read())
            pub_key = old_cert.public_key()

        with open(root_key_path, "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(root_cert_path, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
            
        new_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CTUT"),
            x509.NameAttribute(NameOID.COMMON_NAME, new_common_name),
            x509.NameAttribute(NameOID.USER_ID, user_id)
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        new_cert = (
            x509.CertificateBuilder()
            .subject_name(new_subject)
            .issuer_name(root_cert.subject)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(new_email)]), critical=False)
            .sign(root_key, hashes.SHA256())
        )
        with open(cert_path, "wb") as f:
            f.write(new_cert.public_bytes(serialization.Encoding.PEM))
        return {"status": "success", "message": f"Hệ thống CA: Đã cập nhật hồ sơ và cấp chứng thư số mới cho tài khoản {user_id}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/user/update-profile")
async def user_update_profile(
    user_id: str = Form(...),
    current_password: str = Form(...),
    new_common_name: str = Form(None),
    new_password: str = Form(None)
):
    key_path = os.path.join(USER_STORAGE, f"{user_id}_private.pem")
    cert_path = os.path.join(USER_STORAGE, f"{user_id}_cert.pem")
    root_key_path = os.path.join(CA_DIR, "root_private.pem")
    root_cert_path = os.path.join(CA_DIR, "root_cert.pem")
    
    if not os.path.exists(key_path) or not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp hồ sơ mật mã thực thể.")
        
    try:
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=current_password.encode())
    except Exception:
        raise HTTPException(status_code=401, detail="Xác thực mật khẩu khóa Private hiện tại không chính xác.")
        
    try:
        if new_password and new_password.strip():
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(new_password.encode())
                ))
        
        with open(cert_path, "rb") as f:
            old_cert = x509.load_pem_x509_certificate(f.read())
            
        email_str = "-"
        try:
            san = old_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            emails = san.value.get_values_for_type(x509.RFC822Name)
            if emails: email_str = emails[0]
        except Exception: pass
        
        cn_attrs = old_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        final_cn = new_common_name if (new_common_name and new_common_name.strip()) else (cn_attrs[0].value if cn_attrs else user_id)
        
        with open(root_key_path, "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(root_cert_path, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
            
        new_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CTUT"),
            x509.NameAttribute(NameOID.COMMON_NAME, final_cn),
            x509.NameAttribute(NameOID.USER_ID, user_id)
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        new_cert = (
            x509.CertificateBuilder()
            .subject_name(new_subject)
            .issuer_name(root_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email_str)]), critical=False)
            .sign(root_key, hashes.SHA256())
        )
        with open(cert_path, "wb") as f:
            f.write(new_cert.public_bytes(serialization.Encoding.PEM))
            
        return {"status": "success", "message": "Đã tái mã hóa cấu trúc tệp khóa và ký cấp chứng thư mới thành công."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/user/logout")
async def user_logout(user_id: str = Form(...)):
    if user_id in _user_active_sessions:
        _user_active_sessions[user_id] = False
    return {"status": "success", "message": "Đã đăng xuất"}

@app.post("/api/v1/pdf/request-signing-otp")
async def request_signing_otp(user_id: str = Form(...), password: str = Form(...)):
    key_path = os.path.join(PROJECT_ROOT, "storage", "users", f"{user_id}_private.pem")
    if not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Tài khoản người dùng không tồn tại.")
    try:
        with open(key_path, "rb") as f:
            serialization.load_pem_private_key(f.read(), password=password.encode())
        try:
            # Khi đổi sang luồng 3 bước, xóa trạng thái OTP cũ để cấp mới sạch đệm
            # _user_active_sessions[user_id] = False |cmt dòng này

            AuthEngine.generate_otp(user_id)
            return {"status": "success", "message": "Mã OTP đã được gửi thành công qua Email công vụ."}
        except Exception as e:
            if "SANDBOX_MODE:" in str(e):
                otp_code = str(e).split("SANDBOX_MODE:")[1]
                return {
                    "status": "success", 
                    "message": f"⚠️ [Chế độ Thử nghiệm Hội đồng]: Do tường lửa Cloud Render chặn cổng Outbound SMTP (587/465) của gói Free, hệ thống kích hoạt chế độ giả lập an toàn. Mã OTP kích hoạt lượt ký số của bạn là: {otp_code}"
                }
            raise HTTPException(status_code=500, detail=str(e))
    except ValueError:
        raise HTTPException(status_code=401, detail="Sai mật khẩu xác thực khóa bí mật.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =========================================================================
# LUỒNG XÁC THỰC MÃ OTP BƯỚC 2: GHI NHẬ TRẠNG THÁI PHIÊN AN TOÀN (SESSION)
# =========================================================================
@app.post("/api/v1/pdf/verify-otp")
async def verify_otp_only(user_id: str = Form(...), otp: str = Form(...)):
    if not AuthEngine.verify_otp(user_id, otp):
        raise HTTPException(status_code=400, detail="Mã OTP số không chính xác hoặc đã quá chu kỳ hiệu lực.")
    
    # KÍCH HOẠT TOKEN PHIÊN: Đánh dấu Giảng viên đã vượt qua lớp phòng thủ 2FA thành công
    _user_active_sessions[user_id] = True
    return {"status": "success", "message": "Xác thực mã OTP thành công. Hệ thống đã mở khóa phân vùng tải tệp ở Bước 3."}

# =========================================================================
# LUỒNG TRỤC KÝ SỐ ĐỒNG LOẠT BƯỚC 3: DỰA TRÊN XÁC THỰC PHIÊN LÀM VIỆC (BATCH API)
# =========================================================================
@app.post("/api/v1/pdf/batch-sign")
async def sign_documents_in_batch(
    user_id: str = Form(...),
    password: str = Form(...),
    files: List[UploadFile] = File(...)
):
    # Kiểm tra OTP Session
    if _user_active_sessions.get(user_id) != True:
        raise HTTPException(
            status_code=403,
            detail="Yêu cầu từ chối. Phiên làm việc chưa hoàn tất xác thực OTP ở Bước 2."
        )

    if len(files) == 0:
        raise HTTPException(
            status_code=400,
            detail="Không có tệp PDF nào được gửi lên."
        )

    temp_dir = os.path.join(PROJECT_ROOT, "temp")
    os.makedirs(temp_dir, exist_ok=True)

    signed_paths = []

    def process_single_file(upload_file, raw_bytes):
        input_path = os.path.join(
            temp_dir,
            f"in_{uuid.uuid4().hex}_{upload_file.filename}"
        )

        output_name = f"signed_{upload_file.filename}"
        output_path = os.path.join(temp_dir, output_name)

        with open(input_path, "wb") as f:
            f.write(raw_bytes)

        PDFEngine.sign_pdf(
            user_id,
            password,
            input_path,
            output_path
        )

        return output_path

    try:
        for upload in files:
            data = await upload.read()
            signed_path = await run_in_threadpool(
                process_single_file,
                upload,
                data
            )
            signed_paths.append(signed_path)

        # Sau khi ký xong thì hủy session OTP
        # _user_active_sessions[user_id] = False

        # Trả về JSON danh sách tên file đã ký để frontend hiển thị bảng
        # chọn/tải từng file qua endpoint /api/v1/pdf/download/{filename}.
        # (Trước đây trả FileResponse zip nhị phân, nhưng script.js gọi
        # res.json() nên bị lỗi parse -> hiện nhầm là "mất kết nối API".)
        return {
            "status": "success",
            "filenames": [os.path.basename(p) for p in signed_paths]
        }

    except Exception as e:

        _user_active_sessions[user_id] = False

        raise HTTPException(
            status_code=400,
            detail=f"Lỗi ký số hàng loạt: {str(e)}"
        )

@app.get("/api/v1/pdf/download/{filename}")
async def download_file(filename: str):
    temp_dir = os.path.join(PROJECT_ROOT, "temp")
    possible_names = [filename, f"signed_{filename}", f"check_{filename}", f"signed_batch_{filename}"]
    for name in possible_names:
        path = os.path.join(temp_dir, name)
        if os.path.exists(path):
            return FileResponse(
                path, 
                media_type="application/pdf",
                headers={"Content-Disposition": f"inline; filename={name}"}
            )
    raise HTTPException(status_code=404, detail="Tệp văn bản không tồn tại trên hệ thống lưu trữ tạm.")

@app.post("/api/v1/pdf/download-batch-zip")
async def download_batch_zip(filenames: List[str] = Form(...)):
    """Nén nhiều file PDF đã ký (được chọn ở bảng kết quả Bước 3) thành 1 file ZIP để tải về 1 lần."""
    temp_dir = os.path.join(PROJECT_ROOT, "temp")
    temp_dir_abs = os.path.abspath(temp_dir)

    files_to_zip = []
    for raw_name in filenames:
        # Chỉ lấy tên file (basename) để chặn path traversal (vd: ../../app/main.py)
        safe_name = os.path.basename(raw_name)
        candidate_path = os.path.abspath(os.path.join(temp_dir, safe_name))
        if not candidate_path.startswith(temp_dir_abs + os.sep):
            continue
        if os.path.exists(candidate_path):
            files_to_zip.append((safe_name, candidate_path))

    if not files_to_zip:
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp hợp lệ nào để nén.")

    zip_name = f"signed_batch_zip_{uuid.uuid4().hex}.zip"
    zip_path = os.path.join(temp_dir, zip_name)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for arcname, path in files_to_zip:
            zipf.write(path, arcname=arcname)

    return FileResponse(
        path=zip_path,
        media_type="application/zip",
        filename="Signed_PDFs.zip"
    )

@app.post("/api/v1/pdf/verify")
async def verify_documents_batch(request: Request, files: List[UploadFile] = File(...)):
    if not files or len(files) == 0:
        raise HTTPException(status_code=400, detail="Không có tệp tin văn bản nào được gửi lên.")
        
    temp_dir = os.path.join(PROJECT_ROOT, "temp")
    os.makedirs(temp_dir, exist_ok=True)
    
    client_ip = request.client.host if request.client else "127.0.0.1"
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    results = []

    # Định nghĩa hàm xử lý nội bộ cho từng file để chạy bất đồng bộ qua threadpool
    def process_verification(filename, raw_bytes):
        file_path = os.path.join(temp_dir, f"verify_{uuid.uuid4().hex}_{filename}")
        with open(file_path, "wb") as f:
            f.write(raw_bytes)
            
        result_data = PDFEngine.verify_pdf(file_path)
        signer_str = result_data.get("signer", "-")
        
        if "error" in result_data:
            raw_err = result_data["error"]
            if "Không tìm thấy" in raw_err or "chưa được nhúng" in raw_err:
                status_code = "UNSIGNED"
                status_str = "Tài liệu thuần túy (Unsigned)"
                signer_str = "Chưa có chữ ký"
            else:
                status_code = "STRUCT_ERR"
                status_str = "Sai lệch cấu trúc mật mã"
                signer_str = "Không thể bóc tách"
        else:
            is_valid = result_data.get("valid", False)
            is_intact = result_data.get("intact", False)
            if is_valid and is_intact:
                status_code = "VALID"
                status_str = "Chữ ký hợp lệ - Toàn vẹn dữ liệu"
            elif is_valid and not is_intact:
                status_code = "ALTERED"
                status_str = "Cảnh báo: Toàn vẹn dữ liệu bị vi phạm"
            else:
                status_code = "INVALID"
                status_str = "Chữ ký không hợp lệ"
                
        # Ghi log bảo mật vào SQLite
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO verification_logs (timestamp, filename, status, signer, client_ip)
                    VALUES (?, ?, ?, ?, ?)
                """, (current_time, filename, status_str, signer_str, client_ip))
                conn.commit()
        except Exception:
            pass
            
        return {
            "filename": filename,
            "code": status_code,
            "status_text": status_str,
            "signer": signer_str
        }

    # Vòng lặp đọc và xử lý đồng loạt các file
    for upload in files:
        data = await upload.read()
        res = await run_in_threadpool(process_verification, upload.filename, data)
        results.append(res)
        
    return {"status": "success", "results": results}


@app.get("/api/v1/pdf/verify-history")
async def get_verification_history():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, filename, status, signer, client_ip 
                FROM verification_logs 
                WHERE filename != 'Hạ tầng hệ thống' 
                ORDER BY id DESC LIMIT 1000
            """)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)