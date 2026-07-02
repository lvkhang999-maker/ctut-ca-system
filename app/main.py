# app/main.py
import os
import sys
import sqlite3
import datetime
from fastapi import FastAPI, HTTPException, Form, UploadFile, File, Request, Query
from fastapi.responses import HTMLResponse, FileResponse
from contextlib import asynccontextmanager
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

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

def init_audit_db():
    os.makedirs(DB_DIR, exist_ok=True)
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
            
        cursor.execute("INSERT OR IGNORE INTO admin_roles VALUES ('superadmin', 'ctut@2026', 'SUPER_ADMIN', 1)")
        cursor.execute("INSERT OR IGNORE INTO admin_roles VALUES ('admincds', '123456', 'ADMIN', 1)")
        conn.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_audit_db()
    yield

app = FastAPI(
    title="Hệ thống Hạ tầng Chữ ký số nội bộ CTUT", 
    description="Sản phẩm Nghiên cứu Khoa học - Trung tâm Chuyển đổi số trường ĐH KT-CN Cần Thơ",
    version="2.6.5",
    lifespan=lifespan
)

def verify_admin_privilege(username, password, required_role=None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin_roles WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=403, detail="Sai thông tin tài khoản hoặc mật khẩu quản trị.")
        if user["is_active"] == 0:
            raise HTTPException(status_code=403, detail="Tài khoản quản trị này đã bị vô hiệu hóa quyền truy cập.")
        if required_role == "SUPER_ADMIN" and user["role"] != "SUPER_ADMIN":
            raise HTTPException(status_code=403, detail="Thao tác thất bại. Tính năng này yêu cầu đặc quyền Super Admin.")
        return user["role"]

# =========================================================================
# TRỤC ĐIỀU PHỐI API GATEWAY CHUẨN HÓA QUERY PARAMETERS
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
        
        status_txt = "VÔ HIỆ HÓA" if new_status == 0 else "KÍCH HOẠT LẠI"
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
            
            cursor.execute("""
                INSERT INTO admin_roles (username, password, role, is_active) VALUES (?, ?, ?, 1)
                ON CONFLICT(username) DO UPDATE SET password=excluded.password, role=excluded.role
            """, (target_user, target_pass, assigned_role))
            conn.commit()
        return {"status": "success", "message": f"Đã phê duyệt cấp đặc quyền {assigned_role} thành công cho tài khoản '{target_user}'."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# FIXED: Ép kiểu dữ liệu Query tường minh cho API Lịch sử Audit hệ thống
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

# FIXED: Ép kiểu dữ liệu Query tường minh cho API Danh sách Giảng viên
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

# FIXED: Ép kiểu dữ liệu Query tường minh cho API Danh sách Ban Quản Trị
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
    admin_pass: str = Form(...)
):
    verify_admin_privilege(admin_user, admin_pass)
    cert_path = os.path.join(USER_STORAGE, f"{user_id}_cert.pem")
    root_key_path = os.path.join(PROJECT_ROOT, "storage", "ca", "root_private.pem")
    root_cert_path = os.path.join(PROJECT_ROOT, "storage", "ca", "root_cert.pem")
    
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="Thực thể mục tiêu không tồn tại.")
        
    try:
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
            
        return {"status": "success", "message": f"Hệ thống: Đã cập nhật và tái ký chứng thư thành công cho tài khoản {user_id}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/pdf/request-signing-otp")
async def request_signing_otp(user_id: str = Form(...), password: str = Form(...)):
    key_path = os.path.join(PROJECT_ROOT, "storage", "users", f"{user_id}_private.pem")
    if not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Tài khoản người dùng không tồn tại.")
    try:
        with open(key_path, "rb") as f:
            serialization.load_pem_private_key(f.read(), password=password.encode())
        AuthEngine.generate_otp(user_id)
        return {"status": "success", "message": "Mã OTP đã được gửi thành công."}
    except ValueError:
        raise HTTPException(status_code=401, detail="Sai mật khẩu xác thực khóa bí mật.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/pdf/sign-with-otp")
async def sign_document_with_otp(user_id: str = Form(...), password: str = Form(...), otp: str = Form(...), file: UploadFile = File(...)):
    if not AuthEngine.verify_otp(user_id, otp):
        raise HTTPException(status_code=400, detail="Mã OTP sai hoặc đã hết hạn.")
        
    temp_dir = os.path.join(PROJECT_ROOT, "temp")
    os.makedirs(temp_dir, exist_ok=True)
    input_path = os.path.join(temp_dir, f"in_{file.filename}")
    output_filename = f"signed_{file.filename}"
    output_path = os.path.join(temp_dir, output_filename)
    
    with open(input_path, "wb") as f:
        f.write(await file.read())
        
    try:
        PDFEngine.sign_pdf(user_id, password, input_path, output_path)
        return {"status": "success", "filename": output_filename, "message": "Ký số văn bản hoàn tất."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/pdf/download/{filename}")
async def download_file(filename: str):
    file_path = os.path.join(PROJECT_ROOT, "temp", filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Tệp văn bản không tồn tại.")
    return FileResponse(file_path, media_type="application/pdf", filename=filename)

@app.post("/api/v1/pdf/verify")
async def verify_document(request: Request, file: UploadFile = File(...)):
    temp_dir = os.path.join(PROJECT_ROOT, "temp")
    os.makedirs(temp_dir, exist_ok=True)
    file_path = os.path.join(temp_dir, f"check_{file.filename}")
    
    with open(file_path, "wb") as f:
        f.write(await file.read())
        
    result_data = PDFEngine.verify_pdf(file_path)
    signer_str = result_data.get("signer", "-")
    
    if "error" in result_data:
        if "Không tìm thấy" in result_data["error"] or "chưa được nhúng" in result_data["error"]:
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

    client_ip = request.client.host if request.client else "127.0.0.1"
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO verification_logs (timestamp, filename, status, signer, client_ip)
                VALUES (?, ?, ?, ?, ?)
            """, (current_time, file.filename, status_str, signer_str, client_ip))
            conn.commit()
    except Exception:
        pass
        
    return {
        "status": "success", "code": status_code, "status_text": status_str,
        "result": {"signer": signer_str, "summary": status_str}
    }

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