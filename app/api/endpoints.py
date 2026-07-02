# # app/api/endpoints.py
# from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request
# from fastapi.responses import FileResponse
# from app.core.pki_engine import PKIEngine
# from app.core.pdf_engine import PDFEngine
# from app.core.auth_engine import AuthEngine
# from cryptography.hazmat.primitives import serialization
# import os
# import sqlite3
# import datetime

# router = APIRouter()

# CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) # app/api
# # VÁ LỖI ĐƯỜNG DẪN: Ép lùi cấu trúc 2 tầng để trỏ thẳng về gốc 'ctut-ca-system'
# PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..")) 

# DB_DIR = os.path.join(PROJECT_ROOT, "storage", "db")
# DB_PATH = os.path.join(DB_DIR, "audit_logs.db")

# def init_audit_db():
#     """Hàm khởi tạo cơ sở dữ liệu nhật ký thẩm định nằm ngoài thư mục app"""
#     os.makedirs(DB_DIR, exist_ok=True)
#     with sqlite3.connect(DB_PATH) as conn:
#         cursor = conn.cursor()
#         conn.execute("PRAGMA journal_mode=DELETE;") # Dùng chế độ DELETE truyền thống bảo vệ luồng Windows
#         cursor.execute("""
#             CREATE TABLE IF NOT EXISTS verification_logs (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 timestamp TEXT,
#                 filename TEXT,
#                 status TEXT,
#                 signer TEXT,
#                 client_ip TEXT
#             )
#         """)
#         conn.commit()

# @router.post("/pki/init")
# def init_ca():
#     return {"status": "success", "message": PKIEngine.init_root_ca()}

# @router.post("/user/register")
# def register_user(
#     user_id: str = Form(...), 
#     password: str = Form(...), 
#     common_name: str = Form(...), 
#     email: str = Form(...),
#     admin_user: str = Form(...),
#     admin_pass: str = Form(...)
# ):
#     if admin_user != "admincds" or admin_pass != "123456":
#         raise HTTPException(status_code=403, detail="Truy cập bị từ chối. Bạn không có quyền cấp phát chứng thư số.")
#     try:
#         msg = PKIEngine.issue_user_certificate(user_id, password, common_name, email)
#         return {"status": "success", "message": msg}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @router.post("/pdf/request-signing-otp")
# def request_signing_otp(user_id: str = Form(...), password: str = Form(...)):
#     key_path = os.path.join(PROJECT_ROOT, "storage", "users", f"{user_id}_private.pem")
#     if not os.path.exists(key_path):
#         raise HTTPException(status_code=404, detail="Tài khoản người dùng không tồn tại trên hệ thống CA.")
#     try:
#         with open(key_path, "rb") as f:
#             serialization.load_pem_private_key(f.read(), password=password.encode())
#         AuthEngine.generate_otp(user_id)
#         return {"status": "success", "message": "Mã OTP đã được gửi đến thiết bị cá nhân của bạn."}
#     except ValueError:
#         raise HTTPException(status_code=401, detail="Sai mật khẩu xác thực khóa bí mật.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @router.post("/pdf/sign-with-otp")
# async def sign_document_with_otp(user_id: str = Form(...), password: str = Form(...), otp: str = Form(...), file: UploadFile = File(...)):
#     if not AuthEngine.verify_otp(user_id, otp):
#         raise HTTPException(status_code=400, detail="Mã OTP sai hoặc đã hết hạn.")
        
#     temp_dir = os.path.join(PROJECT_ROOT, "temp")
#     os.makedirs(temp_dir, exist_ok=True)
#     input_path = os.path.join(temp_dir, f"in_{file.filename}")
#     output_filename = f"signed_{file.filename}"
#     output_path = os.path.join(temp_dir, output_filename)
    
#     with open(input_path, "wb") as f:
#         f.write(await file.read())
        
#     try:
#         PDFEngine.sign_pdf(user_id, password, input_path, output_path)
#         return {"status": "success", "filename": output_filename, "message": "Ký số văn bản hoàn tất."}
#     except Exception as e:
#         raise HTTPException(status_code=400, detail=str(e))

# @router.get("/pdf/download/{filename}")
# def download_file(filename: str):
#     file_path = os.path.join(PROJECT_ROOT, "temp", filename)
#     if not os.path.exists(file_path):
#         raise HTTPException(status_code=404, detail="Tệp văn bản không tồn tại trên hệ thống máy chủ.")
#     return FileResponse(file_path, media_type="application/pdf", filename=filename)

# @router.post("/pdf/verify")
# async def verify_document(request: Request, file: UploadFile = File(...)):
#     temp_dir = os.path.join(PROJECT_ROOT, "temp")
#     os.makedirs(temp_dir, exist_ok=True)
#     file_path = os.path.join(temp_dir, f"check_{file.filename}")
    
#     with open(file_path, "wb") as f:
#         f.write(await file.read())
        
#     result_data = PDFEngine.verify_pdf(file_path)
    
#     status_str = "HỢP LỆ" if result_data.get("valid") else "BỊ CHỈNH SỬA"
#     signer_str = result_data.get("signer", "Không rõ danh tính")
    
#     client_ip = request.client.host if request.client else "127.0.0.1"
#     current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
#     try:
#         with sqlite3.connect(DB_PATH) as conn:
#             cursor = conn.cursor()
#             cursor.execute("""
#                 INSERT INTO verification_logs (timestamp, filename, status, signer, client_ip)
#                 VALUES (?, ?, ?, ?, ?)
#             """, (current_time, file.filename, status_str, signer_str, client_ip))
#             conn.commit()
#     except Exception:
#         pass
        
#     return {"status": "success", "result": result_data}

# @router.get("/pdf/verify-history")
# def get_verification_history():
#     try:
#         with sqlite3.connect(DB_PATH) as conn:
#             conn.row_factory = sqlite3.Row
#             cursor = conn.cursor()
#             cursor.execute("""
#                 SELECT timestamp, filename, status, signer, client_ip 
#                 FROM verification_logs 
#                 ORDER BY id DESC LIMIT 15
#             """)
#             rows = cursor.fetchall()
#             return [dict(row) for row in rows]
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))