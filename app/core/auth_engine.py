# # app/core/auth_engine.py
# import secrets
# import time
# import smtplib
# import os
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# from cryptography import x509
# from dotenv import load_dotenv

# load_dotenv()
# _otp_cache = {}

# class AuthEngine:
#     @staticmethod
#     def extract_email_from_cert(user_id: str) -> str:
#         cert_path = f"storage/users/{user_id}_cert.pem"
#         if not os.path.exists(cert_path):
#             raise FileNotFoundError("Thành viên chưa có chứng thư điện tử.")
            
#         with open(cert_path, "rb") as f:
#             cert = x509.load_pem_x509_certificate(f.read())
#         try:
#             san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
#             emails = san.value.get_values_for_type(x509.RFC822Name)
#             if emails:
#                 return emails[0]
#         except Exception:
#             pass
#         raise ValueError("Không tìm thấy cấu hình Email định danh trong chứng thư số.")

#     @staticmethod
#     def send_real_email(receiver_email: str, otp_code: str):
#         smtp_server = os.getenv("SMTP_SERVER")
#         smtp_port = int(os.getenv("SMTP_PORT", 587))
#         smtp_user = os.getenv("SMTP_USERNAME")
#         smtp_pass = os.getenv("SMTP_PASSWORD")

#         if not smtp_user or not smtp_pass:
#             raise ValueError("Chưa thiết lập biến môi trường tài khoản gửi mail trong file .env")

#         msg = MIMEMultipart()
#         msg['From'] = f"OTP - CTUT <{smtp_user}>"
#         msg['To'] = receiver_email
#         msg['Subject'] = f"[{otp_code}] Mã OTP xác thực giao dịch ký số từ xa"

#         body = f"""
#         <html>
#         <body style="font-family: Arial, sans-serif; color: #333;">
#             <div style="max-width: 550px; margin: 0 auto; padding: 20px; border: 1px solid #cbd5e0; border-radius: 6px;">
#                 <h3 style="color: #0f2d59; text-align: center;">HỆ THỐNG XÁC THỰC KÝ SỐ TẬP TRUNG CTUT</h3>
#                 <p>Hệ thống nhận được yêu cầu sử dụng khóa bí mật để thực hiện ký số văn bản từ tài khoản của bạn.</p>
#                 <div style="text-align: center; margin: 20px 0;">
#                     <span style="font-size: 24px; font-weight: bold; color: #e53e3e; background-color: #fff5f5; padding: 10px 20px; border: 1px dashed #e53e3e; letter-spacing: 2px;">
#                         {otp_code}
#                     </span>
#                 </div>
#                 <p>Mã OTP có hiệu lực trong <b>2 phút</b>. Tuyệt đối không chia sẻ mã này.</p>
#             </div>
#         </body>
#         </html>
#         """
#         msg.attach(MIMEText(body, 'html', 'utf-8'))

#         with smtplib.SMTP(smtp_server, smtp_port) as server:
#             server.starttls()
#             server.login(smtp_user, smtp_pass)
#             server.sendmail(smtp_user, receiver_email, msg.as_string())

#     @staticmethod
#     def generate_otp(user_id: str, expiry_seconds: int = 120) -> str:
#         otp_code = "".join(str(secrets.randbelow(10)) for _ in range(6))
#         receiver_email = AuthEngine.extract_email_from_cert(user_id)
        
#         AuthEngine.send_real_email(receiver_email, otp_code)
        
#         _otp_cache[user_id] = {
#             "otp": otp_code,
#             "expire_at": time.time() + expiry_seconds
#         }
#         return otp_code

#     @staticmethod
#     def verify_otp(user_id: str, input_otp: str) -> bool:
#         if user_id not in _otp_cache:
#             return False
#         cached_data = _otp_cache[user_id]
#         if time.time() > cached_data["expire_at"]:
#             del _otp_cache[user_id]
#             return False
#         if cached_data["otp"] == input_otp:
#             del _otp_cache[user_id]
#             return True
#         return False
# app/core/auth_engine.py
import secrets
import time
import os
import requests
from cryptography import x509
from dotenv import load_dotenv

load_dotenv()
_otp_cache = {}

# Endpoint gửi email giao dịch (transactional) của Brevo. Dùng HTTP API (cổng 443)
# thay vì SMTP (cổng 25/465/587) vì nhiều nền tảng hosting free tier (Render...)
# chặn hẳn các cổng SMTP để chống spam, nhưng không thể chặn cổng 443 (web traffic).
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

class AuthEngine:
    @staticmethod
    def extract_email_from_cert(user_id: str) -> str:
        cert_path = f"storage/users/{user_id}_cert.pem"
        if not os.path.exists(cert_path):
            raise FileNotFoundError("Thành viên chưa có chứng thư điện tử.")
            
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            emails = san.value.get_values_for_type(x509.RFC822Name)
            if emails:
                return emails[0]
        except Exception:
            pass
        raise ValueError("Không tìm thấy cấu hình Email định danh trong chứng thư số.")

    @staticmethod
    def send_real_email(receiver_email: str, otp_code: str):
        api_key = os.getenv("BREVO_API_KEY")
        sender_email = os.getenv("BREVO_SENDER_EMAIL")
        sender_name = os.getenv("BREVO_SENDER_NAME", "OTP - CTUT")

        if not api_key or not sender_email:
            raise ValueError(
                "Chưa thiết lập BREVO_API_KEY hoặc BREVO_SENDER_EMAIL trong file .env"
            )

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="max-width: 550px; margin: 0 auto; padding: 20px; border: 1px solid #cbd5e0; border-radius: 6px;">
                <h3 style="color: #0f2d59; text-align: center;">HỆ THỐNG XÁC THỰC KÝ SỐ TẬP TRUNG CTUT</h3>
                <p>Hệ thống nhận được yêu cầu sử dụng khóa bí mật để thực hiện ký số văn bản từ tài khoản của bạn.</p>
                <div style="text-align: center; margin: 20px 0;">
                    <span style="font-size: 24px; font-weight: bold; color: #e53e3e; background-color: #fff5f5; padding: 10px 20px; border: 1px dashed #e53e3e; letter-spacing: 2px;">
                        {otp_code}
                    </span>
                </div>
                <p>Mã OTP có hiệu lực trong <b>2 phút</b>. Tuyệt đối không chia sẻ mã này.</p>
            </div>
        </body>
        </html>
        """

        payload = {
            "sender": {"name": sender_name, "email": sender_email},
            "to": [{"email": receiver_email}],
            "subject": f"[{otp_code}] Mã OTP xác thực giao dịch ký số từ xa",
            "htmlContent": body,
        }
        headers = {
            "accept": "application/json",
            "api-key": api_key,
            "content-type": "application/json",
        }

        try:
            resp = requests.post(BREVO_API_URL, json=payload, headers=headers, timeout=15)
        except requests.RequestException as e:
            raise ValueError(f"Không thể kết nối đến dịch vụ gửi email Brevo: {str(e)}")

        # Brevo trả về 201 khi tạo/gửi email thành công. Bất kỳ mã nào khác đều
        # là lỗi (sai API key, sender chưa xác minh, vượt hạn mức free tier...).
        if resp.status_code != 201:
            raise ValueError(f"Gửi email qua Brevo thất bại (mã {resp.status_code}): {resp.text}")

    @staticmethod
    def generate_otp(user_id: str, expiry_seconds: int = 120) -> str:
        otp_code = "".join(str(secrets.randbelow(10)) for _ in range(6))
        receiver_email = AuthEngine.extract_email_from_cert(user_id)
        
        AuthEngine.send_real_email(receiver_email, otp_code)
        
        _otp_cache[user_id] = {
            "otp": otp_code,
            "expire_at": time.time() + expiry_seconds
        }
        return otp_code

    @staticmethod
    def verify_otp(user_id: str, input_otp: str) -> bool:
        if user_id not in _otp_cache:
            return False
        cached_data = _otp_cache[user_id]
        if time.time() > cached_data["expire_at"]:
            del _otp_cache[user_id]
            return False
        if cached_data["otp"] == input_otp:
            del _otp_cache[user_id]
            return True
        return False