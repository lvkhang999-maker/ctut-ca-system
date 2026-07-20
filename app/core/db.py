# app/core/db.py

import os
from contextlib import contextmanager
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, func, LargeBinary
)
from sqlalchemy.orm import declarative_base, sessionmaker

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
DB_DIR = os.path.join(PROJECT_ROOT, "storage", "db")

_raw_database_url = os.environ.get("DATABASE_URL", "").strip()

if _raw_database_url:
    # Render/Railway thường cấp URL dạng "postgres://..." (kiểu cũ), nhưng
    # SQLAlchemy + psycopg2 yêu cầu "postgresql://...". Tự động chuẩn hoá lại.
    if _raw_database_url.startswith("postgres://"):
        _raw_database_url = _raw_database_url.replace(
            "postgres://", "postgresql://", 1
        )
    DATABASE_URL = _raw_database_url
    IS_SQLITE = False
else:
    os.makedirs(DB_DIR, exist_ok=True)
    DATABASE_URL = f"sqlite:///{os.path.join(DB_DIR, 'audit_logs.db')}"
    IS_SQLITE = True

_engine_kwargs = {}
if IS_SQLITE:
    # Cần thiết cho SQLite khi dùng chung 1 connection giữa nhiều thread (FastAPI
    # threadpool trong main.py chạy sign_pdf/verify_pdf trên các thread khác nhau).
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # pool_pre_ping tránh lỗi "server closed the connection unexpectedly" khi
    # Postgres free tier ngắt kết nối rảnh (idle) sau một khoảng thời gian.
    _engine_kwargs["pool_pre_ping"] = True

engine = create_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


# ============================= MODELS =============================

class AdminRole(Base):
    __tablename__ = "admin_roles"

    username = Column(String, primary_key=True)
    password = Column(String, nullable=False)  # đã băm bcrypt, không lưu plaintext
    role = Column(String, nullable=False)       # "SUPER_ADMIN" | "ADMIN"
    is_active = Column(Integer, default=1)


class VerificationLog(Base):
    """Lưu kết quả THẨM ĐỊNH văn bản (Bước xác thực công khai), và cũng được
    dùng lại để ghi Nhật ký hạ tầng cho các thao tác quản trị (giữ đúng hành vi
    cũ: filename = 'Hạ tầng hệ thống' cho các dòng audit quản trị)."""
    __tablename__ = "verification_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String)
    filename = Column(String)
    status = Column(String)
    signer = Column(String)
    client_ip = Column(String)


class SigningLog(Base):
    """Lưu lịch sử KÝ SỐ (khác với lịch sử thẩm định ở trên)."""
    __tablename__ = "signing_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String)
    filename = Column(String)          # tên file gốc được ký
    user_id = Column(String)           # tài khoản đăng nhập thực hiện ký
    signer_name = Column(String)       # Common Name lấy từ chứng thư số
    status = Column(String)            # "SUCCESS" | "FAILED"
    detail = Column(String)            # thông báo lỗi nếu FAILED, hoặc ghi chú
    client_ip = Column(String)


def init_db():
    """Tạo toàn bộ bảng nếu chưa tồn tại (idempotent, an toàn gọi lại nhiều lần)."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_session():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

class ActiveOtpSession(Base):
    """Đánh dấu tài khoản giảng viên đã vượt qua xác thực OTP (Bước 2), được phép
    ký ở Bước 3. Trước đây lưu bằng 1 dict Python thuần trong RAM
    (_user_active_sessions) - bị XÓA SẠCH mỗi khi Render restart/sleep-wake gói
    Free (thường sau ~15 phút không có request), khiến người dùng đang ở Bước 3
    (đã qua OTP) đột nhiên bị từ chối ký với lỗi 'chưa xác thực OTP' dù họ chưa
    hề đăng xuất. Chuyển sang PostgreSQL để phiên sống sót qua mọi lần restart."""
    __tablename__ = "active_otp_sessions"

    user_id = Column(String, primary_key=True)
    verified_at = Column(String)


class TeacherStatus(Base):
    """Trạng thái kích hoạt/vô hiệu hóa của tài khoản Giảng viên (tách riêng khỏi
    AdminRole vì giảng viên không có bản ghi DB nào từ trước - danh sách giảng
    viên trước giờ chỉ được liệt kê bằng cách quét file chứng thư trên đĩa)."""
    __tablename__ = "teacher_status"

    user_id = Column(String, primary_key=True)
    is_active = Column(Integer, default=1)


class FileStorage(Base):
    __tablename__ = "file_storage"
    # Lưu đường dẫn tương đối, ví dụ: storage/users/admin_cert.pem
    file_path = Column(String, primary_key=True) 
    # Lưu nội dung file dưới dạng nhị phân (BYTEA trong PostgreSQL)
    file_data = Column(LargeBinary, nullable=False)