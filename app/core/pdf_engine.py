import os
import datetime
from zoneinfo import ZoneInfo
import uuid
import inspect
from cryptography import x509
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, AxisAlignment, Margins
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory
from pyhanko.sign import fields, signers
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.validation import validate_pdf_signature
from pypdf import PdfReader, PdfWriter

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
STORAGE_USERS = os.path.join(PROJECT_ROOT, "storage", "users")

# Đường dẫn logo dùng làm nền con dấu ký thay cho icon mặc định của pyhanko.
LOGO_PATH = os.path.join(PROJECT_ROOT, "app", "static", "images", "logo_ctut.png")

# Font TTF hỗ trợ Unicode đầy đủ (tiếng Việt có dấu). Font mặc định của pyhanko
# (Type1/Helvetica) KHÔNG hỗ trợ ký tự có dấu -> gây lỗi hiển thị kiểu "þÿ K ý b ß i".
FONT_PATH = os.path.join(PROJECT_ROOT, "app", "static", "fonts", "NotoSans-Italic-VariableFont_wdth,wght.ttf")

# ==== Cấu hình vị trí & hình thức khung ký (dễ chỉnh sau này) ====
STAMP_MARGIN_TOP = 18      # khoảng cách từ mép TRÊN trang xuống khung ký (points)
STAMP_MARGIN_LEFT = 18     # khoảng cách từ mép TRÁI trang (points)
STAMP_WIDTH = 170          # thu nhỏ chiều rộng khung ký (trước đây 230)
STAMP_HEIGHT = 55
STAMP_GAP_BETWEEN_SIGS = 62   # khoảng hạ xuống cho mỗi chữ ký kế tiếp trên cùng 1 văn bản
STAMP_BORDER_COLOR = (0, 0, 0)  # màu viền khung ký: ĐEN (trước đây xanh lá pastel)
STAMP_BORDER_WIDTH = 1.2

_TEXTSTAMPSTYLE_PARAMS = set(inspect.signature(TextStampStyle.__init__).parameters)

def _build_stamp_style(**kwargs):
    """Tạo TextStampStyle, tự động lược bỏ các tham số mà phiên bản pyhanko
    hiện tại không hỗ trợ (vd: border_color trên bản cũ) để tránh crash."""
    supported_kwargs = {k: v for k, v in kwargs.items() if k in _TEXTSTAMPSTYLE_PARAMS}
    return TextStampStyle(**supported_kwargs)

class PDFEngine:
    @staticmethod
    def sanitize_pdf(input_path: str, output_path: str):
        """Tiền xử lý file: CHỈ ÁP DỤNG KHI FILE CHƯA TỪNG BỊ KÝ"""
        reader = PdfReader(input_path)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        with open(output_path, "wb") as f:
            writer.write(f)

    @staticmethod
    def sign_pdf(user_id: str, user_password: str, input_pdf_path: str, output_pdf_path: str,
                 stamp_ratio_x: float = None, stamp_ratio_y: float = None, stamp_page_index: int = 0,
                 stamp_width_pt: float = None, stamp_height_pt: float = None):
        # Kích thước khung ký: dùng giá trị người dùng kéo-giãn ở giao diện nếu có,
        # kẹp trong khoảng hợp lý để tránh giá trị bất thường (âm, quá nhỏ/quá to)
        # từ request bị thao túng. Nếu không truyền, giữ nguyên mặc định cũ.
        effective_width = STAMP_WIDTH
        effective_height = STAMP_HEIGHT
        if stamp_width_pt is not None and stamp_width_pt > 0:
            effective_width = max(60, min(stamp_width_pt, 400))
        if stamp_height_pt is not None and stamp_height_pt > 0:
            effective_height = max(30, min(stamp_height_pt, 200))

        key_path = os.path.join(STORAGE_USERS, f"{user_id}_private.pem")
        cert_path = os.path.join(STORAGE_USERS, f"{user_id}_cert.pem")
        
        if not os.path.exists(key_path) or not os.path.exists(cert_path):
            raise FileNotFoundError("Không tìm thấy chứng thư số hoặc khóa bí mật.")
            
        # 1. Đếm số lượng chữ ký hiện có để quyết định tọa độ Offset và bảo vệ toàn vẹn
        sig_count = 0
        detection_failed = False
        try:
            with open(input_pdf_path, 'rb') as inf:
                reader = PdfFileReader(inf)
                sig_count = len(reader.embedded_signatures)
        except Exception:
            detection_failed = True
        if sig_count == 0 and not detection_failed:
            target_input_path = input_pdf_path + ".sanitized"
            PDFEngine.sanitize_pdf(input_pdf_path, target_input_path)
            must_clean = True
        else:
            target_input_path = input_pdf_path
            must_clean = False
            
        # 3. Nạp hồ sơ Khóa bất đối xứng
        signer_obj = signers.SimpleSigner.load(
            key_file=key_path, cert_file=cert_path, key_passphrase=user_password.encode()
        )
        
        try:
            with open(cert_path, "rb") as f:
                cert_obj = x509.load_pem_x509_certificate(f.read())
                name_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                signer_real_name = name_attrs[0].value if name_attrs else user_id
                title_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.TITLE)
                if not title_attrs:
                    title_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
                signer_title = title_attrs[0].value if title_attrs else ""
        except Exception:
            signer_real_name = user_id
            signer_title = ""
        try:
            with open(target_input_path, 'rb') as inf:
                w = IncrementalPdfFileWriter(inf)

                # Tạo Định danh Field ID độc nhất tránh xung đột các lớp chữ ký
                unique_sig_id = f"Signature_CTUT_{user_id}_{uuid.uuid4().hex[:6]}"

                pages_kids = w.root['/Pages']['/Kids']
                safe_page_index = max(0, min(stamp_page_index or 0, len(pages_kids) - 1))
                target_page = pages_kids[safe_page_index].get_object()
                media_box = target_page['/MediaBox']
                page_width = float(media_box[2]) - float(media_box[0])
                page_height = float(media_box[3]) - float(media_box[1])
                offset = sig_count * STAMP_GAP_BETWEEN_SIGS
                if stamp_ratio_x is not None and stamp_ratio_y is not None:
                    box_x1 = stamp_ratio_x * page_width
                    box_y2 = page_height - (stamp_ratio_y * page_height) - offset
                    box_y1 = box_y2 - effective_height
                    box_x2 = box_x1 + effective_width

                    box_x1 = max(0, min(box_x1, page_width - effective_width))
                    box_x2 = box_x1 + effective_width
                else:
                    box_y2 = page_height - STAMP_MARGIN_TOP - offset
                    box_y1 = box_y2 - effective_height
                    box_x1 = STAMP_MARGIN_LEFT
                    box_x2 = STAMP_MARGIN_LEFT + effective_width

                stamping_box = (box_x1, max(10, box_y1), box_x2, max(10 + effective_height, box_y2))

                vn_tz = ZoneInfo("Asia/Ho_Chi_Minh")
                current_time_str = datetime.datetime.now(vn_tz).strftime("%d-%m-%Y %H:%M:%S")

                stamp_lines = [f"Ký bởi: {signer_real_name}"]
                if signer_title:
                    stamp_lines.append(f"Chức vụ: {signer_title}")
                stamp_lines.append(f"Thời gian: {current_time_str}")
                stamp_text = "\n".join(stamp_lines)

                user_signature_path = os.path.join(STORAGE_USERS, f"{user_id}_signature.png")
                if os.path.exists(user_signature_path):
                    background_image = PdfImage(user_signature_path)
                elif os.path.exists(LOGO_PATH):
                    background_image = PdfImage(LOGO_PATH)
                else:
                    background_image = None
                text_box_style = (
                    TextBoxStyle(font=GlyphAccumulatorFactory(FONT_PATH), font_size=6)
                    if os.path.exists(FONT_PATH) else TextBoxStyle(font_size=6)
                )

                stamp_style = _build_stamp_style(
                    stamp_text=stamp_text,
                    background=background_image,
                    # Trước đây ảnh nền canh GIỮA khung (ALIGN_MID) nên đè thẳng lên
                    # khối chữ "Ký bởi/Thời gian" đặt ở góc phải-dưới -> rối mắt, mờ.
                    # Giờ dịch ảnh sang góc TRÁI (ALIGN_MIN) để 2 vùng tách biệt nhau,
                    # không còn chồng lấn với khối chữ.
                    background_layout=SimpleBoxLayoutRule(
                        x_align=AxisAlignment.ALIGN_MIN,
                        y_align=AxisAlignment.ALIGN_MID,
                        margins=Margins(left=3, right=0, top=2, bottom=2),
                    ),
                    # Đây là ảnh CHỮ KÝ THẬT của người dùng (không còn là logo mờ kiểu
                    # watermark như trước), nên cần hiển thị rõ hẳn thay vì mờ ảo 0.22.
                    background_opacity=0.95,
                    text_box_style=text_box_style,
                    inner_content_layout=SimpleBoxLayoutRule(
                        x_align=AxisAlignment.ALIGN_MAX,
                        y_align=AxisAlignment.ALIGN_MIN,
                        margins=Margins(left=2, right=4, top=2, bottom=3),
                    ),
                    border_width=STAMP_BORDER_WIDTH,
                    border_color=STAMP_BORDER_COLOR,
                )

                fields.append_signature_field(
                    w, sig_field_spec=fields.SigFieldSpec(
                        sig_field_name=unique_sig_id, 
                        on_page=safe_page_index,
                        box=stamping_box
                    )
                )

                pdf_signer = signers.PdfSigner(
                    signers.PdfSignatureMetadata(field_name=unique_sig_id),
                    signer=signer_obj,
                    stamp_style=stamp_style,
                )

                with open(output_pdf_path, 'wb') as outf:
                    pdf_signer.sign_pdf(w, output=outf)
        finally:
            if must_clean and os.path.exists(target_input_path):
                os.remove(target_input_path)

    @staticmethod
    def verify_pdf(pdf_path: str):
        with open(pdf_path, 'rb') as f:
            try:
                w = IncrementalPdfFileWriter(f)
                if not w.prev.embedded_signatures:
                    return {"valid": False, "error": "Chưa có chữ ký."}
                
                verification_stack = []
                for sig in w.prev.embedded_signatures:
                    status = validate_pdf_signature(sig)
                    
                    signer_name = ""
                    cert = getattr(status, 'signing_cert', None)
                    if cert is not None and hasattr(cert, 'subject'):
                        # QUAN TRỌNG: pyhanko trả về chứng thư dạng asn1crypto.x509.Certificate,
                        # KHÁC với cryptography.x509.Certificate. Object này không có method
                        # get_attributes_for_oid() (chỉ cryptography.x509 mới có), nên gọi vào
                        # sẽ luôn raise AttributeError, bị "except Exception: pass" nuốt mất và
                        # khiến signer_name luôn rỗng -> hiển thị nhầm mặc định "Hệ thống CTUT".
                        # asn1crypto đọc Common Name qua .subject.native["common_name"].
                        try:
                            native_subject = cert.subject.native
                            signer_name = native_subject.get("common_name", "") or ""
                        except Exception:
                            pass
                        # Dự phòng: nếu vì lý do nào đó cert lại là cryptography.x509.Certificate
                        # (ví dụ đổi phiên bản pyhanko sau này), vẫn thử cách cũ.
                        if not signer_name and hasattr(cert.subject, "get_attributes_for_oid"):
                            try:
                                attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                                if attrs: signer_name = attrs[0].value
                            except Exception: pass
                    
                    signer_str = str(signer_name).strip()
                    signer_name = signer_str if signer_str else "Hệ thống CTUT"
                        
                    verification_stack.append({
                        "valid": status.valid,
                        "intact": status.intact,
                        "signer": signer_name
                    })
                
                all_valid = all(v["valid"] for v in verification_stack)
                all_intact = all(v["intact"] for v in verification_stack)
                signer_names = [v["signer"] for v in verification_stack]
                # Hiển thị tối đa 2 tên/dòng để tránh chuỗi ký quá dài bị tràn giao diện.
                # Trong 1 dòng nối 2 tên bằng "->"; giữa các dòng ngắt bằng <br> (chuỗi
                # này được frontend chèn thẳng vào innerHTML nên <br> sẽ xuống dòng thật).
                signer_lines = [
                    "->".join(signer_names[i:i + 2])
                    for i in range(0, len(signer_names), 2)
                ]
                signers_chain = "<br>".join(signer_lines)
                
                summary_txt = f"Văn bản toàn vẹn. Chuỗi xác thực: {signers_chain}" if (all_valid and all_intact) else "Cảnh báo: Tệp tin bị chỉnh sửa."
                    
                return {
                    "valid": all_valid,
                    "intact": all_intact,
                    "signer": signers_chain,
                    "summary": summary_txt
                }
            except Exception as e:
                return {"valid": False, "error": f"Lỗi: {str(e)}"}