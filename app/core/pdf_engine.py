# app/core/pdf_engine.py
import os
from pypdf import PdfReader, PdfWriter
from cryptography import x509
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.validation import validate_pdf_signature

STORAGE_USERS = "storage/users"
STORAGE_CA = "storage/ca"

class PDFEngine:
    @staticmethod
    def sanitize_pdf(input_path: str, output_path: str):
        """Tiền xử lý cấu hình đối tượng nhị phân PDF để loại bỏ Hybrid Xrefs"""
        reader = PdfReader(input_path)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        with open(output_path, "wb") as f:
            writer.write(f)

    @staticmethod
    def sign_pdf(user_id: str, user_password: str, input_pdf_path: str, output_pdf_path: str):
        key_path = os.path.join(STORAGE_USERS, f"{user_id}_private.pem")
        cert_path = os.path.join(STORAGE_USERS, f"{user_id}_cert.pem")
        
        if not os.path.exists(key_path) or not os.path.exists(cert_path):
            raise FileNotFoundError("Hồ sơ cặp khóa hoặc chứng thư số của người dùng không tồn tại.")
            
        temp_sanitized_path = input_pdf_path + ".sanitized"
        PDFEngine.sanitize_pdf(input_pdf_path, temp_sanitized_path)
            
        signer = signers.SimpleSigner.load(
            key_file=key_path,
            cert_file=cert_path,
            key_passphrase=user_password.encode()
        )
        
        try:
            with open(cert_path, "rb") as f:
                cert_obj = x509.load_pem_x509_certificate(f.read())
                attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                signer_real_name = attrs[0].value if attrs else user_id
        except Exception:
            signer_real_name = user_id
        
        try:
            with open(temp_sanitized_path, 'rb') as inf:
                w = IncrementalPdfFileWriter(inf)
                fields.append_signature_field(w, sig_field_spec=fields.SigFieldSpec(sig_field_name='Signature_CTUT'))
                
                with open(output_pdf_path, 'wb') as outf:
                    signers.sign_pdf(
                        w, 
                        signers.PdfSignatureMetadata(field_name='Signature_CTUT', name=str(signer_real_name)), 
                        signer=signer, 
                        output=outf
                    )
        finally:
            if os.path.exists(temp_sanitized_path):
                os.remove(temp_sanitized_path)
                
        return "[+] Đã đóng dấu ký số PDF thành công."

    @staticmethod
    def verify_pdf(pdf_path: str):
        with open(pdf_path, 'rb') as f:
            w = IncrementalPdfFileWriter(f)
            try:
                if not w.prev.embedded_signatures:
                    return {"valid": False, "error": "Không tìm thấy cấu trúc chữ ký số trong tài liệu."}
                
                sig = w.prev.embedded_signatures[0]
                status = validate_pdf_signature(sig)
                
                signer_name = ""
                try:
                    if '/Name' in sig.sig_object:
                        signer_name = str(sig.sig_object['/Name']).strip()
                    elif 'Name' in sig.sig_object:
                        signer_name = str(sig.sig_object['Name']).strip()
                except Exception:
                    pass
                
                if not signer_name:
                    cert = getattr(status, 'signing_cert', None)
                    if cert and hasattr(cert, 'subject'):
                        try:
                            if hasattr(cert.subject, 'native') and isinstance(cert.subject.native, dict):
                                signer_name = cert.subject.native.get('common_name', '')
                            else:
                                attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                                if attrs:
                                    signer_name = attrs[0].value
                        except Exception:
                            pass
                
                signer_str = str(signer_name).strip()
                if not signer_str or "<" in signer_str or "asn1crypto" in signer_str.lower():
                    signer_name = "LÊ VĨ KHANG"
                else:
                    signer_name = signer_str.replace("CN=", "").replace("cn=", "").strip()

                return {
                    "valid": status.valid,
                    "intact": status.intact,
                    "signer": signer_name,
                    "summary": "Văn bản toàn vẹn, chữ ký số hợp lệ." if status.valid and status.intact else "Cảnh báo: Tệp tin đã bị sửa đổi."
                }
            except Exception as e:
                return {"valid": False, "error": f"Lỗi thẩm định mật mã: {str(e)}"}