// app.js
const API_BASE = "/api/v1";

document.addEventListener("DOMContentLoaded", () => {
    const tabButtons = document.querySelectorAll('#pkiTabs button');
    tabButtons.forEach(button => {
        button.addEventListener('click', function (e) {
            e.preventDefault();
            const tabTrigger = new bootstrap.Tab(this);
            tabTrigger.show();

            if (this.id === 'verify-tab') {
                loadVerifyHistory();
            } else if (this.id === 'admin-tab') {
                resetAdminView();
            }
        });
    });

    document.querySelectorAll('.btn-eye-toggle').forEach(btn => {
        btn.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const input = document.getElementById(targetId);
            const icon = this.querySelector('i');
            if (input.type === "password") {
                input.type = "text";
                icon.className = "fa-solid fa-eye-slash";
            } else {
                input.type = "password";
                icon.className = "fa-solid fa-eye";
            }
        });
    });
});

function showResult(divId, type, message) {
    const div = document.getElementById(divId);
    div.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show fw-bold shadow-sm rounded-3 m-0" role="alert">
            <i class="fa-solid ${type === 'success' ? 'fa-circle-check' : 'fa-triangle-exclamation'} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>`;
}

async function loadVerifyHistory() {
    const tbody = document.getElementById("history_table_body");
    try {
        const res = await fetch(`${API_BASE}/pdf/verify-history`);
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">Không thể nạp nhật ký từ máy chủ.</td></tr>`;
            return;
        }
        const logs = await res.json();
        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-4">Chưa có lịch sử thẩm định.</td></tr>`;
            return;
        }
        tbody.innerHTML = logs.map(log => {
            let badgeClass = "bg-success";
            if (log.status.includes("CHỈNH SỬA") || log.status.includes("KHÔNG AN TOÀN")) badgeClass = "bg-danger";
            return `
                <tr>
                    <td class="text-secondary small">${log.timestamp}</td>
                    <td class="fw-semibold text-dark">${log.filename}</td>
                    <td><span class="badge ${badgeClass}">${log.status}</span></td>
                    <td><span class="badge bg-light text-dark border">${log.signer}</span></td>
                    <td class="text-monospace text-muted small">${log.client_ip}</td>
                </tr>`;
        }).join("");
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">Lỗi kết nối cơ sở dữ liệu SQLite.</td></tr>`;
    }
}

async function requestOTP() {
    const uid = document.getElementById("sign_uid").value;
    const pwd = document.getElementById("sign_pwd").value;
    if(!uid || !pwd) return showResult("sign_result", "danger", "Vui lòng điền đủ Thông tin!");

    const formData = new FormData();
    formData.append("user_id", uid);
    formData.append("password", pwd);
    const btn = document.getElementById("btn_otp");
    btn.disabled = true; btn.innerHTML = `Đang kết nối...`;

    try {
        const res = await fetch(`${API_BASE}/pdf/request-signing-otp`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
            document.getElementById("panel_step_1").classList.add("d-none");
            document.getElementById("panel_step_2").classList.remove("d-none");
            document.getElementById("txt_active_user").innerText = uid;
        } else { showResult("sign_result", "danger", `Thất bại: ${data.detail}`); }
    } catch(e) { showResult("sign_result", "danger", "Lỗi mạng!"); }
    finally { btn.disabled = false; btn.innerHTML = `Xác thực & Gửi OTP`; }
}

function backToStep1() {
    document.getElementById("panel_step_2").classList.add("d-none");
    document.getElementById("panel_step_1").classList.remove("d-none");
}

async function executeSign() {
    const fileInput = document.getElementById("sign_file");
    const otpInput = document.getElementById("sign_otp").value;
    if(fileInput.files.length === 0 || !otpInput) return showResult("sign_result", "danger", "Vui lòng chọn file và nhập OTP!");

    document.getElementById("sign_text").classList.add("d-none");
    document.getElementById("sign_spinner").classList.remove("d-none");
    document.getElementById("btn_sign").disabled = true;

    const formData = new FormData();
    formData.append("user_id", document.getElementById("sign_uid").value);
    formData.append("password", document.getElementById("sign_pwd").value);
    formData.append("otp", otpInput);
    formData.append("file", fileInput.files[0]);

    try {
        const res = await fetch(`${API_BASE}/pdf/sign-with-otp`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
            const downloadUrl = `${API_BASE}/pdf/download/${data.filename}`;
            const successHtml = `🎉 Ký số thành công! <a href="${downloadUrl}" target="_blank" class="btn btn-success btn-sm fw-bold">Xem & Tải File</a>`;
            showResult("sign_result", "success", successHtml);
        } else { showResult("sign_result", "danger", `Lỗi: ${data.detail}`); }
    } catch (e) { showResult("sign_result", "danger", "Lỗi đường truyền!"); }
    finally { 
        document.getElementById("sign_text").classList.remove("d-none"); 
        document.getElementById("sign_spinner").classList.add("d-none"); 
        document.getElementById("btn_sign").disabled = false; 
    }
}

async function executeVerify() {
    const fileInput = document.getElementById("verify_file");
    if(fileInput.files.length === 0) return alert("Vui lòng chọn tệp PDF!");

    const btn = document.querySelector("#verify button.btn-success");
    btn.disabled = true; btn.innerHTML = `Đang mã hóa thẩm định...`;
    const div = document.getElementById("verify_result");
    div.innerHTML = "";

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
        const res = await fetch(`${API_BASE}/pdf/verify`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok && data.status === "success" && data.result.valid) {
            div.innerHTML = `
                <div class="card border-success border-2 rounded-3 shadow-sm">
                    <div class="card-header bg-success text-white fw-bold"><i class="fa-solid fa-shield-check me-2"></i>KẾT QUẢ KIỂM TRA: VĂN BẢN HỢP LỆ TRÙNG KHỚP</div>
                    <div class="card-body">
                        <p class="card-text text-success fw-bold m-0">${data.result.summary}</p>
                        <hr class="my-2">
                        <small class="text-muted d-block" id="signer_container"><b>Người sở hữu ký:</b> </small>
                    </div>
                </div>`;
            const badge = document.createElement('span');
            badge.className = "badge bg-primary fs-6 mt-1 px-3 py-2";
            badge.textContent = data.result.signer;
            document.getElementById("signer_container").appendChild(badge);
        } else {
            div.innerHTML = `
                <div class="card border-danger border-2 rounded-3 shadow-sm">
                    <div class="card-header bg-danger text-white fw-bold"><i class="fa-solid fa-triangle-exclamation me-2"></i>CẢNH BÁO: KHÔNG AN TOÀN</div>
                    <div class="card-body"><p class="card-text text-danger fw-bold m-0">${data.detail || "Văn bản đã bị sửa đổi cấu trúc."}</p></div>
                </div>`;
        }
    } catch (e) {
        div.innerHTML = `<div class="alert alert-danger fw-bold">Lỗi xử lý hệ thống máy chủ.</div>`;
    } finally {
        btn.disabled = false; btn.innerHTML = `<i class="fa-solid fa-magnifying-glass me-2"></i>BẮT ĐẦU KIỂM TRA VĂN BẢN`;
        loadVerifyHistory();
    }
}

function unlockAdminPanel() {
    const user = document.getElementById("admin_username").value;
    const pass = document.getElementById("admin_password").value;
    if (user === "admincds" && pass === "123456") {
        document.getElementById("admin_login_panel").classList.add("d-none");
        document.getElementById("admin_main_panel").classList.remove("d-none");
    } else { alert("Sai thông tin quản trị!"); }
}

function resetAdminView() {
    document.getElementById("admin_login_panel").classList.remove("d-none");
    document.getElementById("admin_main_panel").classList.add("d-none");
}

async function executeRegister() {
    const formData = new FormData();
    formData.append("user_id", document.getElementById("reg_uid").value);
    formData.append("password", document.getElementById("reg_pwd").value);
    formData.append("common_name", document.getElementById("reg_name").value);
    formData.append("email", document.getElementById("reg_email").value);
    formData.append("admin_user", "admincds");
    formData.append("admin_pass", "123456");

    const res = await fetch(`${API_BASE}/user/register`, { method: "POST", body: formData });
    const data = await res.json();
    if (res.ok) { showResult("reg_result", "success", `Hệ thống CA: ${data.message}`); }
    else { showResult("reg_result", "danger", `Lỗi: ${data.detail}`); }
}