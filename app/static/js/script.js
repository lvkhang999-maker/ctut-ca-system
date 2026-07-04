const API_BASE = "/api/v1";
let CURRENT_LOGGED_ROLE = "ADMIN";
let activeAdminSubTable = "TEACHERS";

let rawLogDataset = [];
let processedLogDataset = [];
let tableCurrentPage = 1;
let tableRowsPerPage = 10;
let tableSortField = "timestamp";
let tableSortAscending = false;

// BIẾN TOÀN CỤC PHỤC VỤ PHÂN TRANG CHO BẢNG KẾT QUẢ KÝ ĐỒNG LOẠT BƯỚC 3
let batchFilesDataset = [];
let batchCurrentPage = 1;
const batchRowsPerPage = 10;

// BIẾN TOÀN CỤC PHỤC VỤ TÌM KIẾM, SẮP XẾP, PHÂN TRANG CHO BẢNG KẾT QUẢ THẨM ĐỊNH ĐỒNG LOẠT
let batchVerifyRawDataset = [];       // Lưu trữ dữ liệu gốc trả về từ server
let batchVerifyProcessedDataset = []; // Lưu trữ dữ liệu sau khi filter/sort
let batchVerifyCurrentPage = 1;       // Trang hiện tại
let batchVerifyRowsPerPage = 5;       // Số dòng hiển thị tối đa trên một trang (mặc định là 5)
let batchVerifySortField = "filename";// Cột sắp xếp mặc định
let batchVerifySortAscending = true;  // Thang sắp xếp mặc định (A-Z)

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    const icon = btn.querySelector("i");
    if (input.type === "password") { input.type = "text"; icon.className = "fa-solid fa-eye-slash"; }
    else { input.type = "password"; icon.className = "fa-solid fa-eye"; }
}

document.addEventListener("DOMContentLoaded", () => {
    const tabButtons = document.querySelectorAll('#pkiTabs button');
    tabButtons.forEach(button => {
        button.addEventListener('click', function (e) {
            e.preventDefault();
            const tabTrigger = new bootstrap.Tab(this);
            tabTrigger.show();
            if (this.id === 'verify-tab') { fetchHistoryFromServer(); }
        });
    });

    document.getElementById("log_search").addEventListener("input", handleLogSearchAndFilter);

    const savedUser = localStorage.getItem("ctut_session_user");
    const savedPass = localStorage.getItem("ctut_session_pass");
    if (savedUser && savedPass) {
        document.getElementById("admin_username").value = savedUser;
        document.getElementById("admin_password").value = savedPass;
        unlockAdminPanel();
    }
    fetchHistoryFromServer();
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

async function fetchHistoryFromServer() {
    try {
        const res = await fetch(`${API_BASE}/pdf/verify-history`);
        if (!res.ok) return;
        rawLogDataset = await res.json();
        handleLogSearchAndFilter();
    } catch (e) {
        document.getElementById("history_table_body").innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">Lỗi mất kênh truyền dữ liệu SQLite.</td></tr>`;
    }
}

function handleLogSearchAndFilter() {
    const searchQuery = document.getElementById("log_search").value.toLowerCase().trim();
    const filterStatus = document.getElementById("log_filter_status").value;

    processedLogDataset = rawLogDataset.filter(item => {
        const matchStatus = (filterStatus === "ALL") || item.status.includes(filterStatus);
        const matchSearch = !searchQuery ||
            item.filename.toLowerCase().includes(searchQuery) ||
            item.signer.toLowerCase().includes(searchQuery);
        return matchStatus && matchSearch;
    });
    tableCurrentPage = 1;
    sortDataset();
}

function handleLogSort(field) {
    if (tableSortField === field) { tableSortAscending = !tableSortAscending; }
    else { tableSortField = field; tableSortAscending = true; }
    sortDataset();
}

document.addEventListener("click", function (e) {
    if (e.target && e.target.classList.contains('view-pdf-trigger')) {
        e.preventDefault();
        const fname = e.target.getAttribute('data-filename');
        window.open(`${API_BASE}/pdf/download/${encodeURIComponent(fname)}`, '_blank');
    }
});

function sortDataset() {
    processedLogDataset.sort((a, b) => {
        let valA = a[tableSortField] ? a[tableSortField].toString().toLowerCase() : "";
        let valB = b[tableSortField] ? b[tableSortField].toString().toLowerCase() : "";
        if (valA < valB) return tableSortAscending ? -1 : 1;
        if (valA > valB) return tableSortAscending ? 1 : -1;
        return 0;
    });
    renderLogTable();
}

function handleRowsPerPageChange() {
    tableRowsPerPage = parseInt(document.getElementById("log_rows_per_page").value);
    tableCurrentPage = 1;
    renderLogTable();
}

function toggleFilenameExpand(element) {
    element.classList.toggle("text-truncate");
    element.classList.toggle("expanded-text");
}

function renderLogTable() {
    const tbody = document.getElementById("history_table_body");
    const totalRecords = processedLogDataset.length;

    if (totalRecords === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-4">Không tìm thấy nhật ký hợp lệ.</td></tr>`;
        document.getElementById("log_pagination_info").innerText = "Hiển thị 0 - 0 trong 0 bản ghi";
        document.getElementById("log_pagination_controls").innerHTML = "";
        return;
    }

    const totalPages = Math.ceil(totalRecords / tableRowsPerPage);
    if (tableCurrentPage > totalPages) tableCurrentPage = totalPages;

    const startIndex = (tableCurrentPage - 1) * tableRowsPerPage;
    const endIndex = Math.min(startIndex + tableRowsPerPage, totalRecords);
    const pagedData = processedLogDataset.slice(startIndex, endIndex);

    tbody.innerHTML = pagedData.map(log => {
        let badgeClass = "bg-success";
        if (log.status.includes("vi phạm") || log.status.includes("BỊ CHỈNH SỬA")) badgeClass = "bg-danger";
        if (log.status.includes("thuần túy") || log.status.includes("Unsigned")) badgeClass = "bg-warning text-dark";

        return `
                    <tr>
                        <td class="text-secondary small" style="white-space:nowrap;">${log.timestamp}</td>
                        <td>
                            <div class="d-flex align-items-center justify-content-between">
                                <span onclick="toggleFilenameExpand(this)" class="clickable-filename text-truncate fw-semibold me-2" title="Click xem tên file đầy đủ">${log.filename}</span>
                                <button type="button" data-filename="${log.filename}" class="btn btn-sm btn-link text-primary p-0 fw-bold view-pdf-trigger" style="font-size:12.5px; text-decoration:none; white-space:nowrap;">
                                    <i class="fa-solid fa-arrow-up-right-from-square"></i> Mở xem
                                </button>
                            </div>
                        </td>
                        <td><span class="badge ${badgeClass}">${log.status}</span></td>
                        <td><span class="badge bg-light text-dark border">${log.signer}</span></td>
                        <td class="text-monospace text-muted small">${log.client_ip}</td>
                    </tr>`;
    }).join("");

    document.getElementById("log_pagination_info").innerText = `Hiển thị ${startIndex + 1} - ${endIndex} trong ${totalRecords} bản ghi`;

    let paginationHtml = `
                <li class="page-item ${tableCurrentPage === 1 ? 'disabled' : ''}">
                    <button class="page-link" onclick="changeLogPage(${tableCurrentPage - 1})"><i class="fa-solid fa-angle-left"></i></button>
                </li>`;

    let startPage = Math.max(1, tableCurrentPage - 2);
    let endPage = Math.min(totalPages, startPage + 4);
    if (endPage - startPage < 4) startPage = Math.max(1, endPage - 4);

    for (let i = startPage; i <= endPage; i++) {
        paginationHtml += `
                    <li class="page-item ${tableCurrentPage === i ? 'active' : ''}">
                        <button class="page-link ${tableCurrentPage === i ? 'bg-primary border-primary' : ''}" onclick="changeLogPage(${i})">${i}</button>
                    </li>`;
    }

    paginationHtml += `
                <li class="page-item ${tableCurrentPage === totalPages ? 'disabled' : ''}">
                    <button class="page-link" onclick="changeLogPage(${tableCurrentPage + 1})"><i class="fa-solid fa-angle-right"></i></button>
                </li>`;

    document.getElementById("log_pagination_controls").innerHTML = paginationHtml;
}

function changeLogPage(pageTarget) {
    tableCurrentPage = pageTarget;
    renderLogTable();
}

function switchAdminTableData(targetSubTable) {
    activeAdminSubTable = targetSubTable;
    const btnTeachers = document.getElementById("sub_tab_teachers");
    const btnAdmins = document.getElementById("sub_tab_admins");
    const btnAudit = document.getElementById("sub_tab_audit");

    const wrapperTeachers = document.getElementById("wrapper_table_teachers");
    wrapperTeachers.classList.add("d-none");

    const wrapperAdmins = document.getElementById("wrapper_table_admins");
    if (wrapperAdmins) wrapperAdmins.classList.add("d-none");

    const wrapperAudit = document.getElementById("wrapper_table_audit");
    if (wrapperAudit) wrapperAudit.classList.add("d-none");

    btnTeachers.className = "btn btn-white text-secondary fw-bold rounded-2 px-2 border-0";
    if (btnAdmins) btnAdmins.className = "btn btn-white text-secondary fw-bold rounded-2 px-2 border-0";
    if (btnAudit) btnAudit.className = "btn btn-white text-secondary fw-bold rounded-2 px-2 border-0";

    if (targetSubTable === "TEACHERS") {
        btnTeachers.className = "btn btn-primary fw-bold rounded-2 px-2";
        wrapperTeachers.classList.remove("d-none");
        loadAdminUsers();
    } else if (targetSubTable === "ADMINS" && btnAdmins) {
        btnAdmins.className = "btn btn-dark fw-bold rounded-2 px-2";
        if (wrapperAdmins) wrapperAdmins.classList.remove("d-none");
        loadAdminRolesList();
    } else if (targetSubTable === "AUDIT" && btnAudit) {
        btnAudit.className = "btn btn-warning text-dark fw-bold rounded-2 px-2";
        if (wrapperAudit) wrapperAudit.classList.remove("d-none");
        loadAdminAuditHistoryList();
    }
}

function refreshCurrentAdminViewTable() {
    if (activeAdminSubTable === "TEACHERS") { loadAdminUsers(); }
    else if (activeAdminSubTable === "ADMINS") { loadAdminRolesList(); }
    else { loadAdminAuditHistoryList(); }
}

async function loadAdminUsers() {
    const tbody = document.getElementById("admin_users_table_body");
    const admin_user = document.getElementById("admin_username").value;
    const admin_pass = document.getElementById("admin_password").value;
    try {
        const res = await fetch(`${API_BASE}/admin/users?admin_user=${admin_user}&admin_pass=${admin_pass}`);
        if (!res.ok) { tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger fw-bold py-3">Lỗi bóc tách chứng thư số từ Server.</td></tr>`; return; }
        const users = await res.json();
        if (!Array.isArray(users) || users.length === 0) { tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-3">Chưa khởi tạo tài khoản giảng viên nào.</td></tr>`; return; }
        tbody.innerHTML = users.map(user => `
                    <tr>
                        <td class="fw-bold text-secondary">${user.user_id}</td>
                        <td class="text-dark fw-bold">${user.common_name}</td>
                        <td class="text-monospace text-muted">${user.email}</td>
                        <td class="text-center">
                            <button onclick="openEditUser('${user.user_id}', '${user.common_name}', '${user.email}')" class="btn btn-sm btn-outline-primary fw-bold px-2 py-1"><i class="fa-solid fa-user-pen me-1"></i>Sửa</button>
                        </td>
                    </tr>`).join("");
    } catch (e) { tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-3">Lỗi kết nối hạ tầng mạng.</td></tr>`; }
}

async function loadAdminRolesList() {
    const tbody = document.getElementById("admin_roles_table_body");
    if (!tbody) return;
    const admin_user = document.getElementById("admin_username").value;
    const admin_pass = document.getElementById("admin_password").value;
    try {
        const res = await fetch(`${API_BASE}/admin/roles-list?admin_user=${admin_user}&admin_pass=${admin_pass}`);
        if (!res.ok) { tbody.innerHTML = `<tr><td colspan="3" class="text-center text-danger fw-bold py-3">Lỗi trích xuất phân quyền từ DB.</td></tr>`; return; }
        const admins = await res.json();
        tbody.innerHTML = admins.map(adm => {
            const isSuper = adm.role === "SUPER_ADMIN";
            const badgeRole = isSuper ? "bg-danger" : "bg-primary";
            const labelRole = isSuper ? "Super Admin" : "RA Officer";

            const isActive = adm.is_active === 1 || adm.is_active === null;
            const btnClass = isActive ? "btn-outline-danger" : "btn-success";
            const btnIcon = isActive ? "fa-user-slash" : "fa-user-check";
            const btnText = isActive ? "Vô hiệu" : "Kích hoạt";

            return `
                        <tr>
                            <td class="fw-bold text-dark"><i class="fa-solid fa-user-gear me-2 text-secondary"></i>${adm.username}</td>
                            <td><span class="badge ${badgeRole}">${labelRole}</span></td>
                            <td class="text-center">
                                <button onclick="executeToggleAdminActive('${adm.username}')" class="btn btn-sm ${btnClass} fw-bold px-2 py-1">
                                    <i class="fa-solid ${btnIcon} me-1"></i>${btnText}
                                </button>
                            </td>
                        </tr>`;
        }).join("");
    } catch (e) { tbody.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-3">Lỗi nghẽn đường truyền cơ sở dữ liệu.</td></tr>`; }
}

async function loadAdminAuditHistoryList() {
    const tbody = document.getElementById("admin_audit_table_body");
    if (!tbody) return;
    const admin_user = document.getElementById("admin_username").value;
    const admin_pass = document.getElementById("admin_password").value;
    try {
        const res = await fetch(`${API_BASE}/admin/audit-history?admin_user=${admin_user}&admin_pass=${admin_pass}`);
        if (!res.ok) { tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger fw-bold py-3">Lỗi bóc tách log hệ thống.</td></tr>`; return; }
        const logs = await res.json();
        if (logs.length === 0) { tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-3">Chưa ghi nhận biến động hạ tầng nào.</td></tr>`; return; }

        tbody.innerHTML = logs.map(log => {
            let textClass = "text-primary";
            if (log.status.includes("VÔ HIỆU HÓA")) textClass = "text-danger fw-bold";
            if (log.status.includes("ỦY QUYỀN")) textClass = "text-success fw-bold";
            return `
                        <tr>
                            <td class="text-secondary small">${log.timestamp}</td>
                            <td><span class="${textClass}"><i class="fa-solid fa-gears me-1"></i>${log.status}</span></td>
                            <td><span class="badge bg-light text-dark border fw-bold">${log.signer}</span></td>
                            <td class="text-monospace text-muted small">${log.client_ip}</td>
                        </tr>`;
        }).join("");
    } catch (e) { tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-3">Lỗi nghẽn luồng đọc DB.</td></tr>`; }
}

async function executeAdminUpdateUser() {
    const formData = new FormData();
    formData.append("user_id", document.getElementById("edit_uid").value);
    formData.append("new_common_name", document.getElementById("edit_name").value);
    formData.append("new_email", document.getElementById("edit_email").value);
    formData.append("admin_user", document.getElementById("admin_username").value);
    formData.append("admin_pass", document.getElementById("admin_password").value);

    try {
        const res = await fetch(`${API_BASE}/admin/update-user`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) { showResult("edit_user_result", "success", data.message); refreshCurrentAdminViewTable(); setTimeout(closeEditUser, 1200); }
        else { showResult("edit_user_result", "danger", `Lỗi: ${data.detail}`); }
    } catch (e) { showResult("edit_user_result", "danger", "Lỗi đường truyền mạng!"); }
}

async function executeUserSelfUpdate() {
    const uid = document.getElementById("sign_uid").value;
    const current_pwd = document.getElementById("sign_pwd").value;
    const new_name = document.getElementById("user_self_name").value;
    const new_pwd = document.getElementById("user_self_pass").value;
    const new_pwd_confirm = document.getElementById("user_self_pass_confirm").value;
    const resDiv = document.getElementById("user_self_result");

    if (new_pwd !== new_pwd_confirm) {
        resDiv.innerHTML = `<span class="text-danger fw-bold">❌ Xác nhận mật khẩu mới không trùng khớp!</span>`;
        return;
    }

    const formData = new FormData();
    formData.append("user_id", uid);
    formData.append("current_password", current_pwd);
    if (new_name) formData.append("new_common_name", new_name);
    if (new_pwd) formData.append("new_password", new_pwd);

    try {
        const res = await fetch(`${API_BASE}/user/update-profile`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
            resDiv.innerHTML = `<span class="text-success fw-bold">✔️ ${data.message}</span>`;
            if (new_pwd) {
                document.getElementById("sign_pwd").value = new_pwd;
            }
            setTimeout(() => {
                const modalEl = document.getElementById('userSelfUpdateModal');
                const modalInstance = bootstrap.Modal.getInstance(modalEl);
                if (modalInstance) modalInstance.hide();
                resDiv.innerHTML = "";
                document.getElementById("user_self_name").value = "";
                document.getElementById("user_self_pass").value = "";
                document.getElementById("user_self_pass_confirm").value = "";
            }, 1500);
        } else {
            resDiv.innerHTML = `<span class="text-danger fw-bold">❌ Lỗi: ${data.detail}</span>`;
        }
    } catch (e) {
        resDiv.innerHTML = `<span class="text-danger fw-bold">❌ Lỗi nghẽn đường truyền kết nối API.</span>`;
    }
}

async function executeAssignPrivilege() {
    const targetUser = document.getElementById("priv_user").value;
    const targetPass = document.getElementById("priv_pass").value;
    if (!targetUser || !targetPass) return showResult("priv_result", "danger", "Vui lòng nhập tài khoản và mật khẩu gán quyền mới!");

    const formData = new FormData();
    formData.append("target_user", targetUser);
    formData.append("target_pass", targetPass);
    formData.append("assigned_role", document.getElementById("priv_role").value);
    formData.append("admin_user", document.getElementById("admin_username").value);
    formData.append("admin_pass", document.getElementById("admin_password").value);

    try {
        const res = await fetch(`${API_BASE}/admin/assign-role`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
            showResult("priv_result", "success", data.message);
            document.getElementById("priv_user").value = "";
            document.getElementById("priv_pass").value = "";
            if (activeAdminSubTable === "AUDIT") loadAdminAuditHistoryList();
        } else { showResult("priv_result", "danger", `Lỗi: ${data.detail}`); }
    } catch (e) { showResult("priv_result", "danger", "Lỗi kết nối mạng!"); }
}
async function unlockAdminPanel() {
    const user = document.getElementById("admin_username").value;
    const pass = document.getElementById("admin_password").value;
    const errDiv = document.getElementById("admin_auth_result");
    if (!user || !pass) { errDiv.innerHTML = `<div class="alert alert-danger fw-bold rounded-3 small m-0">Vui lòng điền thông tin đăng nhập!</div>`; return; }

    try {
        const res = await fetch(`${API_BASE}/admin/users?admin_user=${user}&admin_pass=${pass}`);
        if (res.ok) {
            document.getElementById("admin_login_panel").classList.add("d-none");
            document.getElementById("admin_main_panel").classList.remove("d-none");
            errDiv.innerHTML = "";

            localStorage.setItem("ctut_session_user", user);
            localStorage.setItem("ctut_session_pass", pass);

            const badge = document.getElementById("txt_admin_role_badge");
            const superBtn = document.getElementById("btn_toggle_privilege_panel");
            const createFormFields = document.getElementById("admin_create_form_fields");
            const restrictionMsg = document.getElementById("admin_create_restriction_msg");

            if (user.toLowerCase().includes("super")) {
                CURRENT_LOGGED_ROLE = "SUPER_ADMIN";
                badge.innerText = "SUPER ADMIN";
                badge.className = "badge bg-danger fs-6";
                superBtn.classList.remove("d-none");
                createFormFields.classList.remove("d-none");
                restrictionMsg.classList.add("d-none");
            } else {
                CURRENT_LOGGED_ROLE = "ADMIN";
                badge.innerText = "ADMIN (RA OFFICER)";
                badge.className = "badge bg-primary fs-6";
                superBtn.classList.add("d-none");
                createFormFields.classList.add("d-none");
                restrictionMsg.classList.remove("d-none");
            }
            switchAdminTableData("TEACHERS");
        } else {
            const errData = await res.json();
            errDiv.innerHTML = `<div class="alert alert-danger fw-bold rounded-3 small m-0"><i class="fa-solid fa-circle-xmark me-2"></i>${errData.detail || 'Sai thông tin quản trị.'}</div>`;
        }
    } catch (e) { errDiv.innerHTML = `<div class="alert alert-danger fw-bold rounded-3 small m-0">Lỗi kết nối hạ tầng API.</div>`; }
}

async function executeToggleAdminActive(targetUid) {
    const admin_user = document.getElementById("admin_username").value;
    const admin_pass = document.getElementById("admin_password").value;

    if (admin_user === targetUid) {
        alert("Hệ thống bảo mật từ chối lệnh tự vô hiệu hóa tài khoản chính mình!");
        return;
    }
    if (!confirm(`Bạn có chắc chắn muốn thay đổi trạng thái hoạt động của tài khoản quản trị '${targetUid}'?`)) return;

    const formData = new FormData();
    formData.append("target_user", targetUid);
    formData.append("admin_user", admin_user);
    formData.append("admin_pass", admin_pass);

    try {
        const res = await fetch(`${API_BASE}/admin/toggle-active`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) { alert(data.message); loadAdminRolesList(); }
        else { alert(`Từ chối lệnh: ${data.detail}`); }
    } catch (e) { alert("Lỗi nghẽn đường truyền bảo mật."); }
}

async function executeRegister() {
    const uid = document.getElementById("reg_uid").value;
    const pwd = document.getElementById("reg_pwd").value;
    const name = document.getElementById("reg_name").value;
    const email = document.getElementById("reg_email").value;
    const adminUser = document.getElementById("admin_username").value;
    const adminPass = document.getElementById("admin_password").value;

    if (!uid || !pwd || !name || !email) {
        showResult("reg_result", "danger", "Vui lòng điền đầy đủ thông tin thực thể!");
        return;
    }

    const formData = new FormData();
    formData.append("user_id", uid);
    formData.append("password", pwd);
    formData.append("common_name", name);
    formData.append("email", email);
    formData.append("admin_user", adminUser);
    formData.append("admin_pass", adminPass);

    try {
        const res = await fetch(`${API_BASE}/user/register`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
            showResult("reg_result", "success", `Hệ thống CA: ${data.message}`);
            loadAdminUsers();
            document.getElementById("reg_uid").value = "";
            document.getElementById("reg_pwd").value = "";
            document.getElementById("reg_name").value = "";
            document.getElementById("reg_email").value = "";
        }
        else { showResult("reg_result", "danger", `Lỗi: ${data.detail}`); }
    } catch (e) { showResult("reg_result", "danger", "Lỗi mạng kết nối API Gateway!"); }
}

// =========================================================================
// WIZARD CONTROL PIPELINE (LUỒNG ĐIỀU HƯỚNG 3 BƯỚC ĐÃ KHẮC PHỤC HOÀN TOÀN)
// =========================================================================

// BƯỚC 1: ĐĂNG NHẬP XÁC THỰC MẬT KHẨU KHÓA VÀ GỬI MÃ OTP
async function executeRequestOTP() {
    const uid = document.getElementById("sign_uid").value;
    const pwd = document.getElementById("sign_pwd").value;
    if (!uid || !pwd) return showResult("sign_result", "danger", "Vui lòng điền đủ Thông tin đăng nhập!");

    const formData = new FormData();
    formData.append("user_id", uid);
    formData.append("password", pwd);
    const btn = document.getElementById("btn_otp");
    btn.disabled = true; btn.innerHTML = `Đang kết nối hạ tầng...`;

    try {
        const res = await fetch(`${API_BASE}/pdf/request-signing-otp`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
            document.getElementById("panel_step_1").classList.add("d-none");
            document.getElementById("panel_step_2").classList.remove("d-none");
            document.getElementById("txt_active_user").innerText = uid;
            document.getElementById("sign_result").innerHTML = "";
        } else { showResult("sign_result", "danger", `Thất bại: ${data.detail}`); }
    } catch (e) { showResult("sign_result", "danger", "Lỗi kết nối server API Gateway!"); }
    finally { btn.disabled = false; btn.innerHTML = `<i class="fa-solid fa-paper-plane me-2"></i>Xác thực danh tính & Gửi mã OTP`; }
}

function backToStep1() {
    document.getElementById("panel_step_2").classList.add("d-none");
    document.getElementById("panel_step_1").classList.remove("d-none");
    document.getElementById("sign_result").innerHTML = "";
}

// BƯỚC 2: PHÊ DUYỆT MÃ OTP RIÊNG BIỆT - ĐĂNG KÝ STATEFUL SESSION TRÊN SERVER
async function executeVerifyOTP() {
    const uid = document.getElementById("sign_uid").value;
    const otp = document.getElementById("sign_otp").value;
    const btn = document.getElementById("btn_verify_otp");
    if (!otp || otp.length !== 6) return showResult("sign_result", "danger", "Vui lòng nhập đúng mã số OTP gồm 6 chữ số!");

    const formData = new FormData();
    formData.append("user_id", uid);
    formData.append("otp", otp);
    btn.disabled = true; btn.innerHTML = `Đang đối sánh OTP...`;

    try {
        const res = await fetch(`${API_BASE}/pdf/verify-otp`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
            document.getElementById("panel_step_2").classList.add("d-none");
            document.getElementById("panel_step_3").classList.remove("d-none");
            document.getElementById("sign_result").innerHTML = "";
        } else { showResult("sign_result", "danger", `Lỗi xác thực: ${data.detail}`); }
    } catch (e) { showResult("sign_result", "danger", "Lỗi trục truyền kết nối xác thực OTP!"); }
    finally { btn.disabled = false; btn.innerHTML = `XÁC THỰC MÃ OTP`; }
}

function backToStep2() {
    document.getElementById("panel_step_3").classList.add("d-none");
    document.getElementById("panel_step_2").classList.remove("d-none");
    document.getElementById("sign_result").innerHTML = "";
}

// BƯỚC 3: THỰC THI LUỒNG KÝ SỐ ĐỒNG LOẠT QUA PHIÊN AN TOÀN (BẢO VỆ CHỐNG TIMEOUT)
async function executeBatchSign() {
    const fileInput = document.getElementById("sign_file");
    if (fileInput.files.length === 0) {
        return showResult("sign_result", "danger", "Vui lòng chọn ít nhất một văn bản PDF cần ký!");
    }

    document.getElementById("sign_text").classList.add("d-none");
    document.getElementById("sign_spinner").classList.remove("d-none");
    document.getElementById("btn_sign").disabled = true;

    const formData = new FormData();
    formData.append("user_id", document.getElementById("sign_uid").value);
    formData.append("password", document.getElementById("sign_pwd").value);

    for (let i = 0; i < fileInput.files.length; i++) {
        formData.append("files", fileInput.files[i]);
    }

    try {
        const res = await fetch(`${API_BASE}/pdf/batch-sign`, { method: "POST", body: formData });
        const data = await res.json();

        if (res.ok) {
            batchFilesDataset = data.filenames;
            batchCurrentPage = 1;
            renderBatchFilesTable();
        } else {
            showResult("sign_result", "danger", `Từ chối lệnh ký: ${data.detail || "Không thể thực thi luồng ký"}`);
        }
    } catch (e) {
        showResult("sign_result", "danger", "Lỗi mất kết nối mạng trục API Gateway!");
    } finally {
        document.getElementById("sign_text").classList.remove("d-none");
        document.getElementById("sign_spinner").classList.add("d-none");
        document.getElementById("btn_sign").disabled = false;
    }
}

// HÀM HIỆN THỊ BẢNG KẾT QUẢ CHỮ KÝ SỐ ĐỒNG LOẠT CÓ PHÂN TRANG (10 DÒNG/TRANG)
function renderBatchFilesTable() {
    const totalRecords = batchFilesDataset.length;
    const totalPages = Math.ceil(totalRecords / batchRowsPerPage);

    if (batchCurrentPage > totalPages) batchCurrentPage = totalPages;
    const startIndex = (batchCurrentPage - 1) * batchRowsPerPage;
    const endIndex = Math.min(startIndex + batchRowsPerPage, totalRecords);
    const pagedData = batchFilesDataset.slice(startIndex, endIndex);

    let tableHtml = `
                <div class="alert alert-success border-0 rounded-3 mb-3">🎉 Hệ thống hoàn tất tiến trình ký số đồng loạt thành công cho toàn bộ ${totalRecords} văn bản PDF.</div>
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <button type="button" class="btn btn-sm btn-primary rounded-2 px-3 fw-bold shadow-sm" onclick="downloadSelectedBatchFiles()">
                        <i class="fa-solid fa-cloud-arrow-down me-1"></i> Tải các file đã chọn
                    </button>
                    <span class="small fw-semibold text-muted">Hiển thị ${startIndex + 1} - ${endIndex} trong ${totalRecords} tệp</span>
                </div>
                <div class="table-responsive border rounded-3 bg-white mb-2">
                    <table class="table table-hover align-middle m-0" style="font-size: 13.5px;">
                        <thead class="table-light">
                            <tr>
                                <th style="width: 50px;" class="text-center">
                                    <input type="checkbox" id="batch_select_all" class="form-check-input" onclick="toggleSelectAllBatch(this)">
                                </th>
                                <th>Tên tệp tin đã đóng dấu mã hóa X.509</th>
                                <th class="text-center" style="width: 120px;">Hành động</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${pagedData.map(fn => {
        const cleanName = fn.replace("signed_batch_", "");
        return `
                                    <tr>
                                        <td class="text-center">
                                            <input type="checkbox" class="form-check-input batch-file-checkbox" value="${fn}">
                                        </td>
                                        <td class="fw-semibold text-secondary"><i class="fa-solid fa-file-pdf text-danger me-2"></i>${cleanName}</td>
                                        <td class="text-center">
                                            <a href="${API_BASE}/pdf/download/${encodeURIComponent(fn)}" target="_blank" class="btn btn-sm btn-link text-success p-0 fw-bold" style="text-decoration:none;">
                                                <i class="fa-solid fa-arrow-up-right-from-square me-1"></i>Xem file
                                            </a>
                                        </td>
                                    </tr>`;
    }).join("")}
                        </tbody>
                    </table>
                </div>`;

    if (totalPages > 1) {
        tableHtml += `<nav><ul class="pagination pagination-sm justify-content-center m-0 mt-3">`;
        tableHtml += `
                    <li class="page-item ${batchCurrentPage === 1 ? 'disabled' : ''}">
                        <button class="page-link" onclick="changeBatchPage(${batchCurrentPage - 1})"><i class="fa-solid fa-angle-left"></i></button>
                    </li>`;
        for (let i = 1; i <= totalPages; i++) {
            tableHtml += `
                        <li class="page-item ${batchCurrentPage === i ? 'active' : ''}">
                            <button class="page-link" onclick="changeBatchPage(${i})">${i}</button>
                        </li>`;
        }
        tableHtml += `
                    <li class="page-item ${batchCurrentPage === totalPages ? 'disabled' : ''}">
                        <button class="page-link" onclick="changeBatchPage(${batchCurrentPage + 1})"><i class="fa-solid fa-angle-right"></i></button>
                    </li></ul></nav>`;
    }

    document.getElementById("sign_result").innerHTML = tableHtml;
}

function changeBatchPage(pageTarget) {
    batchCurrentPage = pageTarget;
    renderBatchFilesTable();
}

function toggleSelectAllBatch(masterObj) {
    const checkboxes = document.querySelectorAll(".batch-file-checkbox");
    checkboxes.forEach(cb => cb.checked = masterObj.checked);
}

async function downloadSelectedBatchFiles() {
    const checkedBoxes = document.querySelectorAll(".batch-file-checkbox:checked");
    if (checkedBoxes.length === 0) {
        alert("Vui lòng tích chọn các văn bản cần tải về máy!");
        return;
    }

    const btn = document.querySelector('button[onclick="downloadSelectedBatchFiles()"]');
    const originalHtml = btn ? btn.innerHTML : null;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Đang nén ZIP...`;
    }

    const formData = new FormData();
    checkedBoxes.forEach(cb => formData.append("filenames", cb.value));

    try {
        const res = await fetch(`${API_BASE}/pdf/download-batch-zip`, { method: "POST", body: formData });
        if (!res.ok) {
            let msg = "Không thể tạo file ZIP để tải về.";
            try { const err = await res.json(); msg = err.detail || msg; } catch (e) { }
            alert(msg);
            return;
        }
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "Signed_PDFs.zip";
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    } catch (e) {
        alert("Lỗi kết nối khi tải file ZIP.");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    }
}

async function executeVerify() {
    const fileInput = document.getElementById("verify_file");
    if (fileInput.files.length === 0) return alert("Vui lòng chọn ít nhất một tệp PDF để thẩm định!");

    const btn = document.querySelector("#verify button.btn-success");
    const originalText = btn.innerHTML;
    
    btn.disabled = true; 
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Đang phân tích hệ thống mật mã hàng loạt...`;
    
    const div = document.getElementById("verify_result");
    div.innerHTML = "";

    const formData = new FormData();
    for (let i = 0; i < fileInput.files.length; i++) {
        formData.append("files", fileInput.files[i]);
    }

    try {
        const res = await fetch(`${API_BASE}/pdf/verify`, { method: "POST", body: formData });
        const data = await res.json();
        
        if (res.ok && data.status === "success") {
            // Nạp dữ liệu vào bộ nhớ tạm toàn cục
            batchVerifyRawDataset = data.results;
            batchVerifyCurrentPage = 1;
            
            // Dựng khung cấu trúc Card kết quả bao gồm các thanh điều hướng (Tìm kiếm, Chọn số dòng hiển thị)
            div.innerHTML = `
                <div class="card border-primary rounded-3 shadow-sm animate__animated animate__fadeIn">
                    <div class="card-header bg-primary text-white fw-bold d-flex align-items-center justify-content-between flex-wrap gap-2">
                        <span><i class="fa-solid fa-shield-halved me-2"></i>BẢNG KẾT QUẢ THẨM ĐỊNH ĐỒNG LOẠT</span>
                        <span class="badge bg-light text-primary">Tổng số: ${batchVerifyRawDataset.length} File</span>
                    </div>
                    <div class="card-body bg-light border-bottom p-3">
                        <div class="row g-2">
                            <div class="col-12 col-md-8">
                                <div class="input-group">
                                    <span class="input-group-text bg-white border-end-0 text-muted"><i class="fa-solid fa-magnifying-glass"></i></span>
                                    <input type="text" id="batch_verify_search" class="form-control border-start-0 ps-0" placeholder="Tìm nhanh tên file hoặc chủ thể ký trong kết quả hiện tại...">
                                </div>
                            </div>
                            <div class="col-12 col-md-4">
                                <select id="batch_verify_rows_per_page" class="form-select" onchange="handleBatchVerifyRowsChange()">
                                    <option value="5" selected>Hiển thị 5 dòng / trang</option>
                                    <option value="10">Hiển thị 10 dòng / trang</option>
                                    <option value="25">Hiển thị 25 dòng / trang</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="table-responsive bg-white">
                        <table class="table table-custom table-hover align-middle m-0" style="font-size: 13.5px;">
                            <thead class="table-light">
                                <tr>
                                    <th class="text-center" style="width: 60px;">STT</th>
                                    <th onclick="handleBatchVerifySort('filename')" class="clickable-header" style="cursor:pointer; width: 45%;">Tên văn bản kiểm tra <i class="fa-solid fa-sort small ms-1 text-muted"></i></th>
                                    <th onclick="handleBatchVerifySort('status_text')" class="clickable-header" style="cursor:pointer;">Trạng thái xác thực mật mã <i class="fa-solid fa-sort small ms-1 text-muted"></i></th>
                                    <th onclick="handleBatchVerifySort('signer')" class="clickable-header" style="cursor:pointer;">Chủ thể sở hữu chữ ký <i class="fa-solid fa-sort small ms-1 text-muted"></i></th>
                                </tr>
                            </thead>
                            <tbody id="batch_verify_table_body">
                                <!-- Dữ liệu phân trang sẽ được render động tại đây -->
                            </tbody>
                        </table>
                    </div>
                    <div class="card-footer bg-white d-flex flex-wrap justify-content-between align-items-center gap-2 py-3">
                        <small class="text-muted fw-semibold" id="batch_verify_pagination_info">Hiển thị 0 - 0 trong 0 bản ghi</small>
                        <nav>
                            <ul class="pagination pagination-sm m-0" id="batch_verify_pagination_controls"></ul>
                        </nav>
                    </div>
                </div>`;
            
            // Lắng nghe sự kiện gõ phím trên ô tìm kiếm vừa tạo
            document.getElementById("batch_verify_search").addEventListener("input", handleBatchVerifySearchAndFilter);
            
            // Gọi hàm xử lý lọc và vẽ bảng lần đầu tiên
            handleBatchVerifySearchAndFilter();
        } else { 
            div.innerHTML = `<div class="alert alert-danger fw-bold"><i class="fa-solid fa-circle-xmark me-2"></i>Lỗi: ${data.detail || "Không thể xử lý dữ liệu từ API."}</div>`; 
        }
    } catch (e) { 
        div.innerHTML = `<div class="alert alert-danger fw-bold"><i class="fa-solid fa-circle-xmark me-2"></i>Không thể kết nối API Gateway.</div>`; 
    } finally { 
        btn.disabled = false; 
        btn.innerHTML = originalText; 
        fetchHistoryFromServer(); // Tự động cập nhật lại nhật ký hệ thống ở phía dưới[cite: 3]
    }
}
async function unlockAdminPanel() {
    const user = document.getElementById("admin_username").value;
    const pass = document.getElementById("admin_password").value;
    const errDiv = document.getElementById("admin_auth_result");

    try {
        const res = await fetch(`${API_BASE}/admin/users?admin_user=${user}&admin_pass=${pass}`);
        if (res.ok) {
            document.getElementById("admin_login_panel").classList.add("d-none");
            document.getElementById("admin_main_panel").classList.remove("d-none");
            errDiv.innerHTML = "";
            localStorage.setItem("ctut_session_user", user);
            localStorage.setItem("ctut_session_pass", pass);

            // CẬP NHẬT ĐÚNG: Định nghĩa các phần tử giao diện
            const badge = document.getElementById("txt_admin_role_badge");
            const superBtn = document.getElementById("btn_toggle_privilege_panel");
            const createFormFields = document.getElementById("admin_create_form_fields");
            const restrictionMsg = document.getElementById("admin_create_restriction_msg");

            if (user.toLowerCase() === "superadmin") { // So sánh chính xác tài khoản Super
                CURRENT_LOGGED_ROLE = "SUPER_ADMIN";
                badge.innerText = "SUPER ADMIN";
                badge.className = "badge bg-danger fs-6";
                superBtn.classList.remove("d-none");
                // MỞ KHÓA FORM: Phải remove class d-none để hiển thị form
                createFormFields.classList.remove("d-none");
                restrictionMsg.classList.add("d-none");
            } else {
                CURRENT_LOGGED_ROLE = "ADMIN";
                badge.innerText = "ADMIN (RA OFFICER)";
                badge.className = "badge bg-primary fs-6";
                superBtn.classList.add("d-none");
                // KHÓA FORM: Chỉ hiện thông báo giới hạn
                createFormFields.classList.add("d-none");
                restrictionMsg.classList.remove("d-none");
            }
            switchAdminTableData("TEACHERS");
        } else {
            errDiv.innerHTML = `<div class="alert alert-danger fw-bold rounded-3 small m-0">Sai tài khoản hoặc mật khẩu!</div>`;
        }
    } catch (e) { errDiv.innerHTML = `<div class="alert alert-danger fw-bold rounded-3 small m-0">Lỗi kết nối hạ tầng API.</div>`; }
}
function resetAdminView() {
    document.getElementById("admin_username").value = "";
    document.getElementById("admin_password").value = "";
    document.getElementById("admin_auth_result").innerHTML = "";
    document.getElementById("admin_login_panel").classList.remove("d-none");
    document.getElementById("admin_main_panel").classList.add("d-none");
    localStorage.removeItem("ctut_session_user");
    localStorage.removeItem("ctut_session_pass");
    closeEditUser();
    closePrivilegeCard();
}
function openEditUser(uid, currentName, currentEmail) {
    document.getElementById("admin_create_card").classList.add("d-none");
    document.getElementById("admin_privilege_card").classList.add("d-none");
    document.getElementById("admin_edit_card").classList.remove("d-none");
    document.getElementById("edit_uid").value = uid;
    document.getElementById("edit_uid_display").value = uid;
    document.getElementById("edit_name").value = currentName;
    document.getElementById("edit_email").value = currentEmail;

    // Clear password inputs
    document.getElementById("edit_password").value = "";
    document.getElementById("edit_password_confirm").value = "";
    document.getElementById("edit_user_result").innerHTML = "";
}

function closeEditUser() {
    document.getElementById("admin_create_card").classList.remove("d-none");
    document.getElementById("admin_edit_card").classList.add("d-none");
    document.getElementById("edit_user_result").innerHTML = "";
    if (CURRENT_LOGGED_ROLE !== "SUPER_ADMIN") {
        document.getElementById("admin_create_form_fields").classList.add("d-none");
        document.getElementById("admin_create_restriction_msg").classList.remove("d-none");
    }
}

function showPrivilegeCard() {
    document.getElementById("admin_create_card").classList.add("d-none");
    document.getElementById("admin_edit_card").classList.add("d-none");
    document.getElementById("admin_privilege_card").classList.remove("d-none");
    document.getElementById("priv_result").innerHTML = "";
}

function closePrivilegeCard() {
    document.getElementById("admin_create_card").classList.remove("d-none");
    document.getElementById("admin_privilege_card").classList.add("d-none");
    if (CURRENT_LOGGED_ROLE !== "SUPER_ADMIN") {
        document.getElementById("admin_create_form_fields").classList.add("d-none");
        document.getElementById("admin_create_restriction_msg").classList.remove("d-none");
    }
}
// 1. Xử lý bộ lọc tìm kiếm văn bản số công khai trong bảng kết quả hàng loạt
function handleBatchVerifySearchAndFilter() {
    const searchQuery = document.getElementById("batch_verify_search").value.toLowerCase().trim();

    batchVerifyProcessedDataset = batchVerifyRawDataset.filter(item => {
        return !searchQuery || 
               item.filename.toLowerCase().includes(searchQuery) || 
               item.signer.toLowerCase().includes(searchQuery) ||
               item.status_text.toLowerCase().includes(searchQuery);
    });
    
    batchVerifyCurrentPage = 1; // Khởi động lại về trang 1 khi gõ tìm kiếm
    sortBatchVerifyDataset();
}

// 2. Xử lý sự kiện click tiêu đề cột để sắp xếp dữ liệu
function handleBatchVerifySort(field) {
    if (batchVerifySortField === field) {
        batchVerifySortAscending = !batchVerifySortAscending;
    } else {
        batchVerifySortField = field;
        batchVerifySortAscending = true;
    }
    sortBatchVerifyDataset();
}

// 3. Thực thi sắp xếp mảng kết quả
function sortBatchVerifyDataset() {
    batchVerifyProcessedDataset.sort((a, b) => {
        let valA = a[batchVerifySortField] ? a[batchVerifySortField].toString().toLowerCase() : "";
        let valB = b[batchVerifySortField] ? b[batchVerifySortField].toString().toLowerCase() : "";
        if (valA < valB) return batchVerifySortAscending ? -1 : 1;
        if (valA > valB) return batchVerifySortAscending ? 1 : -1;
        return 0;
    });
    renderBatchVerifyTable();
}

// 4. Xử lý thay đổi cấu hình giới hạn số dòng hiển thị tối đa trên một trang
function handleBatchVerifyRowsChange() {
    batchVerifyRowsPerPage = parseInt(document.getElementById("batch_verify_rows_per_page").value);
    batchVerifyCurrentPage = 1;
    renderBatchVerifyTable();
}

// 5. Hàm cốt lõi vẽ giao diện (Render) dữ liệu và thanh phân trang số
function renderBatchVerifyTable() {
    const tbody = document.getElementById("batch_verify_table_body");
    const totalRecords = batchVerifyProcessedDataset.length;

    if (totalRecords === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-4">Không tìm thấy kết quả phù hợp với tiêu chí tìm kiếm.</td></tr>`;
        document.getElementById("batch_verify_pagination_info").innerText = "Hiển thị 0 - 0 trong 0 bản ghi";
        document.getElementById("batch_verify_pagination_controls").innerHTML = "";
        return;
    }

    const totalPages = Math.ceil(totalRecords / batchVerifyRowsPerPage);
    if (batchVerifyCurrentPage > totalPages) batchVerifyCurrentPage = totalPages;

    const startIndex = (batchVerifyCurrentPage - 1) * batchVerifyRowsPerPage;
    const endIndex = Math.min(startIndex + batchVerifyRowsPerPage, totalRecords);
    const pagedData = batchVerifyProcessedDataset.slice(startIndex, endIndex);

    // Dựng luồng dòng dữ liệu
    tbody.innerHTML = pagedData.map((item, index) => {
        let badgeClass = "bg-success";
        if (item.code === "ALTERED") badgeClass = "bg-danger";
        else if (item.code === "UNSIGNED") badgeClass = "bg-warning text-dark";
        else if (item.code === "STRUCT_ERR" || item.code === "INVALID") badgeClass = "bg-dark";

        return `
            <tr>
                <td class="text-center fw-bold text-secondary">${startIndex + index + 1}</td>
                <td>
                    <div class="d-flex align-items-center justify-content-between">
                        <span onclick="toggleFilenameExpand(this)" class="clickable-filename text-truncate fw-semibold me-2" style="max-width:320px;" title="Click xem tên file đầy đủ">${item.filename}</span>
                    </div>
                </td>
                <td><span class="badge ${badgeClass}">${item.status_text}</span></td>
                <td><span class="badge bg-light text-dark border"><i class="fa-solid fa-user me-1 text-muted"></i>${item.signer}</span></td>
            </tr>`;
    }).join("");

    // Hiển thị nhãn thông tin phân trang[cite: 3]
    document.getElementById("batch_verify_pagination_info").innerText = `Hiển thị ${startIndex + 1} - ${endIndex} trong ${totalRecords} bản ghi`;

    // Khởi tạo thuật toán vẽ các nút bấm chuyển trang (Pagination Controls)[cite: 3]
    let paginationHtml = `
        <li class="page-item ${batchVerifyCurrentPage === 1 ? 'disabled' : ''}">
            <button class="page-link" onclick="changeBatchVerifyPage(${batchVerifyCurrentPage - 1})"><i class="fa-solid fa-angle-left"></i></button>
        </li>`;

    let startPage = Math.max(1, batchVerifyCurrentPage - 2);
    let endPage = Math.min(totalPages, startPage + 4);
    if (endPage - startPage < 4) startPage = Math.max(1, endPage - 4);

    for (let i = startPage; i <= endPage; i++) {
        paginationHtml += `
            <li class="page-item ${batchVerifyCurrentPage === i ? 'active' : ''}">
                <button class="page-link ${batchVerifyCurrentPage === i ? 'bg-primary border-primary' : ''}" onclick="changeBatchVerifyPage(${i})">${i}</button>
            </li>`;
    }

    paginationHtml += `
        <li class="page-item ${batchVerifyCurrentPage === totalPages ? 'disabled' : ''}">
            <button class="page-link" onclick="changeBatchVerifyPage(${batchVerifyCurrentPage + 1})"><i class="fa-solid fa-angle-right"></i></button>
        </li>`;

    document.getElementById("batch_verify_pagination_controls").innerHTML = paginationHtml;
}

// 6. Hàm kích hoạt đổi trang khi click nút điều hướng phân trang
function changeBatchVerifyPage(pageTarget) {
    batchVerifyCurrentPage = pageTarget;
    renderBatchVerifyTable();
}