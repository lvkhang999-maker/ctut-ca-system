const API_BASE = "/api/v1";
let CURRENT_LOGGED_ROLE = "ADMIN";
let activeAdminSubTable = "TEACHERS";

// =========================================================================
// 1. BIẾN TOÀN CỤC: NHẬT KÝ THẨM ĐỊNH (VERIFY HISTORY)
// =========================================================================
let rawLogDataset = [];
let processedLogDataset = [];
let tableCurrentPage = 1;
let tableRowsPerPage = 10;
let tableSortField = "timestamp";
let tableSortAscending = false;

// =========================================================================
// 2. BIẾN TOÀN CỤC: BẢNG KẾT QUẢ KÝ ĐỒNG LOẠT (BƯỚC 3)
// =========================================================================
let batchFilesDataset = [];
let batchCurrentPage = 1;
const batchRowsPerPage = 10;

// =========================================================================
// 2b. BIẾN TOÀN CỤC: VỊ TRÍ KÉO-THẢ ĐÓNG DẤU (BƯỚC 3)
// =========================================================================
// stampRatioX/Y: vị trí góc trên-trái của khung dấu, tính theo tỷ lệ (0-1) so
// với chiều rộng/cao trang PDF. null nghĩa là chưa chọn -> backend tự dùng vị
// trí mặc định (góc trên-trái) như hành vi cũ.
let stampRatioX = null;
let stampRatioY = null;
let currentStampPdfDoc = null;   // Đối tượng PDF (pdf.js) đã load, để đổi trang mà không cần đọc lại file
let currentStampPageIndex = 0;   // Trang đang xem trong preview (đếm từ 0)
// Kích thước khung dấu THẬT trên PDF (điểm PDF). Trước đây là hằng số cố định
// (170x55), giờ có thể thay đổi qua tay cầm kéo-giãn ở góc dưới-phải của khung
// preview, nên chuyển thành biến (khởi tạo bằng giá trị mặc định cũ).
let stampWidthPt = 170;
let stampHeightPt = 55;
// Giới hạn kích thước hợp lý để khung không bị kéo quá nhỏ (không đọc được chữ)
// hoặc quá to (che hết nội dung văn bản).
const STAMP_MIN_WIDTH_PT = 60;
const STAMP_MIN_HEIGHT_PT = 30;
const STAMP_MAX_WIDTH_PT = 400;
const STAMP_MAX_HEIGHT_PT = 200;
// Vị trí mặc định (khớp STAMP_MARGIN_TOP/LEFT = 18 bên pdf_engine.py)
const STAMP_DEFAULT_MARGIN_PT = 18;

// =========================================================================
// 3. BIẾN TOÀN CỤC: BẢNG KẾT QUẢ THẨM ĐỊNH ĐỒNG LOẠT
// =========================================================================
let batchVerifyRawDataset = [];       // Lưu trữ dữ liệu gốc trả về từ server
let batchVerifyProcessedDataset = []; // Lưu trữ dữ liệu sau khi filter/sort
let batchVerifyCurrentPage = 1;       // Trang hiện tại
let batchVerifyRowsPerPage = 5;       // Số dòng hiển thị tối đa trên một trang
let batchVerifySortField = "filename";// Cột sắp xếp mặc định
let batchVerifySortAscending = true;  // Thang sắp xếp mặc định (A-Z)

// =========================================================================
// 4. BIẾN TOÀN CỤC: LỊCH SỬ KÝ (SIGNING HISTORY)
// =========================================================================
let rawSignLogDataset = [];
let processedSignLogDataset = [];
let signLogCurrentPage = 1;
let signLogRowsPerPage = 10;
let signLogSortField = "timestamp";
let signLogSortAscending = false;

// =========================================================================
// UTILITIES
// =========================================================================
function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    const icon = btn.querySelector("i");
    if (input.type === "password") { input.type = "text"; icon.className = "fa-solid fa-eye-slash"; }
    else { input.type = "password"; icon.className = "fa-solid fa-eye"; }
}

function showResult(divId, type, message) {
    const div = document.getElementById(divId);
    div.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show fw-bold shadow-sm rounded-3 m-0" role="alert">
            <i class="fa-solid ${type === 'success' ? 'fa-circle-check' : 'fa-triangle-exclamation'} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>`;
}

document.addEventListener("DOMContentLoaded", () => {
    const tabButtons = document.querySelectorAll('#pkiTabs button');
    tabButtons.forEach(button => {
        button.addEventListener('click', function (e) {
            e.preventDefault();
            const tabTrigger = new bootstrap.Tab(this);
            tabTrigger.show();
            if (this.id === 'verify-tab') { fetchHistoryFromServer(); }
            if (this.id === 'signhistory-tab') { fetchSigningHistoryFromServer(); }
        });
    });

    const logSearchInput = document.getElementById("log_search");
    if (logSearchInput) logSearchInput.addEventListener("input", handleLogSearchAndFilter);

    const signLogSearchInput = document.getElementById("sign_log_search");
    if (signLogSearchInput) signLogSearchInput.addEventListener("input", handleSignLogSearchAndFilter);

    const savedUser = localStorage.getItem("ctut_session_user");
    const savedPass = localStorage.getItem("ctut_session_pass");
    if (savedUser && savedPass) {
        document.getElementById("admin_username").value = savedUser;
        document.getElementById("admin_password").value = savedPass;
        unlockAdminPanel();
    }
    fetchHistoryFromServer();
});

// =========================================================================
// MODULE: NHẬT KÝ THẨM ĐỊNH CHUNG
// =========================================================================
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

// Chuỗi ký nhiều chữ ký nối bằng " ➔ " (vd: "A ➔ B ➔ C ➔ D") có thể rất dài và
// tràn dòng badge. Xuống dòng cứ mỗi 2 tên, giữ mũi tên ở đầu dòng kế tiếp để
// thể hiện chuỗi vẫn đang tiếp diễn (vd: "A ➔ B" xuống dòng "➔ C ➔ D").
// Dùng chung cho cả bảng "Kết Quả Thẩm Định Đồng Loạt" và "Nhật Ký Thẩm Định Hệ Thống".
function formatSignerChain(signerStr) {
    if (!signerStr) return signerStr;
    const names = signerStr.split(" ➔ ").map(s => s.trim()).filter(Boolean);
    if (names.length <= 2) return names.join(" ➔ ");

    const lines = [];
    for (let i = 0; i < names.length; i += 2) {
        const pair = names.slice(i, i + 2).join(" ➔ ");
        lines.push(i === 0 ? pair : `➔ ${pair}`);
    }
    return lines.join("<br>");
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
        // Khớp theo nhãn status_text MỚI (main.py đã đổi nhãn, logic match cũ ở đây
        // vẫn dùng cụm từ cũ như "thuần túy"/"Unsigned"/"BỊ CHỈNH SỬA" nên không bao
        // giờ khớp nữa -> mọi dòng rơi về mặc định xanh lá dù trạng thái thực là lỗi.
        let badgeClass = "bg-success"; // mặc định: Hợp lệ - Văn bản toàn vẹn
        if (log.status.includes("chỉnh sửa") || log.status.includes("không hợp lệ")) badgeClass = "bg-danger";
        else if (log.status.includes("Chưa được ký")) badgeClass = "bg-warning text-dark";
        else if (log.status.includes("cấu trúc")) badgeClass = "bg-dark";

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
                <td><span class="badge bg-light text-dark border">${formatSignerChain(log.signer)}</span></td>
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

// =========================================================================
// MODULE: LỊCH SỬ KÝ (SIGNING HISTORY)
// =========================================================================
async function fetchSigningHistoryFromServer() {
    try {
        const res = await fetch(`${API_BASE}/pdf/signing-history`);
        if (!res.ok) return;
        rawSignLogDataset = await res.json();
        handleSignLogSearchAndFilter();
    } catch (e) {
        document.getElementById("sign_history_table_body").innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">Lỗi mất kênh truyền dữ liệu CSDL.</td></tr>`;
    }
}

function handleSignLogSearchAndFilter() {
    const searchQuery = document.getElementById("sign_log_search").value.toLowerCase().trim();
    const filterStatus = document.getElementById("sign_log_filter_status").value;

    processedSignLogDataset = rawSignLogDataset.filter(item => {
        const matchStatus = (filterStatus === "ALL") || item.status === filterStatus;
        const matchSearch = !searchQuery ||
            item.filename.toLowerCase().includes(searchQuery) ||
            (item.signer_name || "").toLowerCase().includes(searchQuery) ||
            (item.user_id || "").toLowerCase().includes(searchQuery);
        return matchStatus && matchSearch;
    });
    signLogCurrentPage = 1;
    sortSignLogDataset();
}

function handleSignLogSort(field) {
    if (signLogSortField === field) { signLogSortAscending = !signLogSortAscending; }
    else { signLogSortField = field; signLogSortAscending = true; }
    sortSignLogDataset();
}

function renderSignLogTable() {
    const tbody = document.getElementById("sign_history_table_body");
    if (!tbody) return;
    const totalRecords = processedSignLogDataset.length;

    if (totalRecords === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-4">Chưa có lịch sử ký nào.</td></tr>`;
        document.getElementById("sign_log_pagination_info").innerText = "Hiển thị 0 - 0 trong 0 bản ghi";
        document.getElementById("sign_log_pagination_controls").innerHTML = "";
        return;
    }

    const totalPages = Math.ceil(totalRecords / signLogRowsPerPage);
    if (signLogCurrentPage > totalPages) signLogCurrentPage = totalPages;

    const startIndex = (signLogCurrentPage - 1) * signLogRowsPerPage;
    const endIndex = Math.min(startIndex + signLogRowsPerPage, totalRecords);
    const pagedData = processedSignLogDataset.slice(startIndex, endIndex);

    tbody.innerHTML = pagedData.map(log => {
        const isSuccess = log.status === "SUCCESS";
        const badgeClass = isSuccess ? "bg-success" : "bg-danger";
        const badgeText = isSuccess ? "Ký thành công" : "Ký thất bại";

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
                <td><span class="badge bg-light text-dark border">${log.signer_name || log.user_id}</span></td>
                <td><span class="badge ${badgeClass}">${badgeText}</span></td>
                <td class="text-muted small">${log.detail ? log.detail : "-"}</td>
            </tr>`;
    }).join("");

    document.getElementById("sign_log_pagination_info").innerText = `Hiển thị ${startIndex + 1} - ${endIndex} trong ${totalRecords} bản ghi`;

    let paginationHtml = `
        <li class="page-item ${signLogCurrentPage === 1 ? 'disabled' : ''}">
            <button class="page-link" onclick="changeSignLogPage(${signLogCurrentPage - 1})"><i class="fa-solid fa-angle-left"></i></button>
        </li>`;

    let startPage = Math.max(1, signLogCurrentPage - 2);
    let endPage = Math.min(totalPages, startPage + 4);
    if (endPage - startPage < 4) startPage = Math.max(1, endPage - 4);

    for (let i = startPage; i <= endPage; i++) {
        paginationHtml += `
            <li class="page-item ${signLogCurrentPage === i ? 'active' : ''}">
                <button class="page-link ${signLogCurrentPage === i ? 'bg-primary border-primary' : ''}" onclick="changeSignLogPage(${i})">${i}</button>
            </li>`;
    }

    paginationHtml += `
        <li class="page-item ${signLogCurrentPage === totalPages ? 'disabled' : ''}">
            <button class="page-link" onclick="changeSignLogPage(${signLogCurrentPage + 1})"><i class="fa-solid fa-angle-right"></i></button>
        </li>`;

    document.getElementById("sign_log_pagination_controls").innerHTML = paginationHtml;
}

function sortSignLogDataset() {
    processedSignLogDataset.sort((a, b) => {
        let valA = a[signLogSortField] ? a[signLogSortField].toString().toLowerCase() : "";
        let valB = b[signLogSortField] ? b[signLogSortField].toString().toLowerCase() : "";
        if (valA < valB) return signLogSortAscending ? -1 : 1;
        if (valA > valB) return signLogSortAscending ? 1 : -1;
        return 0;
    });
    renderSignLogTable();
}

function handleSignLogRowsPerPageChange() {
    signLogRowsPerPage = parseInt(document.getElementById("sign_log_rows_per_page").value);
    signLogCurrentPage = 1;
    renderSignLogTable();
}


function changeSignLogPage(pageTarget) {
    signLogCurrentPage = pageTarget;
    renderSignLogTable();
}

// =========================================================================
// MODULE: QUẢN TRỊ ADMIN (USERS & ROLES)
// =========================================================================
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

            if (user.toLowerCase() === "superadmin") {
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

// =========================================================================
// WIZARD CONTROL PIPELINE (LUỒNG ĐIỀU HƯỚNG 3 BƯỚC ĐĂNG NHẬP / KÝ SỐ)
// =========================================================================

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
            // QUAN TRỌNG: trước đây data.message bị bỏ qua hoàn toàn. Nếu gửi email
            // thật thất bại (vd Brevo lỗi), server sẽ tự chuyển sang "chế độ giả lập"
            // và trả kèm MÃ OTP ngay trong message này - nếu không hiển thị ra thì
            // người dùng không có cách nào biết mã đó để nhập ở Bước 2.
            if (data.message) {
                const isWarning = data.message.includes("⚠️");
                showResult("sign_result", isWarning ? "warning" : "success", data.message);
            }
        } else { showResult("sign_result", "danger", `Thất bại: ${data.detail}`); }
    } catch (e) { showResult("sign_result", "danger", "Lỗi kết nối server API Gateway!"); }
    finally { btn.disabled = false; btn.innerHTML = `<i class="fa-solid fa-paper-plane me-2"></i>Xác thực danh tính & Gửi mã OTP`; }
}

function backToStep1() {
    document.getElementById("panel_step_2").classList.add("d-none");
    document.getElementById("panel_step_1").classList.remove("d-none");
    document.getElementById("sign_result").innerHTML = "";
}

// =========================================================================
// KHÔI PHỤC PHIÊN OTP SAU KHI RELOAD TRANG
// =========================================================================
// Trước đây trạng thái "đã đăng nhập/đã xác thực OTP" chỉ tồn tại trong biến
// JS của tab, nên F5 là mất sạch dù server (_user_active_sessions) vẫn còn
// nhớ phiên OTP hợp lệ. Giờ dùng sessionStorage (KHÔNG lưu mật khẩu, chỉ lưu
// user_id, và tự xóa khi đóng tab) để phát hiện và mời người dùng tiếp tục ký
// ngay mà không cần xin OTP mới - chỉ cần nhập lại mật khẩu.
async function checkResumeSessionOnLoad() {
    const savedUid = sessionStorage.getItem("ctut_active_uid");
    const savedPwd = sessionStorage.getItem("ctut_active_pwd"); // Dòng thêm mới
    if (!savedUid) return;

    document.getElementById("sign_uid").value = savedUid;

    try {
        const res = await fetch(`${API_BASE}/user/session-status/${encodeURIComponent(savedUid)}`);
        const data = await res.json();
        if (res.ok && data.active) {
            if (savedPwd) {
                // AUTO-RESUME: Tự động điền pass và nhảy thẳng vào Bước 3 (Bỏ qua banner rườm rà)
                document.getElementById("sign_pwd").value = savedPwd;
                document.getElementById("panel_step_1").classList.add("d-none");
                document.getElementById("panel_step_3").classList.remove("d-none");
                updateHeaderSignaturePreview();
                document.getElementById("sign_result").innerHTML = "";
            } else {
                // Fallback: Banner cũ phòng trường hợp user xóa storage mật khẩu nhưng còn UID
                const banner = document.getElementById("resume_session_banner");
                document.getElementById("resume_session_uid").innerText = savedUid;
                banner.classList.remove("d-none");
                document.getElementById("sign_pwd").focus();
            }
        } else {
            sessionStorage.removeItem("ctut_active_uid");
            sessionStorage.removeItem("ctut_active_pwd"); // Dòng thêm mới
        }
    } catch (e) {
        // Mất mạng lúc kiểm tra -> im lặng bỏ qua, người dùng vẫn đăng nhập lại bình thường.
    }
}

function resumeSessionContinueSigning() {
    const pwd = document.getElementById("sign_pwd").value;
    if (!pwd) {
        showResult("sign_result", "danger", "Vui lòng nhập lại mật khẩu khóa Private để tiếp tục!");
        return;
    }
    document.getElementById("panel_step_1").classList.add("d-none");
    document.getElementById("panel_step_3").classList.remove("d-none");
    document.getElementById("sign_result").innerHTML = "";
}

document.addEventListener("DOMContentLoaded", checkResumeSessionOnLoad);

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
            updateHeaderSignaturePreview();
            document.getElementById("sign_result").innerHTML = "";


            // LƯU LẠI UID VÀ MẬT KHẨU VÀO SESSION STORAGE
            sessionStorage.setItem("ctut_active_uid", uid);
            sessionStorage.setItem("ctut_active_pwd", document.getElementById("sign_pwd").value); // Dòng thêm mới
        } else { showResult("sign_result", "danger", `Lỗi xác thực: ${data.detail}`); }
    } catch (e) { showResult("sign_result", "danger", "Lỗi trục truyền kết nối xác thực OTP!"); }
    finally { btn.disabled = false; btn.innerHTML = `XÁC THỰC MÃ OTP`; }
}

function backToStep2() {
    document.getElementById("panel_step_3").classList.add("d-none");
    document.getElementById("panel_step_2").classList.remove("d-none");
    document.getElementById("sign_result").innerHTML = "";
}

// =========================================================================
// VỊ TRÍ KÉO-THẢ ĐÓNG DẤU (dùng pdf.js render trang 1 của file đầu tiên)
// =========================================================================
if (window['pdfjsLib']) {
    pdfjsLib.GlobalWorkerOptions.workerSrc = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
}

async function handleSignFilesSelected(inputEl) {
    const picker = document.getElementById("stamp_position_picker");
    if (!inputEl.files || inputEl.files.length === 0) {
        picker.classList.add("d-none");
        currentStampPdfDoc = null;
        return;
    }
    if (!window['pdfjsLib']) {
        // Không load được pdf.js (vd mất mạng CDN) -> ẩn khung preview, backend
        // vẫn ký bình thường với vị trí mặc định vì stampRatioX/Y giữ nguyên null.
        picker.classList.add("d-none");
        return;
    }

    try {
        const file = inputEl.files[0];
        const arrayBuffer = await file.arrayBuffer();
        currentStampPdfDoc = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
        currentStampPageIndex = 0;
        stampRatioX = null; // reset để tự đặt lại mặc định đúng theo kích thước trang mới
        stampRatioY = null;
        await renderStampPreviewPage(currentStampPageIndex);
        picker.classList.remove("d-none");
        updateStampPreviewInfoText();
        loadStampPreviewSignatureImage();
        initStampDragHandlers();
    } catch (e) {
        picker.classList.add("d-none");
        currentStampPdfDoc = null;
    }
}

// Cập nhật khối chữ "Ký bởi/Thời gian" trong khung preview để khớp với nội dung
// thật sẽ được đóng dấu (dùng đúng user_id đang nhập và thời điểm hiện tại).
function updateStampPreviewInfoText() {
    const textArea = document.getElementById("stamp_preview_text_area");
    if (!textArea) return;
    const uid = document.getElementById("sign_uid").value || "...";
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    
    const dateStr = `${pad(now.getDate())}-${pad(now.getMonth() + 1)}-${now.getFullYear()}`;
    const timeStr = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    
    // Đúng định dạng 3 dòng
    textArea.innerHTML = `Ký bởi: ${uid}<br>Ngày: ${dateStr}<br>Giờ: ${timeStr}`;
}

async function loadStampPreviewSignatureImage() {
    const uid = document.getElementById("sign_uid").value;
    const img = document.getElementById("stamp_preview_sig_img");
    const placeholder = document.getElementById("stamp_preview_sig_placeholder");
    if (!img || !placeholder) return;

    if (!uid) {
        img.classList.add("d-none");
        placeholder.classList.remove("d-none");
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/user/signature-preview/${encodeURIComponent(uid)}`);
        if (res.ok) {
            const blob = await res.blob();
            img.src = URL.createObjectURL(blob);
            img.classList.remove("d-none");
            placeholder.classList.add("d-none");
        } else {
            img.classList.add("d-none");
            placeholder.classList.remove("d-none");
        }
    } catch (e) {
        img.classList.add("d-none");
        placeholder.classList.remove("d-none");
    }
}

async function renderStampPreviewPage(pageIndex) {
    const picker = document.getElementById("stamp_position_picker");
    if (!currentStampPdfDoc) return;

    const page = await currentStampPdfDoc.getPage(pageIndex + 1); // pdf.js đánh số trang từ 1

    // page.view = [x0, y0, x1, y1] theo ĐIỂM PDF thật (không phụ thuộc scale),
    // dùng để quy đổi chính xác giữa pixel xem trước và điểm PDF thật.
    const pagePtWidth = page.view[2] - page.view[0];
    const pagePtHeight = page.view[3] - page.view[1];

    const previewMaxWidthPx = 460;
    const scale = previewMaxWidthPx / pagePtWidth;
    const viewport = page.getViewport({ scale });

    const canvas = document.getElementById("stamp_preview_canvas");
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    const ctx = canvas.getContext("2d");
    await page.render({ canvasContext: ctx, viewport }).promise;

    picker.dataset.pagePtWidth = pagePtWidth;
    picker.dataset.pagePtHeight = pagePtHeight;
    picker.dataset.canvasPxWidth = viewport.width;
    picker.dataset.canvasPxHeight = viewport.height;

    document.getElementById("stamp_page_indicator").innerText =
        `Trang ${pageIndex + 1} / ${currentStampPdfDoc.numPages}`;

    // Nếu chưa từng chọn vị trí (file mới hoặc vừa đổi trang lần đầu), đặt mặc
    // định đúng bằng vị trí mặc định thật bên backend (góc trên-trái, cách mép
    // 18pt) để khung xem trước khớp với kết quả ký thực tế nếu không kéo gì cả.
    if (stampRatioX === null || stampRatioY === null) {
        stampRatioX = STAMP_DEFAULT_MARGIN_PT / pagePtWidth;
        stampRatioY = STAMP_DEFAULT_MARGIN_PT / pagePtHeight;
    }
    positionStampDragBox();
}

function changeStampPreviewPage(delta) {
    if (!currentStampPdfDoc) return;
    const newIndex = currentStampPageIndex + delta;
    if (newIndex < 0 || newIndex >= currentStampPdfDoc.numPages) return;
    currentStampPageIndex = newIndex;
    renderStampPreviewPage(currentStampPageIndex);
    updateStampPreviewInfoText();
}

function positionStampDragBox() {
    const picker = document.getElementById("stamp_position_picker");
    const box = document.getElementById("stamp_drag_box");
    const canvasPxWidth = parseFloat(picker.dataset.canvasPxWidth);
    const canvasPxHeight = parseFloat(picker.dataset.canvasPxHeight);
    const pagePtWidth = parseFloat(picker.dataset.pagePtWidth);
    const pagePtHeight = parseFloat(picker.dataset.pagePtHeight);

    const boxPxWidth = (stampWidthPt / pagePtWidth) * canvasPxWidth;
    const boxPxHeight = (stampHeightPt / pagePtHeight) * canvasPxHeight;

    box.style.width = `${boxPxWidth}px`;
    box.style.height = `${boxPxHeight}px`;
    box.style.left = `${stampRatioX * canvasPxWidth}px`;
    box.style.top = `${stampRatioY * canvasPxHeight}px`;
}

function resetStampPosition() {
    const picker = document.getElementById("stamp_position_picker");
    const pagePtWidth = parseFloat(picker.dataset.pagePtWidth);
    const pagePtHeight = parseFloat(picker.dataset.pagePtHeight);
    if (!pagePtWidth || !pagePtHeight) return;
    stampRatioX = STAMP_DEFAULT_MARGIN_PT / pagePtWidth;
    stampRatioY = STAMP_DEFAULT_MARGIN_PT / pagePtHeight;
    // Đặt lại mặc định cũng trả kích thước về giá trị gốc (170x55pt), không chỉ vị trí.
    stampWidthPt = 170;
    stampHeightPt = 55;
    positionStampDragBox();
}

let _stampDragHandlersInitialized = false;
function initStampDragHandlers() {
    if (_stampDragHandlersInitialized) return;
    _stampDragHandlersInitialized = true;

    const box = document.getElementById("stamp_drag_box");
    const wrapper = document.getElementById("stamp_preview_wrapper");
    const resizeHandle = document.getElementById("stamp_resize_handle");
    let isDragging = false;
    let isResizing = false;
    let dragOffsetX = 0, dragOffsetY = 0;
    let resizeStartX = 0, resizeStartY = 0;
    let resizeStartWidthPx = 0, resizeStartHeightPx = 0;

    function getPointerPos(evt) {
        const point = evt.touches ? evt.touches[0] : evt;
        return { x: point.clientX, y: point.clientY };
    }

    function onDragStart(evt) {
        isDragging = true;
        box.style.cursor = "grabbing";
        const rect = box.getBoundingClientRect();
        const pos = getPointerPos(evt);
        dragOffsetX = pos.x - rect.left;
        dragOffsetY = pos.y - rect.top;
        evt.preventDefault();
        evt.stopPropagation();
    }

    function onDragMove(evt) {
        if (!isDragging) return;
        const picker = document.getElementById("stamp_position_picker");
        const canvasPxWidth = parseFloat(picker.dataset.canvasPxWidth);
        const canvasPxHeight = parseFloat(picker.dataset.canvasPxHeight);
        const wrapperRect = wrapper.getBoundingClientRect();
        const pos = getPointerPos(evt);

        let newLeft = pos.x - wrapperRect.left - dragOffsetX;
        let newTop = pos.y - wrapperRect.top - dragOffsetY;

        // Kẹp trong biên canvas để khung dấu không bị kéo ra ngoài trang.
        const boxWidthPx = box.offsetWidth;
        const boxHeightPx = box.offsetHeight;
        newLeft = Math.max(0, Math.min(newLeft, canvasPxWidth - boxWidthPx));
        newTop = Math.max(0, Math.min(newTop, canvasPxHeight - boxHeightPx));

        box.style.left = `${newLeft}px`;
        box.style.top = `${newTop}px`;

        stampRatioX = newLeft / canvasPxWidth;
        stampRatioY = newTop / canvasPxHeight;
        evt.preventDefault();
    }

    function onDragEnd() {
        isDragging = false;
        box.style.cursor = "grab";
    }

    // ---- Kéo-giãn kích thước (tay cầm ở góc dưới-phải khung) ----
    function onResizeStart(evt) {
        isResizing = true;
        const pos = getPointerPos(evt);
        resizeStartX = pos.x;
        resizeStartY = pos.y;
        resizeStartWidthPx = box.offsetWidth;
        resizeStartHeightPx = box.offsetHeight;
        evt.preventDefault();
        evt.stopPropagation(); // không để onDragStart của khung cha bắt luôn sự kiện này
    }

    function onResizeMove(evt) {
        if (!isResizing) return;
        const picker = document.getElementById("stamp_position_picker");
        const canvasPxWidth = parseFloat(picker.dataset.canvasPxWidth);
        const canvasPxHeight = parseFloat(picker.dataset.canvasPxHeight);
        const pagePtWidth = parseFloat(picker.dataset.pagePtWidth);
        const pagePtHeight = parseFloat(picker.dataset.pagePtHeight);
        const pos = getPointerPos(evt);

        let newWidthPx = resizeStartWidthPx + (pos.x - resizeStartX);
        let newHeightPx = resizeStartHeightPx + (pos.y - resizeStartY);

        // Quy đổi giới hạn min/max (tính bằng điểm PDF) sang pixel preview để kẹp trực tiếp.
        const minWidthPx = (STAMP_MIN_WIDTH_PT / pagePtWidth) * canvasPxWidth;
        const maxWidthPx = (STAMP_MAX_WIDTH_PT / pagePtWidth) * canvasPxWidth;
        const minHeightPx = (STAMP_MIN_HEIGHT_PT / pagePtHeight) * canvasPxHeight;
        const maxHeightPx = (STAMP_MAX_HEIGHT_PT / pagePtHeight) * canvasPxHeight;

        const boxLeftPx = box.offsetLeft;
        const boxTopPx = box.offsetTop;
        // Không cho khung giãn ra khỏi biên phải/dưới của trang.
        newWidthPx = Math.max(minWidthPx, Math.min(newWidthPx, maxWidthPx, canvasPxWidth - boxLeftPx));
        newHeightPx = Math.max(minHeightPx, Math.min(newHeightPx, maxHeightPx, canvasPxHeight - boxTopPx));

        box.style.width = `${newWidthPx}px`;
        box.style.height = `${newHeightPx}px`;

        stampWidthPt = (newWidthPx / canvasPxWidth) * pagePtWidth;
        stampHeightPt = (newHeightPx / canvasPxHeight) * pagePtHeight;
        evt.preventDefault();
    }

    function onResizeEnd() {
        isResizing = false;
    }

    box.addEventListener("mousedown", onDragStart);
    document.addEventListener("mousemove", onDragMove);
    document.addEventListener("mouseup", onDragEnd);
    box.addEventListener("touchstart", onDragStart, { passive: false });
    document.addEventListener("touchmove", onDragMove, { passive: false });
    document.addEventListener("touchend", onDragEnd);

    if (resizeHandle) {
        resizeHandle.addEventListener("mousedown", onResizeStart);
        document.addEventListener("mousemove", onResizeMove);
        document.addEventListener("mouseup", onResizeEnd);
        resizeHandle.addEventListener("touchstart", onResizeStart, { passive: false });
        document.addEventListener("touchmove", onResizeMove, { passive: false });
        document.addEventListener("touchend", onResizeEnd);
    }
}

async function executeUploadSignature() {
    const uid = document.getElementById("sign_uid").value;
    const current_pwd = document.getElementById("sign_pwd").value;
    const fileInput = document.getElementById("user_self_signature_file");
    const resDiv = document.getElementById("user_self_signature_result");

    if (!fileInput.files || fileInput.files.length === 0) {
        resDiv.innerHTML = `<span class="text-danger fw-bold">❌ Vui lòng chọn 1 tệp ảnh chữ ký!</span>`;
        return;
    }

    const formData = new FormData();
    formData.append("user_id", uid);
    formData.append("current_password", current_pwd);
    formData.append("signature_file", fileInput.files[0]);

    try {
        const res = await fetch(`${API_BASE}/user/upload-signature`, { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok) {
            resDiv.innerHTML = `<span class="text-success fw-bold">✔️ ${data.message}</span>`;
            fileInput.value = "";
            loadStampPreviewSignatureImage();
            updateHeaderSignaturePreview();
        } else {
            resDiv.innerHTML = `<span class="text-danger fw-bold">❌ Lỗi: ${data.detail}</span>`;
        }
    } catch (e) {
        resDiv.innerHTML = `<span class="text-danger fw-bold">❌ Lỗi nghẽn đường truyền kết nối API.</span>`;
    }
}

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

    // Nếu người dùng đã kéo-thả chọn vị trí đóng dấu ở khung preview, gửi kèm
    // tỷ lệ vị trí đó. Nếu chưa (ví dụ trình duyệt không load được pdf.js), bỏ
    // qua để backend tự dùng vị trí mặc định góc trên-trái như hành vi cũ.
    if (stampRatioX !== null && stampRatioY !== null) {
        formData.append("stamp_ratio_x", stampRatioX);
        formData.append("stamp_ratio_y", stampRatioY);
        formData.append("stamp_page_index", currentStampPageIndex);
        // Kích thước khung do người dùng kéo-giãn (nếu chưa kéo gì thì vẫn gửi giá
        // trị mặc định 170x55pt trong stampWidthPt/stampHeightPt).
        formData.append("stamp_width_pt", stampWidthPt);
        formData.append("stamp_height_pt", stampHeightPt);
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

async function logoutUser() {
    const uid = document.getElementById("sign_uid").value;
    if (!uid) return;

    const formData = new FormData();
    formData.append("user_id", uid);

    try {
        await fetch(`${API_BASE}/user/logout`, { method: "POST", body: formData });
    } catch (e) {
        console.error("Lỗi ngắt kết nối mạng khi đăng xuất.");
    } finally {
        document.getElementById("panel_step_3").classList.add("d-none");
        document.getElementById("panel_step_1").classList.remove("d-none");
        document.getElementById("resume_session_banner").classList.add("d-none");

        // XÓA SẠCH DỮ LIỆU TẠM THỜI
        sessionStorage.removeItem("ctut_active_uid");
        sessionStorage.removeItem("ctut_active_pwd"); // Dòng thêm mới

        document.getElementById("sign_pwd").value = "";
        document.getElementById("sign_otp").value = "";
        document.getElementById("sign_file").value = "";
        document.getElementById("sign_result").innerHTML = "";
    }
}

// =========================================================================
// THẨM ĐỊNH ĐỒNG LOẠT (BATCH VERIFY) - BẢO LƯU TỪ FILE TRƯỚC
// =========================================================================
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
            batchVerifyRawDataset = data.results;
            batchVerifyCurrentPage = 1;

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

            document.getElementById("batch_verify_search").addEventListener("input", handleBatchVerifySearchAndFilter);
            handleBatchVerifySearchAndFilter();
        } else {
            div.innerHTML = `<div class="alert alert-danger fw-bold"><i class="fa-solid fa-circle-xmark me-2"></i>Lỗi: ${data.detail || "Không thể xử lý dữ liệu từ API."}</div>`;
        }
    } catch (e) {
        div.innerHTML = `<div class="alert alert-danger fw-bold"><i class="fa-solid fa-circle-xmark me-2"></i>Không thể kết nối API Gateway.</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
        fetchHistoryFromServer();
    }
}

function handleBatchVerifySearchAndFilter() {
    const searchQuery = document.getElementById("batch_verify_search").value.toLowerCase().trim();
    batchVerifyProcessedDataset = batchVerifyRawDataset.filter(item => {
        return !searchQuery ||
            item.filename.toLowerCase().includes(searchQuery) ||
            item.signer.toLowerCase().includes(searchQuery) ||
            item.status_text.toLowerCase().includes(searchQuery);
    });

    batchVerifyCurrentPage = 1;
    sortBatchVerifyDataset();
}

function handleBatchVerifySort(field) {
    if (batchVerifySortField === field) {
        batchVerifySortAscending = !batchVerifySortAscending;
    } else {
        batchVerifySortField = field;
        batchVerifySortAscending = true;
    }
    sortBatchVerifyDataset();
}

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

function handleBatchVerifyRowsChange() {
    batchVerifyRowsPerPage = parseInt(document.getElementById("batch_verify_rows_per_page").value);
    batchVerifyCurrentPage = 1;
    renderBatchVerifyTable();
}

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

    tbody.innerHTML = pagedData.map((item, index) => {
        let badgeClass = "bg-success"; // VALID
        if (item.code === "ALTERED" || item.code === "INVALID") badgeClass = "bg-danger";
        else if (item.code === "UNSIGNED") badgeClass = "bg-warning text-dark";
        else if (item.code === "STRUCT_ERR") badgeClass = "bg-dark";

        return `
            <tr>
                <td class="text-center fw-bold text-secondary">${startIndex + index + 1}</td>
                <td>
                    <div class="d-flex align-items-center justify-content-between">
                        <span onclick="toggleFilenameExpand(this)" class="clickable-filename text-truncate fw-semibold me-2" style="max-width:320px;" title="Click xem tên file đầy đủ">${item.filename}</span>
                    </div>
                </td>
                <td><span class="badge ${badgeClass}">${item.status_text}</span></td>
                <td><span class="badge bg-light text-dark border"><i class="fa-solid fa-user me-1 text-muted"></i>${formatSignerChain(item.signer)}</span></td>
            </tr>`;
    }).join("");

    document.getElementById("batch_verify_pagination_info").innerText = `Hiển thị ${startIndex + 1} - ${endIndex} trong ${totalRecords} bản ghi`;

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

function changeBatchVerifyPage(pageTarget) {
    batchVerifyCurrentPage = pageTarget;
    renderBatchVerifyTable();
}

// Hàm cập nhật ảnh chữ ký trên Header của Bước 3
async function updateHeaderSignaturePreview() {
    const uid = document.getElementById("sign_uid").value;
    const imgEl = document.getElementById("header_signature_preview");
    if (!imgEl || !uid) return;

    try {
        const res = await fetch(`${API_BASE}/user/signature-preview/${encodeURIComponent(uid)}`);
        if (res.ok) {
            const blob = await res.blob();
            // Xóa object URL cũ khỏi bộ nhớ để tránh rò rỉ RAM (Memory Leak)
            if (imgEl.dataset.blobUrl) {
                URL.revokeObjectURL(imgEl.dataset.blobUrl);
            }
            const url = URL.createObjectURL(blob);
            imgEl.src = url;
            imgEl.dataset.blobUrl = url;
        } else {
            // Nếu lỗi 404 (chưa tải lên chữ ký), fallback về logo CTUT
            imgEl.src = "/static/images/logo_ctut.png";
        }
    } catch (e) {
        // Fallback khi mất mạng
        imgEl.src = "/static/images/logo_ctut.png";
    }
}
document.addEventListener("DOMContentLoaded", function() {
    const sigArea = document.getElementById("stamp_preview_sig_area");
    const textArea = document.getElementById("stamp_preview_text_area");
    
    if (sigArea && textArea) {
        // Ép CSS cột trái (Ảnh)
        sigArea.style.inset = "auto";
        sigArea.style.position = "absolute";
        sigArea.style.left = "0";
        sigArea.style.top = "0";
        sigArea.style.width = "55%";
        sigArea.style.height = "100%";
        sigArea.style.display = "flex";
        sigArea.style.alignItems = "center";
        sigArea.style.justifyContent = "center";
        
        // Ép CSS cột phải (Chữ)
        textArea.style.inset = "auto";
        textArea.style.position = "absolute";
        textArea.style.left = "55%";
        textArea.style.top = "0";
        textArea.style.width = "45%";
        textArea.style.height = "100%";
        textArea.style.display = "flex";
        textArea.style.flexDirection = "column";
        textArea.style.alignItems = "flex-start"; // Chữ thẳng lề trái
        textArea.style.justifyContent = "center";
        textArea.style.textAlign = "left"; // Căn trái
        textArea.style.paddingLeft = "5px"; // Hở 1 chút so với ảnh
    }
});