<<<<<<< HEAD
# TruyenHay Lab — môi trường thử nghiệm tấn công web

Phiên bản lab của trang TruyenHay, dùng cho đề tài *"Tăng cường phát hiện tấn công
(SQLi, XSS, DoS, Brute Force) dựa trên học máy / học sâu"*.

Có **hai chế độ bật/tắt bằng biến môi trường**, dùng chung một bộ giao diện:

| Chế độ | Biến `SECURITY_LEVEL` | Mục đích |
|---|---|---|
| **LOW**  | `low`  | **Cố ý** chứa lỗ hổng (SQLi, XSS, Brute Force, IDOR, CSRF, đặc quyền dư thừa...) để bạn tấn công, quan sát, sinh log |
| **HIGH** | `high` | Bản đã vá cùng một tính năng, dùng để đối chiếu / kiểm tra bộ phát hiện có báo đúng hay không |

> ⚠️ **CẢNH BÁO**: chế độ `low` có lỗ hổng thật trên dữ liệu thật (PostgreSQL). Chỉ chạy
> trong máy ảo / mạng nội bộ cô lập, không public ra Internet, không dùng dữ liệu/mật khẩu thật.

---

## 1. Cài đặt PostgreSQL (pgAdmin)

1. Cài PostgreSQL (đã có sẵn pgAdmin đi kèm nếu dùng bộ cài PostgreSQL cho Windows/Mac).
2. Mở pgAdmin, kết nối tới server PostgreSQL bằng tài khoản `postgres` bạn đã đặt khi cài.
3. Không cần tạo database thủ công — script `init_db.py` ở bước 3 sẽ tự tạo.

## 2. Cài Python và thư viện

```bash
cd truyenhay
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac
pip install -r requirements.txt
```

## 3. Khởi tạo database

Đặt thông tin tài khoản quản trị PostgreSQL của bạn qua biến môi trường rồi chạy script:

```bash
set PG_ADMIN_USER=postgres
set PG_ADMIN_PASSWORD=mat_khau_cua_ban
python init_db.py
```

Script sẽ:
- Tạo database `truyenhay` (nếu chưa có).
- Tạo **2 role ứng dụng** để minh hoạ "đặc quyền tối thiểu":
  - `th_app_low` — quyền rộng (ALL trên mọi bảng) → dùng cho chế độ LOW.
  - `th_app_high` — quyền tối thiểu (không đọc được bảng `secret_notes`, không `DELETE`
    `users`/`truyen`...) → dùng cho chế độ HIGH.
- Tạo lại toàn bộ bảng + dữ liệu mẫu (**XOÁ dữ liệu cũ** nếu chạy lại).
- In ra tài khoản mẫu: `admin/admin@123`, `hieu/hieu@123`, `mod/mod@123`, `hai/hai@123`, `duy/duy@123`, `thanh/thanh@123`.

Có thể xem toàn bộ bảng/role vừa tạo trong pgAdmin (Databases → truyenhay → Schemas → public → Tables,
và Login/Group Roles).

## 4. Chạy ứng dụng

**Chế độ LOW (có lỗ hổng):**
```bash
set SECURITY_LEVEL=low
python app.py
```

**Chế độ HIGH (đã vá):**
```bash
set SECURITY_LEVEL=high
python app.py
```

Mặc định chạy ở `http://127.0.0.1:5000`. Có thể đổi bằng biến `HOST`, `PORT`.

Các biến môi trường khác (có giá trị mặc định sẵn, chỉ cần đổi nếu bạn đặt mật khẩu khác lúc
`init_db.py`): `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_LOW_USER`, `DB_LOW_PASSWORD`,
`DB_HIGH_USER`, `DB_HIGH_PASSWORD`, `SECRET_KEY` (chỉ dùng ở chế độ HIGH).

---

## 5. Tính năng đã thêm so với bản gốc

- Đăng ký tài khoản, đổi mật khẩu, sửa hồ sơ (bio, tên hiển thị).
- Chương truyện (đọc theo từng chương, điều hướng chương trước/sau).
- Đánh giá sao, lưu vào "Tủ truyện" (bookmark).
- Lọc/sắp xếp danh sách truyện theo thể loại, lượt xem, tên; phân trang.
- Khu quản trị: tổng quan thống kê, quản lý người dùng (đổi vai trò, khoá/mở khoá),
  quản lý truyện (thêm/sửa), kiểm duyệt bình luận.
- **Nhật ký truy cập (`access_logs`) ghi lại mọi request** (IP, method, path, query, body,
  user-agent, mã trạng thái, thời gian xử lý) — dùng làm nguồn dữ liệu cho mô hình phát hiện.
- Trang **Admin → Nhật ký**: xem/lọc theo IP, **gán nhãn thủ công** (`normal` / `sqli` / `xss` /
  `bruteforce` / `dos` / `other`) cho các request trong một khoảng thời gian + IP, và **xuất CSV**
  để huấn luyện mô hình ML/DL.
- API JSON (`/api/truyen`, `/api/truyen/<id>`, `/api/admin/users`) — cũng có lỗi ở chế độ LOW.

---

## 6. Danh sách lỗ hổng cố ý ở chế độ LOW (và cách HIGH vá)

| # | Lỗ hổng | Vị trí (LOW) | Cách vá (HIGH) |
|---|---|---|---|
| 1 | SQL Injection (UNION/boolean/error-based) | Tìm kiếm `/truyen?q=`, `/truyen?sort=`, `/truyen/<id>`, `/truyen/<id>/chapter/<n>`, `/login`, `/register`, `/profile/*`, `/api/truyen*`, bình luận | Câu lệnh tham số hoá (`%s`), ép kiểu `int`, whitelist cột `sort`/`order` |
| 2 | Reflected / Stored XSS | Ô tìm kiếm hiển thị lại (`\|safe`), nội dung bình luận, tên hiển thị, bio | Bỏ `\|safe`, dựa vào auto-escape của Jinja2 |
| 3 | Brute force đăng nhập | `/login` không giới hạn số lần thử, không khoá tài khoản | Khoá sau 5 lần sai / IP trong 5 phút, thông báo lỗi chung chung, so sánh hash chống timing attack |
| 4 | Lộ thông tin qua thông báo lỗi | Lỗi SQL hiển thị thẳng ra trang | HIGH chỉ ghi log phía server, trả lỗi chung |
| 5 | User enumeration | "Tài khoản không tồn tại" vs "Sai mật khẩu" | Một thông báo chung cho mọi trường hợp |
| 6 | Mật khẩu lưu dạng plaintext | Cột `password` trong `users` | HIGH chỉ dùng `password_hash` (Werkzeug `generate_password_hash`) |
| 7 | IDOR (Broken Object-Level Access Control) | `/user/<id>` xem hồ sơ bất kỳ không cần đăng nhập; xoá bình luận của người khác | Kiểm tra chủ sở hữu / vai trò trước khi cho xem/sửa/xoá |
| 8 | Đặc quyền dư thừa / leo thang quyền (Mass Assignment) | `/profile/edit` chấp nhận field `role`, `is_active` từ client | HIGH chỉ cho cập nhật các field an toàn (email, tên, bio) |
| 9 | Thiếu kiểm soát truy cập theo vai trò (RBAC) | `/admin/users/<id>/role`, `/admin/users/<id>/toggle` không kiểm tra vai trò admin thật trong DB, cookie `role` quyết định tất cả | HIGH luôn truy vấn vai trò thật từ DB, không tin cookie |
| 10 | Thiếu bảo vệ CSRF | Mọi form POST không có token | HIGH kiểm tra `csrf_token` trên mọi POST |
| 11 | Secret key yếu / cookie dễ giả mạo | `app.secret_key = "truyenhay"`, cookie không `HttpOnly` | HIGH dùng khoá ngẫu nhiên 32 byte, cookie `HttpOnly` + `SameSite=Lax` |
| 12 | Open Redirect | Tham số `next` dùng thẳng để redirect sau đăng nhập | HIGH chỉ chấp nhận đường dẫn nội bộ (`is_safe_redirect`) |
| 13 | Database least privilege | `th_app_low` có quyền `ALL` trên mọi bảng, kể cả `secret_notes` | `th_app_high` chỉ có quyền tối thiểu cần thiết, không đọc được `secret_notes` |
| 14 | Thiếu header bảo mật / rate limit (nền DoS) | Không có CSP, không giới hạn số request | HIGH có CSP/X-Frame-Options/nosniff + giới hạn 60 request/10 giây/IP (HTTP 429) |
| 15 | CSV Injection khi xuất log | — | `/admin/logs/export.csv` luôn escape ký tự `= + - @` ở đầu ô, kể cả 2 chế độ |

---

## 7. Hướng dẫn test thủ công (không có script tự động tấn công đi kèm)

Lưu ý: repo này **không** đi kèm script tự động sinh traffic tấn công (brute force/DoS...) vì
các script như vậy có thể bị dùng sai mục đích ngoài phạm vi lab. Bạn tự thực hiện các bước dưới
đây bằng trình duyệt, `curl`, hoặc công cụ pentest tiêu chuẩn (Burp Suite, OWASP ZAP) — những công
cụ này có sẵn cơ chế giới hạn tốc độ và ghi log phù hợp cho mục đích học thuật.

### 7.1 SQL Injection

Ở chế độ LOW:

- Tìm kiếm với: `' UNION SELECT id,name,value,'c','d','i',1,'s',NOW() FROM secret_notes--`
  trong ô tìm kiếm `/truyen` → thấy được nội dung bảng `secret_notes` (dữ liệu "nhạy cảm" giả lập).
- Đăng nhập với username: `admin'--` và mật khẩu bất kỳ → đăng nhập được vào tài khoản admin
  mà không cần biết mật khẩu.
- So sánh: thử lại y hệt ở chế độ HIGH → không còn tác dụng, lỗi hoặc đăng nhập thất bại bình thường.

### 7.2 XSS (Cross-Site Scripting)

- Gửi bình luận với nội dung: `<img src=x onerror=alert(document.cookie)>` ở `/truyen/1`
  (chế độ LOW) → mã JavaScript thực thi khi người khác xem trang.
- Thử lại ở chế độ HIGH → nội dung hiển thị dạng text thuần (đã escape), không thực thi.

### 7.3 Brute Force

- Ở chế độ LOW, dùng Burp Intruder (hoặc gửi nhiều request `curl -X POST .../login` thủ công/
  bằng vòng lặp đơn giản tự viết, tần suất thấp, chỉ nhắm vào server lab của chính bạn) với danh
  sách mật khẩu phổ biến cho tài khoản `hieu` → không bị khoá, có thể thử vô hạn lần.
- Ở chế độ HIGH, lặp lại → sau 5 lần sai liên tiếp từ cùng IP, tài khoản bị khoá 5 phút (HTTP 429),
  kể cả khi sau đó nhập đúng mật khẩu.
- Xem `/admin/logs?kind=login` (đăng nhập bằng `admin`) để thấy toàn bộ lịch sử thử đăng nhập theo IP.

### 7.4 Đặc quyền tối thiểu (Least Privilege / Broken Access Control)

- Đăng nhập tài khoản `thanh` (role `user`) ở chế độ LOW, gọi `GET /admin/users/3/toggle` trực
  tiếp trên thanh địa chỉ trình duyệt → khoá được tài khoản người khác dù không có quyền admin.
- Thử sửa hồ sơ (`/profile/edit`) và chèn thêm field `role=admin` bằng Burp/`curl -d` → tài khoản
  tự nâng quyền thành admin.
- Mức cơ sở dữ liệu: đăng nhập pgAdmin bằng role `th_app_low` → có thể `SELECT`/`DELETE` trên
  mọi bảng kể cả `secret_notes`; đăng nhập bằng `th_app_high` → bị từ chối quyền trên `secret_notes`
  và không `DELETE` được `users`/`truyen` — minh hoạ nguyên tắc đặc quyền tối thiểu ở tầng DB.
- Lặp lại tất cả ở chế độ HIGH → các hành vi trên đều bị chặn (403/không đổi được field `role`).

### 7.5 DoS (từ chối dịch vụ)

- Dùng công cụ benchmark tiêu chuẩn đã có sẵn trên hệ thống của bạn (ví dụ `ab` — Apache Bench,
  hoặc `wrk`) nhắm vào `http://127.0.0.1:5000/` ở **chế độ HIGH** để quan sát cơ chế giới hạn:
  ```bash
  ab -n 500 -c 20 http://127.0.0.1:5000/truyen
  ```
  Bạn sẽ thấy một phần request trả về `429 Too Many Requests` sau khi vượt ngưỡng 60 request/10
  giây/IP, trong khi ở chế độ LOW không có giới hạn này.

### 7.6 Thu thập dữ liệu cho mô hình phát hiện

1. Thực hiện các kịch bản 7.1–7.5 (và cả truy cập bình thường) trong một khoảng thời gian.
2. Đăng nhập admin → **Admin → Nhật ký** → lọc theo IP, xem các request vừa gửi.
3. Dùng form "Gán nhãn cho dataset ML" để gán nhãn (`sqli`, `xss`, `bruteforce`, `dos`, `normal`...)
   theo IP + khoảng thời gian tương ứng với từng đợt bạn vừa thử.
4. Nhấn **Xuất CSV** để tải `access_logs.csv` làm tập dữ liệu huấn luyện/đánh giá mô hình.

---

## 8. Cấu trúc thư mục

```
truyenhay/
├── app.py            # Flask app (hành vi rẽ theo SECURITY_LEVEL=low|high)
├── init_db.py         # Khởi tạo PostgreSQL: bảng, role, dữ liệu mẫu
├── requirements.txt
├── static/
│   ├── style.css
│   └── images/*.jpg
└── templates/
    ├── base.html, index.html, truyen.html, truyen_detail.html, chapter.html,
    │   login.html, register.html, profile.html, bookmarks.html, error.html
    └── admin/        # dashboard, users, truyen, truyen_form, comments, logs
```

