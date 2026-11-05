"""
Khoi tao database PostgreSQL cho TruyenHay Lab.

Chay bang tai khoan co quyen tao DB/role (vi du: postgres):

    set PG_ADMIN_USER=postgres
    set PG_ADMIN_PASSWORD=mat_khau_postgres
    python init_db.py

Script se:
  1. Tao database `truyenhay` neu chua co (hoac tao thu cong trong pgAdmin).
  2. Tao 2 role ung dung de demo "dac quyen toi thieu":
       th_app_low  : quyen rong (ALL tren moi bang)    -> dung cho che do LOW
       th_app_high : quyen toi thieu, khong doc duoc bang secret_notes,
                     khong DELETE users/truyen          -> dung cho che do HIGH
  3. Tao lai toan bo bang + du lieu mau (XOA du lieu cu!).
"""
import os
import sys

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from werkzeug.security import generate_password_hash

HOST = os.getenv("DB_HOST", "127.0.0.1")
PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "truyenhay")
ADMIN_USER = os.getenv("PG_ADMIN_USER", "postgres")
ADMIN_PASSWORD = os.getenv("PG_ADMIN_PASSWORD", "postgres")

LOW_USER = os.getenv("DB_LOW_USER", "th_app_low")
LOW_PASSWORD = os.getenv("DB_LOW_PASSWORD", "low_pass_123")
HIGH_USER = os.getenv("DB_HIGH_USER", "th_app_high")
HIGH_PASSWORD = os.getenv("DB_HIGH_PASSWORD", "high_pass_123")


SCHEMA = """
DROP TABLE IF EXISTS access_logs, login_logs, bookmarks, ratings, comments,
                     chapters, truyen, secret_notes, users CASCADE;

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50) UNIQUE NOT NULL,
    password      TEXT,                       -- plaintext: chi dung o che do LOW (co chu dich)
    password_hash TEXT,                       -- hash: dung o che do HIGH
    email         VARCHAR(120),
    display_name  VARCHAR(80),
    bio           TEXT DEFAULT '',
    role          VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE truyen (
    id          SERIAL PRIMARY KEY,
    title       VARCHAR(200) NOT NULL,
    author      VARCHAR(120),
    category    VARCHAR(60),
    description TEXT,
    image       VARCHAR(120),
    views       INTEGER NOT NULL DEFAULT 0,
    status      VARCHAR(30) NOT NULL DEFAULT 'Đang ra',
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE chapters (
    id         SERIAL PRIMARY KEY,
    truyen_id  INTEGER NOT NULL REFERENCES truyen(id) ON DELETE CASCADE,
    chapter_no INTEGER NOT NULL,
    title      VARCHAR(200),
    content    TEXT,
    UNIQUE (truyen_id, chapter_no)
);

CREATE TABLE comments (
    id         SERIAL PRIMARY KEY,
    truyen_id  INTEGER NOT NULL REFERENCES truyen(id) ON DELETE CASCADE,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username   VARCHAR(80),
    content    TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE ratings (
    id        SERIAL PRIMARY KEY,
    truyen_id INTEGER NOT NULL REFERENCES truyen(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score     INTEGER NOT NULL CHECK (score BETWEEN 1 AND 5),
    UNIQUE (truyen_id, user_id)
);

CREATE TABLE bookmarks (
    id         SERIAL PRIMARY KEY,
    truyen_id  INTEGER NOT NULL REFERENCES truyen(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (truyen_id, user_id)
);

CREATE TABLE login_logs (
    id         SERIAL PRIMARY KEY,
    username   VARCHAR(200),
    ip_address VARCHAR(64),
    user_agent TEXT,
    success    BOOLEAN,
    login_time TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Nhat ky request: dung lam dataset cho mo hinh phat hien tan cong (ML/DL)
CREATE TABLE access_logs (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address  VARCHAR(64),
    method      VARCHAR(10),
    path        TEXT,
    query_string TEXT,
    body        TEXT,
    user_agent  TEXT,
    username    VARCHAR(80),
    status_code INTEGER,
    duration_ms INTEGER,
    security_level VARCHAR(10),
    label       VARCHAR(30) DEFAULT NULL   -- gan nhan thu cong: normal/sqli/xss/bruteforce/dos
);

CREATE INDEX idx_access_logs_ts ON access_logs(ts);
CREATE INDEX idx_login_logs_time ON login_logs(login_time);

-- Bang nhay cam: o che do HIGH role th_app_high KHONG duoc doc bang nay
CREATE TABLE secret_notes (
    id    SERIAL PRIMARY KEY,
    name  VARCHAR(80),
    value TEXT
);
"""

USERS = [
    ("admin", "admin@123", "admin@truyenhay.local", "Quản trị viên", "admin"),
    ("hieu", "hieu@123", "hieu@truyenhay.local", "Hiếu", "user"),
    ("hai", "hai@123", "hai@truyenhay.local", "Hải", "user"),
    ("duy", "duy@123", "duy@truyenhay.local", "Duy", "user"),
    ("thanh", "thanh@123", "thanh@truyenhay.local", "Thanh", "user"),
    ("mod", "mod@123", "mod@truyenhay.local", "Kiểm duyệt viên", "moderator"),
]

TRUYEN = [
    ("Tiên Nghịch", "Nhĩ Căn", "Tiên Hiệp",
     "Tiểu thuyết “Tiên Nghịch” của tác giả Nhĩ Căn, kể về thiếu niên bình phàm Vương Lâm xuất thân nông thôn, "
     "mang theo nhiệt huyết, tu luyện nghịch tiên, không chỉ cầu trường sinh mà còn muốn thoát khỏi thân phận giun dế. "
     "Hắn tin rằng đạo do người quyết định, dùng tư chất bình phàm bước vào con đường tu chân, từng bước lên đỉnh cao, "
     "danh chấn Tu chân giới.",
     "tien_nghich.jpg", 24124, "Hoàn thành"),
    ("Phàm Nhân Tu Tiên", "Vong Ngữ", "Tiên Hiệp",
     "Hàn Lập, một thiếu niên xuất thân bần hàn, tình cờ bước vào con đường tu tiên đầy chông gai. Không có tiên căn, "
     "không có kỳ ngộ lớn lao, chỉ có sự cẩn thận và kiên trì đưa hắn đi đến đỉnh cao.",
     "pham_nhan_tu_tien.jpg", 22412, "Hoàn thành"),
    ("Quang Âm Chi Ngoại", "Nhĩ Căn", "Tiên Hiệp",
     "Trời đất là quán trọ của muôn vật và chúng sinh, thời gian là kẻ qua đường của xưa và nay. Gương mặt tàn khuyết "
     "mở ra con mắt quỷ dị, nơi ánh nhìn chiếu tới thì sinh linh lầm than, biến thành vùng cấm vĩnh hằng. Thiếu niên "
     "Hứa Thanh vì sinh tồn mà tiến bước bằng sự tàn nhẫn và quyết liệt.",
     "quang_am_chi_ngoai.jpg", 19284, "Đang ra"),
    ("Thôn Phệ Tinh Không", "Ngã Cật Tây Hồng Thị", "Hiện Đại",
     "Thế giới xuất hiện loại virus RR không rõ lai lịch, động vật nhiễm bệnh đột biến thành quái thú xâm lược. Loài "
     "người xây tường bao, lập căn cứ làm pháo đài cuối cùng. La Phong năm 18 tuổi ước mơ trở thành chiến binh bảo vệ "
     "người mình yêu thương, từng bước khai quật tiềm năng của bản thân giữa tận thế.",
     "thon_phe_tinh_khong.jpg", 18903, "Hoàn thành"),
    ("Mục Thần Ký", "Trạch Trư", "Tiên Hiệp",
     "Trong Đại Khư Tàn Lão Thôn, nơi cư ngụ của chín vị lão nhân bí ẩn, có một thiếu niên tên Tần Mục do họ nuôi dưỡng "
     "từ nhỏ. Dù đối diện với bao hiểm nguy, Tần Mục vẫn không hề nao núng, lĩnh hội tất cả những gì chín vị lão truyền "
     "dạy, lấy thân bá thể mà khai phá một vùng trời riêng.",
     "muc_than_ky.jpg", 16903, "Đang ra"),
    ("Thương Nguyên Đồ", "Ngã Cật Tây Hồng Thị", "Huyền Huyễn",
     "Yêu tà hoành hành ở Thương Nguyên giới, loài người chịu đủ tàn phá. Nam chính Mạnh Xuyên từ nhỏ đã lập lời thề "
     "báo thù cho mẫu thân. Lấy đạo viện Kính Hồ làm khởi điểm, hắn tiêu diệt yêu tộc, đăng đỉnh tứ đại đạo viện, "
     "nổi danh Đông Minh phủ, trở thành một Thần Ma.",
     "thuong_nguyen_do.jpg", 15460, "Đang ra"),
]

CHAPTER_TEXT = (
    "Đây là nội dung mẫu dùng cho môi trường thử nghiệm.\n\n"
    "Gió đêm thổi qua đỉnh núi, mang theo hơi lạnh của sương sớm. Nhân vật chính đứng lặng bên vách đá, "
    "ánh mắt nhìn xa xăm về phía chân trời, nơi những đám mây đang dần tan ra nhường chỗ cho ánh bình minh.\n\n"
    "Con đường phía trước còn rất dài, nhưng chỉ cần bước đi từng bước vững chắc thì sẽ có ngày đến đích."
)

COMMENTS = [
    (1, "hieu", "Truyện hay quá, đọc không dứt ra được!"),
    (1, "hai", "Vương Lâm đúng là nhân vật để đời."),
    (2, "duy", "Hàn Lập cẩn thận nhất giới tu tiên :D"),
    (3, "thanh", "Mong tác giả ra chương đều."),
    (4, "hieu", "Mở đầu tận thế rất cuốn."),
    (5, "hai", "Bò mẹ biết nói là chi tiết tuyệt vời."),
]


def connect(dbname):
    conn = psycopg2.connect(host=HOST, port=PORT, dbname=dbname,
                            user=ADMIN_USER, password=ADMIN_PASSWORD)
    return conn


def ensure_database():
    conn = connect("postgres")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
    if not cur.fetchone():
        cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DB_NAME)))
        print(f"[+] Da tao database {DB_NAME}")
    for user, pwd in ((LOW_USER, LOW_PASSWORD), (HIGH_USER, HIGH_PASSWORD)):
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (user,))
        if cur.fetchone():
            cur.execute(sql.SQL("ALTER ROLE {} LOGIN PASSWORD %s").format(sql.Identifier(user)), (pwd,))
        else:
            cur.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(sql.Identifier(user)), (pwd,))
            print(f"[+] Da tao role {user}")
        cur.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(DB_NAME), sql.Identifier(user)))
    conn.close()


def grants(cur):
    low, high = sql.Identifier(LOW_USER), sql.Identifier(HIGH_USER)
    cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}, {}").format(low, high))

    # LOW: quyen rong (cố ý) - van KHONG phai superuser, khong the DROP bang vi khong phai owner
    cur.execute(sql.SQL("GRANT ALL ON ALL TABLES IN SCHEMA public TO {}").format(low))
    cur.execute(sql.SQL("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {}").format(low))

    # HIGH: dac quyen toi thieu
    cur.execute(sql.SQL(
        "GRANT SELECT ON truyen, chapters, comments, ratings, bookmarks, users, login_logs, access_logs TO {}"
    ).format(high))
    cur.execute(sql.SQL(
        "GRANT INSERT ON truyen, chapters, comments, ratings, bookmarks, users, login_logs, access_logs TO {}"
    ).format(high))
    cur.execute(sql.SQL("GRANT UPDATE ON truyen, chapters, users, ratings, comments, access_logs TO {}").format(high))
    cur.execute(sql.SQL("GRANT DELETE ON comments, bookmarks TO {}").format(high))
    cur.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(high))
    # Khong co: secret_notes, DELETE users/truyen/logs, DDL


def main():
    try:
        ensure_database()
    except psycopg2.Error as e:
        print("[!] Khong ket noi duoc PostgreSQL:", e)
        print("    Kiem tra PG_ADMIN_USER / PG_ADMIN_PASSWORD / DB_HOST / DB_PORT")
        sys.exit(1)

    conn = connect(DB_NAME)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(SCHEMA)

    for username, pwd, email, name, role in USERS:
        cur.execute(
            "INSERT INTO users (username, password, password_hash, email, display_name, role) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (username, pwd, generate_password_hash(pwd), email, name, role),
        )

    for t in TRUYEN:
        cur.execute(
            "INSERT INTO truyen (title, author, category, description, image, views, status) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id", t)
        tid = cur.fetchone()[0]
        for n in range(1, 6):
            cur.execute(
                "INSERT INTO chapters (truyen_id, chapter_no, title, content) VALUES (%s,%s,%s,%s)",
                (tid, n, f"Chương {n}", CHAPTER_TEXT))

    for tid, uname, content in COMMENTS:
        cur.execute("SELECT id FROM users WHERE username=%s", (uname,))
        uid = cur.fetchone()[0]
        cur.execute("INSERT INTO comments (truyen_id, user_id, username, content) VALUES (%s,%s,%s,%s)",
                    (tid, uid, uname, content))

    cur.execute("INSERT INTO ratings (truyen_id, user_id, score) VALUES (1,2,5),(1,3,4),(2,4,5),(3,5,4),(5,2,5)")
    cur.execute("INSERT INTO bookmarks (truyen_id, user_id) VALUES (1,2),(2,2),(3,3)")

    cur.execute(
        "INSERT INTO secret_notes (name, value) VALUES "
        "('flag_sqli', 'FLAG{union_based_sqli_ok}'),"
        "('internal_api_key', 'sk_live_truyenhay_0123456789'),"
        "('db_backup_password', 'backup@2026')")

    grants(cur)
    conn.close()

    print("[OK] Khoi tao database thanh cong.")
    print(f"     LOW  role : {LOW_USER}")
    print(f"     HIGH role : {HIGH_USER}")
    print("     Tai khoan mau: admin/admin@123, hieu/hieu@123, mod/mod@123 ...")


if __name__ == "__main__":
    main()
