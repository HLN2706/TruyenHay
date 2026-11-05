"""
TruyenHay Lab - web doc truyen DUNG DE THU NGHIEM TAN CONG (SQLi, XSS, Brute Force,
DoS, Broken Access Control / dac quyen toi thieu ...) cho de tai
"Tang cuong phat hien tan cong dua tren hoc may / hoc sau".

!!! CANH BAO !!!
  - SECURITY_LEVEL=low  : CO CHU DICH chua nhieu lo hong. CHI chay trong may ao / mang noi bo.
  - SECURITY_LEVEL=high : ban da va (parameterized SQL, escape, CSRF, rate limit, lockout, RBAC ...).
  - Tuyet doi khong dua che do low len Internet.

Chay:
    set SECURITY_LEVEL=low   (hoac high)
    python app.py
"""
import csv
import io
import os
import re
import secrets
import time
from collections import defaultdict, deque
from functools import wraps
from urllib.parse import urlparse

import psycopg2
import psycopg2.extras
from flask import (
    Flask, Response, abort, flash, g, jsonify, redirect, render_template,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Cau hinh
# --------------------------------------------------------------------------- #
LEVEL = os.getenv("SECURITY_LEVEL", "low").lower()
if LEVEL not in ("low", "high"):
    LEVEL = "low"

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "truyenhay")
DB_CREDS = {
    "low": (os.getenv("DB_LOW_USER", "th_app_low"), os.getenv("DB_LOW_PASSWORD", "low_pass_123")),
    "high": (os.getenv("DB_HIGH_USER", "th_app_high"), os.getenv("DB_HIGH_PASSWORD", "high_pass_123")),
}

PER_PAGE = 8
MAX_FAILED_LOGINS = 5          # che do high: khoa sau 5 lan sai
LOCKOUT_SECONDS = 300          # trong 5 phut
RATE_LIMIT_REQUESTS = 60       # che do high: 60 request / 10 giay / IP
RATE_LIMIT_WINDOW = 10

app = Flask(__name__)
app.config["LEVEL"] = LEVEL
if LEVEL == "low":
    app.secret_key = "truyenhay"                 # yeu: co the brute-force / gia mao cookie session
    app.config.update(SESSION_COOKIE_HTTPONLY=False, SESSION_COOKIE_SAMESITE=None)
else:
    app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      PERMANENT_SESSION_LIFETIME=3600)


def is_low():
    return app.config["LEVEL"] == "low"


# --------------------------------------------------------------------------- #
# Database (PostgreSQL)
# --------------------------------------------------------------------------- #
def get_db():
    if "db" not in g:
        user, pwd = DB_CREDS[app.config["LEVEL"]]
        g.db = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
                                user=user, password=pwd, connect_timeout=5)
        g.db.autocommit = True
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def q_all(sql, params=None):
    cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        cur.close()


def q_one(sql, params=None):
    cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(sql, params)
        return cur.fetchone()
    finally:
        cur.close()


def q_exec(sql, params=None):
    cur = get_db().cursor()
    try:
        cur.execute(sql, params)
    finally:
        cur.close()


def db_msg(e):
    return (getattr(e, "pgerror", None) or str(e)).strip()


def to_int(v, default=1, lo=1, hi=10 ** 6):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Phien lam viec / phan quyen
# --------------------------------------------------------------------------- #
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    if "cur_user" not in g:
        g.cur_user = q_one("SELECT id, username, role, is_active, display_name FROM users WHERE id = %s", (uid,))
    return g.cur_user


def client_ip():
    return request.remote_addr or "?"


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        if not is_low():
            u = current_user()
            if not u or not u["is_active"]:
                session.clear()
                return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def role_required(*roles, low_check=True):
    """HIGH: kiem tra role that trong DB. LOW: chi doc role trong cookie session
    (va mot so route co tinh bo qua low_check de demo Broken Access Control)."""
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if is_low():
                if low_check and session.get("role") not in roles:
                    abort(403)
                return f(*a, **kw)
            u = current_user()
            if not u or not u["is_active"] or u["role"] not in roles:
                abort(403)
            return f(*a, **kw)
        return wrapper
    return deco


def is_safe_redirect(target):
    if not target:
        return False
    p = urlparse(target)
    return not p.netloc and not p.scheme and target.startswith("/") and not target.startswith("//")


# --------------------------------------------------------------------------- #
# CSRF + rate limit + header bao mat + access log
# --------------------------------------------------------------------------- #
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


_hits = defaultdict(deque)


def rate_limited(ip):
    now = time.time()
    dq = _hits[ip]
    while dq and now - dq[0] > RATE_LIMIT_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_REQUESTS:
        return True
    dq.append(now)
    return False


@app.before_request
def before():
    g.t0 = time.time()
    if request.endpoint == "static":
        return
    if not is_low():
        if rate_limited(client_ip()):
            return Response("429 Too Many Requests - vui long thu lai sau.", 429,
                            headers={"Retry-After": str(RATE_LIMIT_WINDOW)})
        if request.method == "POST" and not request.path.startswith("/api/"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "CSRF token khong hop le")


@app.after_request
def after(resp):
    if not is_low():
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
    if request.endpoint != "static":
        try:
            body = ""
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                data = request.form.to_dict() if request.form else (request.get_data(as_text=True) or "")
                if isinstance(data, dict):
                    data = {k: ("***" if "pass" in k.lower() else v) for k, v in data.items()
                            if k != "csrf_token"}
                body = str(data)[:2000]
            q_exec(
                "INSERT INTO access_logs (ip_address, method, path, query_string, body, user_agent, "
                "username, status_code, duration_ms, security_level) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (client_ip(), request.method, request.path[:2000], request.query_string.decode("utf-8", "replace")[:2000],
                 body, (request.user_agent.string or "")[:500], session.get("username"),
                 resp.status_code, int((time.time() - g.get("t0", time.time())) * 1000), app.config["LEVEL"]))
        except Exception:
            pass
    return resp


@app.context_processor
def inject():
    return dict(LOW=is_low(), LEVEL=app.config["LEVEL"], csrf_token=csrf_token)


@app.template_filter("num")
def num_filter(v):
    try:
        return "{:,}".format(int(v))
    except (TypeError, ValueError):
        return v if v is not None else 0


# --------------------------------------------------------------------------- #
# Xu ly loi
# --------------------------------------------------------------------------- #
@app.errorhandler(psycopg2.Error)
def on_db_error(e):
    if is_low():  # ro ri thong tin loi SQL -> error-based SQLi
        return render_template("error.html", code=500, title="Lỗi cơ sở dữ liệu", detail=db_msg(e)), 500
    app.logger.error("DB error: %s", db_msg(e))
    return render_template("error.html", code=500, title="Đã xảy ra lỗi", detail=None), 500


@app.errorhandler(403)
def e403(_e):
    return render_template("error.html", code=403, title="Bạn không có quyền truy cập", detail=None), 403


@app.errorhandler(404)
def e404(_e):
    return render_template("error.html", code=404, title="Không tìm thấy trang", detail=None), 404


@app.errorhandler(400)
def e400(e):
    return render_template("error.html", code=400, title="Yêu cầu không hợp lệ",
                           detail=getattr(e, "description", None)), 400


# --------------------------------------------------------------------------- #
# Trang chu / danh sach / chi tiet / doc chuong
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    hot = q_all("SELECT * FROM truyen ORDER BY views DESC LIMIT 4")
    latest_cmts = q_all(
        "SELECT c.*, t.title FROM comments c JOIN truyen t ON t.id = c.truyen_id "
        "ORDER BY c.id DESC LIMIT 5")
    cats = q_all("SELECT category, COUNT(*) AS n FROM truyen GROUP BY category ORDER BY n DESC")
    return render_template("index.html", truyen_list=hot, comments=latest_cmts, cats=cats)


@app.route("/truyen")
def truyen_list():
    q = request.args.get("q", "")
    category = request.args.get("category", "")
    sort = request.args.get("sort", "id")
    order = request.args.get("order", "asc")
    page = to_int(request.args.get("page", 1))
    error = None
    rows = []

    if is_low():
        # [SQLi] noi chuoi truc tiep: WHERE (UNION/boolean/time/error-based) va ORDER BY
        where = "WHERE 1=1"
        if q:
            where = f"WHERE (title ILIKE '%{q}%' OR author ILIKE '%{q}%' OR category ILIKE '%{q}%')"
        if category:
            where += f" AND category = '{category}'"
        sql = f"SELECT * FROM truyen {where} ORDER BY {sort} {order}"
        try:
            rows = q_all(sql)
        except psycopg2.Error as e:
            return render_template("truyen.html", truyen_list=[], query=q, category=category, sort=sort,
                                   order=order, page=1, pages=1, total=0, error=db_msg(e)), 400
    else:
        sort = sort if sort in ("id", "views", "title") else "id"
        order = "desc" if order == "desc" else "asc"
        sql = "SELECT * FROM truyen WHERE 1=1"
        params = []
        if q:
            sql += " AND (title ILIKE %s OR author ILIKE %s OR category ILIKE %s)"
            params += [f"%{q}%"] * 3
        if category:
            sql += " AND category = %s"
            params.append(category)
        sql += f" ORDER BY {sort} {order}"          # sort/order da qua whitelist
        rows = q_all(sql, params)

    total = len(rows)
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, pages)
    rows = rows[(page - 1) * PER_PAGE: page * PER_PAGE]
    cats = q_all("SELECT DISTINCT category FROM truyen ORDER BY category")
    return render_template("truyen.html", truyen_list=rows, query=q, category=category, sort=sort,
                           order=order, page=page, pages=pages, total=total, error=error, cats=cats)


@app.route("/truyen/<tid>", methods=["GET", "POST"])
def truyen_detail(tid):
    if request.method == "POST":
        return add_comment(tid)

    if is_low():
        try:   # [SQLi] id tren URL
            truyen = q_one(f"SELECT * FROM truyen WHERE id = {tid}")
        except psycopg2.Error as e:
            return f"Loi: {db_msg(e)}", 400
        if not truyen:
            abort(404)
        try:
            q_exec(f"UPDATE truyen SET views = views + 1 WHERE id = {tid}")
        except psycopg2.Error:
            pass
    else:
        if not tid.isdigit():
            abort(404)
        truyen = q_one("SELECT * FROM truyen WHERE id = %s", (int(tid),))
        if not truyen:
            abort(404)
        q_exec("UPDATE truyen SET views = views + 1 WHERE id = %s", (truyen["id"],))

    try:
        comments = q_all("SELECT * FROM comments WHERE truyen_id = %s ORDER BY id DESC", (truyen["id"],))
        rating = q_one("SELECT COALESCE(ROUND(AVG(score),1),0) AS avg, COUNT(*) AS n FROM ratings WHERE truyen_id = %s",
                       (truyen["id"],))
        chapters = q_all("SELECT chapter_no, title FROM chapters WHERE truyen_id = %s ORDER BY chapter_no",
                         (truyen["id"],))
        uid = session.get("user_id")
        bookmarked = bool(uid and q_one("SELECT 1 FROM bookmarks WHERE truyen_id=%s AND user_id=%s",
                                        (truyen["id"], uid)))
        my_score = None
        if uid:
            r = q_one("SELECT score FROM ratings WHERE truyen_id=%s AND user_id=%s", (truyen["id"], uid))
            my_score = r["score"] if r else None
    except psycopg2.Error:
        if not is_low():
            raise
        comments, rating, chapters, bookmarked, my_score = [], {"avg": 0, "n": 0}, [], False, None
    return render_template("truyen_detail.html", truyen=truyen, comments=comments, rating=rating,
                           chapters=chapters, bookmarked=bookmarked, my_score=my_score)


def add_comment(tid):
    content = request.form.get("content", "")
    uid = session.get("user_id")
    if is_low():
        # [Stored XSS + SQLi + gia mao nguoi dung]: ten tu form, khong can dang nhap
        username = request.form.get("username", "AnDanh")
        uid_sql = uid if uid else "NULL"
        sql = (f"INSERT INTO comments (truyen_id, user_id, username, content) "
               f"VALUES ({tid}, {uid_sql}, '{username}', '{content}')")
        try:
            q_exec(sql)
        except psycopg2.Error as e:
            flash(f"Lỗi: {db_msg(e)}", "error")
    else:
        if not uid:
            return redirect(url_for("login", next=request.path))
        content = content.strip()
        if not tid.isdigit() or not (1 <= len(content) <= 1000):
            flash("Bình luận không hợp lệ (1–1000 ký tự).", "error")
        else:
            u = current_user()
            q_exec("INSERT INTO comments (truyen_id, user_id, username, content) VALUES (%s,%s,%s,%s)",
                   (int(tid), u["id"], u["username"], content))
    return redirect(url_for("truyen_detail", tid=tid) + "#binh-luan")


@app.route("/truyen/<tid>/chapter/<n>")
def chapter(tid, n):
    if is_low():
        try:   # [SQLi]
            ch = q_one(f"SELECT * FROM chapters WHERE truyen_id = {tid} AND chapter_no = {n}")
        except psycopg2.Error as e:
            return f"Loi: {db_msg(e)}", 400
    else:
        if not (tid.isdigit() and n.isdigit()):
            abort(404)
        ch = q_one("SELECT * FROM chapters WHERE truyen_id = %s AND chapter_no = %s", (int(tid), int(n)))
    if not ch:
        abort(404)
    try:
        truyen = q_one("SELECT id, title FROM truyen WHERE id = %s", (ch["truyen_id"],))
        last = q_one("SELECT MAX(chapter_no) AS m FROM chapters WHERE truyen_id = %s", (ch["truyen_id"],))["m"]
    except psycopg2.Error:
        if not is_low():
            raise
        truyen, last = {"id": 0, "title": "?"}, 0
    return render_template("chapter.html", ch=ch, truyen=truyen, last=last or 0)


@app.route("/truyen/<int:tid>/rate", methods=["POST"])
@login_required
def rate(tid):
    score = to_int(request.form.get("score"), 0, 0, 5)
    if score < 1:
        flash("Điểm đánh giá phải từ 1 đến 5.", "error")
    else:
        q_exec("INSERT INTO ratings (truyen_id, user_id, score) VALUES (%s,%s,%s) "
               "ON CONFLICT (truyen_id, user_id) DO UPDATE SET score = EXCLUDED.score",
               (tid, session["user_id"], score))
        flash("Đã ghi nhận đánh giá.", "success")
    return redirect(url_for("truyen_detail", tid=tid))


@app.route("/truyen/<int:tid>/bookmark", methods=["POST"])
@login_required
def bookmark(tid):
    uid = session["user_id"]
    if q_one("SELECT 1 FROM bookmarks WHERE truyen_id=%s AND user_id=%s", (tid, uid)):
        q_exec("DELETE FROM bookmarks WHERE truyen_id=%s AND user_id=%s", (tid, uid))
        flash("Đã bỏ khỏi tủ truyện.", "success")
    else:
        q_exec("INSERT INTO bookmarks (truyen_id, user_id) VALUES (%s,%s)", (tid, uid))
        flash("Đã thêm vào tủ truyện.", "success")
    return redirect(url_for("truyen_detail", tid=tid))


@app.route("/bookmarks")
@login_required
def bookmarks():
    rows = q_all("SELECT t.* FROM bookmarks b JOIN truyen t ON t.id=b.truyen_id "
                 "WHERE b.user_id=%s ORDER BY b.created_at DESC", (session["user_id"],))
    return render_template("bookmarks.html", truyen_list=rows)


@app.route("/comments/<int:cid>/delete", methods=["POST"])
@login_required
def delete_comment(cid):
    c = q_one("SELECT * FROM comments WHERE id = %s", (cid,))
    if not c:
        abort(404)
    if not is_low():     # HIGH: chi chu comment hoac moderator/admin
        u = current_user()
        if c["user_id"] != u["id"] and u["role"] not in ("admin", "moderator"):
            abort(403)
    # LOW: bat ky ai dang nhap cung xoa duoc comment cua nguoi khac (IDOR)
    q_exec("DELETE FROM comments WHERE id = %s", (cid,))
    flash("Đã xóa bình luận.", "success")
    back = request.form.get("back", "")
    return redirect(back if is_safe_redirect(back) else url_for("truyen_detail", tid=c["truyen_id"]))


# --------------------------------------------------------------------------- #
# Xac thuc: dang ky / dang nhap / dang xuat
# --------------------------------------------------------------------------- #
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$")


def log_login(username, success):
    try:
        q_exec("INSERT INTO login_logs (username, ip_address, user_agent, success) VALUES (%s,%s,%s,%s)",
               ((username or "")[:200], client_ip(), (request.user_agent.string or "")[:500], success))
    except psycopg2.Error:
        pass


def is_locked_out(username):
    r = q_one(
        "SELECT COUNT(*) FILTER (WHERE username = %s) AS by_user, COUNT(*) AS by_ip FROM login_logs "
        "WHERE success = FALSE AND ip_address = %s AND login_time > NOW() - (%s || ' seconds')::interval",
        (username, client_ip(), str(LOCKOUT_SECONDS)))
    return r["by_user"] >= MAX_FAILED_LOGINS or r["by_ip"] >= MAX_FAILED_LOGINS * 4


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        if is_low():
            # [SQLi + luu mat khau plaintext + khong kiem tra do manh]
            h = generate_password_hash(password)
            sql = (f"INSERT INTO users (username, password, password_hash, email, display_name) "
                   f"VALUES ('{username}', '{password}', '{h}', '{email}', '{username}')")
            try:
                q_exec(sql)
                flash("Đăng ký thành công, hãy đăng nhập.", "success")
                return redirect(url_for("login"))
            except psycopg2.Error as e:
                error = f"Lỗi: {db_msg(e)}"
        else:
            if not USERNAME_RE.match(username):
                error = "Tên đăng nhập 3–30 ký tự: chữ, số, gạch dưới."
            elif not EMAIL_RE.match(email):
                error = "Email không hợp lệ."
            elif len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
                error = "Mật khẩu tối thiểu 8 ký tự, gồm cả chữ và số."
            elif q_one("SELECT 1 FROM users WHERE username = %s", (username,)):
                error = "Không thể đăng ký với thông tin này."
            else:
                q_exec("INSERT INTO users (username, password_hash, email, display_name, role) "
                       "VALUES (%s,%s,%s,%s,'user')",
                       (username, generate_password_hash(password), email, username))
                flash("Đăng ký thành công, hãy đăng nhập.", "success")
                return redirect(url_for("login"))
    return render_template("register.html", error=error), (400 if error else 200)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    nxt = request.values.get("next", "")
    status = 200
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = None

        if is_low():
            # [SQLi auth bypass] + [Brute force: khong gioi han] + [User enumeration]
            sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                user = q_one(sql)
                if not user:
                    exists = q_one(f"SELECT 1 FROM users WHERE username = '{username}'")
                    error = "Sai mật khẩu." if exists else "Tài khoản không tồn tại."
            except psycopg2.Error as e:
                error = f"Lỗi: {db_msg(e)}"
        else:
            if is_locked_out(username):
                log_login(username, False)
                return render_template("login.html", next=nxt,
                                       error=f"Quá nhiều lần thử sai. Vui lòng thử lại sau {LOCKOUT_SECONDS // 60} phút."), 429
            u = q_one("SELECT * FROM users WHERE username = %s", (username,))
            h = u["password_hash"] if u and u["password_hash"] else generate_password_hash("dummy")  # chong timing
            if check_password_hash(h, password) and u and u["is_active"]:
                user = u
            else:
                error = "Sai tên đăng nhập hoặc mật khẩu."   # thong bao chung

        log_login(username, bool(user))
        if user:
            if not is_low():
                session.clear()           # chong session fixation
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            if is_low():
                return redirect(nxt or url_for("index"))      # [Open redirect]
            return redirect(nxt if is_safe_redirect(nxt) else url_for("index"))
        status = 401
    return render_template("login.html", error=error, next=nxt), status


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# --------------------------------------------------------------------------- #
# Ho so nguoi dung
# --------------------------------------------------------------------------- #
@app.route("/profile")
@login_required
def my_profile():
    return redirect(url_for("profile", uid=session["user_id"]))


@app.route("/user/<uid>")
def profile(uid):
    if is_low():   # [IDOR + SQLi]: ai cung xem duoc, ke ca chua dang nhap
        try:
            u = q_one(f"SELECT * FROM users WHERE id = {uid}")
        except psycopg2.Error as e:
            return f"Loi: {db_msg(e)}", 400
    else:
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if not uid.isdigit():
            abort(404)
        me = current_user()
        if int(uid) != me["id"] and me["role"] != "admin":
            abort(403)
        u = q_one("SELECT * FROM users WHERE id = %s", (int(uid),))
    if not u:
        abort(404)
    try:
        marks = q_all("SELECT t.id, t.title FROM bookmarks b JOIN truyen t ON t.id=b.truyen_id WHERE b.user_id=%s",
                      (u["id"],))
        cmts = q_all("SELECT c.*, t.title FROM comments c JOIN truyen t ON t.id=c.truyen_id "
                     "WHERE c.user_id=%s ORDER BY c.id DESC LIMIT 10", (u["id"],))
    except psycopg2.Error:
        marks, cmts = [], []
    is_me = session.get("user_id") == u["id"]
    return render_template("profile.html", u=u, marks=marks, cmts=cmts, is_me=is_me)


@app.route("/profile/edit", methods=["POST"])
@login_required
def profile_edit():
    uid = session["user_id"]
    if is_low():
        # [Mass assignment -> leo thang dac quyen] chap nhan ca 'role', 'is_active' neu client gui len
        # [SQLi] gia tri noi chuoi
        allowed = {"email", "display_name", "bio", "role", "is_active"}
        sets = [f"{k} = '{v}'" for k, v in request.form.items() if k in allowed]
        if sets:
            try:
                q_exec(f"UPDATE users SET {', '.join(sets)} WHERE id = {uid}")
                r = q_one("SELECT role FROM users WHERE id = %s", (uid,))
                session["role"] = r["role"]
                flash("Đã cập nhật hồ sơ.", "success")
            except psycopg2.Error as e:
                flash(f"Lỗi: {db_msg(e)}", "error")
    else:
        email = request.form.get("email", "").strip()
        name = request.form.get("display_name", "").strip()[:80]
        bio = request.form.get("bio", "").strip()[:500]
        if email and not EMAIL_RE.match(email):
            flash("Email không hợp lệ.", "error")
        else:
            q_exec("UPDATE users SET email=%s, display_name=%s, bio=%s WHERE id=%s", (email, name, bio, uid))
            flash("Đã cập nhật hồ sơ.", "success")
    return redirect(url_for("profile", uid=uid))


@app.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    uid = session["user_id"]
    new = request.form.get("new_password", "")
    if is_low():
        # khong yeu cau mat khau cu, khong kiem tra do manh, luu plaintext
        try:
            q_exec(f"UPDATE users SET password = '{new}' WHERE id = {uid}")
            q_exec("UPDATE users SET password_hash = %s WHERE id = %s", (generate_password_hash(new), uid))
            flash("Đã đổi mật khẩu.", "success")
        except psycopg2.Error as e:
            flash(f"Lỗi: {db_msg(e)}", "error")
    else:
        u = q_one("SELECT password_hash FROM users WHERE id=%s", (uid,))
        if not check_password_hash(u["password_hash"], request.form.get("old_password", "")):
            flash("Mật khẩu hiện tại không đúng.", "error")
        elif len(new) < 8 or not re.search(r"[A-Za-z]", new) or not re.search(r"\d", new):
            flash("Mật khẩu mới tối thiểu 8 ký tự, gồm cả chữ và số.", "error")
        else:
            q_exec("UPDATE users SET password_hash=%s, password=NULL WHERE id=%s",
                   (generate_password_hash(new), uid))
            flash("Đã đổi mật khẩu.", "success")
    return redirect(url_for("profile", uid=uid))


# --------------------------------------------------------------------------- #
# API JSON
# --------------------------------------------------------------------------- #
def jsonable(rows):
    return [{k: (str(v) if hasattr(v, "isoformat") else v) for k, v in r.items()} for r in rows]


@app.route("/api/health")
def api_health():
    return jsonify(status="ok", level=app.config["LEVEL"])


@app.route("/api/truyen")
def api_truyen():
    q = request.args.get("q", "")
    try:
        if is_low():    # [SQLi]
            rows = q_all(f"SELECT id, title, author, category, views FROM truyen "
                         f"WHERE title ILIKE '%{q}%' OR author ILIKE '%{q}%'")
        else:
            rows = q_all("SELECT id, title, author, category, views FROM truyen "
                         "WHERE title ILIKE %s OR author ILIKE %s", (f"%{q}%", f"%{q}%"))
        return jsonify(jsonable(rows))
    except psycopg2.Error as e:
        return jsonify(error=db_msg(e) if is_low() else "Lỗi truy vấn"), 500


@app.route("/api/truyen/<tid>")
def api_truyen_one(tid):
    try:
        if is_low():
            row = q_one(f"SELECT id, title, author, category, views FROM truyen WHERE id = {tid}")
        else:
            if not tid.isdigit():
                return jsonify(error="not found"), 404
            row = q_one("SELECT id, title, author, category, views FROM truyen WHERE id = %s", (int(tid),))
        return (jsonify(jsonable([row])[0]) if row else (jsonify(error="not found"), 404))
    except psycopg2.Error as e:
        return jsonify(error=db_msg(e) if is_low() else "Lỗi truy vấn"), 500


@app.route("/api/admin/users")
def api_admin_users():
    # LOW: KHONG kiem tra dang nhap/quyen (Broken Access Control) -> lo ca mat khau plaintext
    if not is_low():
        u = current_user()
        if not u or u["role"] != "admin":
            return jsonify(error="forbidden"), 403
        rows = q_all("SELECT id, username, email, role, is_active, created_at FROM users ORDER BY id")
    else:
        rows = q_all("SELECT id, username, password, email, role, is_active, created_at FROM users ORDER BY id")
    return jsonify(jsonable(rows))


# --------------------------------------------------------------------------- #
# Khu quan tri
# --------------------------------------------------------------------------- #
@app.route("/admin")
@role_required("admin", "moderator")
def admin_dashboard():
    stats = q_one(
        "SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM truyen) AS truyen, "
        "(SELECT COUNT(*) FROM comments) AS comments, "
        "(SELECT COUNT(*) FROM login_logs WHERE success=FALSE AND login_time > NOW() - INTERVAL '24 hours') AS failed24, "
        "(SELECT COUNT(*) FROM access_logs WHERE ts > NOW() - INTERVAL '1 hour') AS req1h")
    failed = q_all("SELECT ip_address, COUNT(*) AS n FROM login_logs WHERE success=FALSE "
                   "AND login_time > NOW() - INTERVAL '24 hours' GROUP BY ip_address ORDER BY n DESC LIMIT 5")
    return render_template("admin/dashboard.html", stats=stats, failed=failed)


@app.route("/admin/users")
@role_required("admin")
def admin_users():
    return render_template("admin/users.html", users=q_all("SELECT * FROM users ORDER BY id"))


@app.route("/admin/users/<int:uid>/role", methods=["POST"])
@role_required("admin", low_check=False)     # LOW: thieu kiem tra quyen admin -> user thuong tu nang quyen
@login_required
def admin_set_role(uid):
    role = request.form.get("role", "user")
    if role not in ("user", "moderator", "admin"):
        abort(400)
    q_exec("UPDATE users SET role = %s WHERE id = %s", (role, uid))
    flash("Đã đổi vai trò.", "success")
    return redirect(url_for("admin_users") if session.get("role") == "admin" or not is_low() else url_for("index"))


@app.route("/admin/users/<int:uid>/toggle", methods=["GET", "POST"])
def admin_toggle_user(uid):
    if is_low():
        pass          # LOW: khong kiem tra quyen, cho phep ca GET (de bi CSRF / truy cap truc tiep)
    else:
        if request.method != "POST":
            abort(405)
        u = current_user()
        if not u or u["role"] != "admin":
            abort(403)
        if u["id"] == uid:
            abort(400, "Không thể tự khóa tài khoản của mình")
    q_exec("UPDATE users SET is_active = NOT is_active WHERE id = %s", (uid,))
    flash("Đã đổi trạng thái tài khoản.", "success")
    return redirect(url_for("admin_users") if session.get("role") == "admin" else url_for("index"))


@app.route("/admin/truyen")
@role_required("admin")
def admin_truyen():
    return render_template("admin/truyen.html", rows=q_all("SELECT * FROM truyen ORDER BY id"))


IMAGE_RE = re.compile(r"^[A-Za-z0-9_\-]+\.(jpg|jpeg|png|webp)$")


@app.route("/admin/truyen/new", methods=["GET", "POST"])
@app.route("/admin/truyen/<int:tid>/edit", methods=["GET", "POST"])
@role_required("admin")
def admin_truyen_form(tid=None):
    row = q_one("SELECT * FROM truyen WHERE id = %s", (tid,)) if tid else None
    if tid and not row:
        abort(404)
    if request.method == "POST":
        f = {k: request.form.get(k, "").strip() for k in ("title", "author", "category", "description", "image", "status")}
        if not f["title"] or len(f["title"]) > 200:
            flash("Tiêu đề không hợp lệ.", "error")
        elif f["image"] and not IMAGE_RE.match(f["image"]):
            flash("Tên file ảnh không hợp lệ.", "error")
        else:
            vals = (f["title"], f["author"], f["category"], f["description"], f["image"] or None,
                    f["status"] or "Đang ra")
            if tid:
                q_exec("UPDATE truyen SET title=%s, author=%s, category=%s, description=%s, image=%s, status=%s "
                       "WHERE id=%s", vals + (tid,))
            else:
                q_exec("INSERT INTO truyen (title, author, category, description, image, status) "
                       "VALUES (%s,%s,%s,%s,%s,%s)", vals)
            flash("Đã lưu truyện.", "success")
            return redirect(url_for("admin_truyen"))
    return render_template("admin/truyen_form.html", row=row)


@app.route("/admin/comments")
@role_required("admin", "moderator")
def admin_comments():
    rows = q_all("SELECT c.*, t.title FROM comments c JOIN truyen t ON t.id=c.truyen_id ORDER BY c.id DESC LIMIT 100")
    return render_template("admin/comments.html", rows=rows)


@app.route("/admin/logs")
@role_required("admin")
def admin_logs():
    kind = request.args.get("kind", "access")
    ip = request.args.get("ip", "").strip()
    page = to_int(request.args.get("page", 1))
    per = 50
    if kind == "login":
        table, tcol = "login_logs", "login_time"
    else:
        kind, table, tcol = "access", "access_logs", "ts"
    where, params = "", []
    if ip:
        where, params = "WHERE ip_address = %s", [ip]
    total = q_one(f"SELECT COUNT(*) AS n FROM {table} {where}", params)["n"]
    rows = q_all(f"SELECT * FROM {table} {where} ORDER BY id DESC LIMIT %s OFFSET %s",
                 params + [per, (page - 1) * per])
    pages = max(1, (total + per - 1) // per)
    return render_template("admin/logs.html", rows=rows, kind=kind, ip=ip, page=page, pages=pages, total=total)


@app.route("/admin/logs/label", methods=["POST"])
@role_required("admin")
def admin_logs_label():
    """Gan nhan cho cac request cua 1 IP trong khoang thoi gian -> tao dataset co nhan cho ML."""
    label = request.form.get("label", "").strip()
    ip = request.form.get("ip", "").strip()
    t_from, t_to = request.form.get("from", ""), request.form.get("to", "")
    if label not in ("normal", "sqli", "xss", "bruteforce", "dos", "other") or not ip or not t_from or not t_to:
        flash("Thiếu hoặc sai thông tin gán nhãn.", "error")
    else:
        try:
            cur = get_db().cursor()
            cur.execute("UPDATE access_logs SET label=%s WHERE ip_address=%s AND ts BETWEEN %s AND %s",
                        (label, ip, t_from, t_to))
            flash(f"Đã gán nhãn '{label}' cho {cur.rowcount} request.", "success")
            cur.close()
        except psycopg2.Error:
            flash("Khoảng thời gian không hợp lệ (định dạng YYYY-MM-DD HH:MM:SS).", "error")
    return redirect(url_for("admin_logs"))


def csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


@app.route("/admin/logs/export.csv")
@role_required("admin")
def admin_logs_export():
    rows = q_all("SELECT * FROM access_logs ORDER BY id LIMIT 100000")
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["id", "ts", "ip_address", "method", "path", "query_string", "body", "user_agent",
            "username", "status_code", "duration_ms", "security_level", "label"]
    w.writerow(cols)
    for r in rows:
        w.writerow([csv_safe(r[c]) for c in cols])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=access_logs.csv"})


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    print(f"[*] TruyenHay Lab - SECURITY_LEVEL = {LEVEL.upper()}")
    if LEVEL == "low":
        print("[!] Che do LOW co chu dich de bi tan cong - chi chay trong moi truong lab/co lap.")
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")),
            debug=False, threaded=True)
