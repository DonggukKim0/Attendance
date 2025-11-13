# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from datetime import datetime, date, time
from datetime import timedelta
import calendar
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

import os
from werkzeug.utils import secure_filename
import random  # <--- 새로 추가

app = Flask(__name__)
app.secret_key = "change-this-to-random-value"

BASE_DIR = Path(__file__).resolve().parent  # folder where app.py lives

AVATAR_DIR = BASE_DIR / "static" / "avatars"
AVATAR_DIR.mkdir(parents=True, exist_ok=True)

app.config["UPLOAD_FOLDER"] = AVATAR_DIR
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB 정도 제한

def get_db_path():
    # e.g. "attendance_2025_10.db"
    ym = datetime.now().strftime("%Y_%m")
    return BASE_DIR / f"attendance_{ym}.db"


def get_db():
    db_path = get_db_path()
    first_time = not db_path.exists()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # --- ensure board_messages table exists (monthly DB refresh by design) ---
    c_tmp = conn.cursor()
    c_tmp.execute(
        """
        CREATE TABLE IF NOT EXISTS board_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            created_at TEXT,
            content TEXT,
            like_count INTEGER DEFAULT 0,
            sad_count INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    # 기존 DB에 리액션 컬럼이 없을 수 있으므로, 실패는 무시하고 ALTER 시도
    try:
        c_tmp.execute("ALTER TABLE board_messages ADD COLUMN like_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        c_tmp.execute("ALTER TABLE board_messages ADD COLUMN sad_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    conn.commit()

    # Ensure attendance table has paused_seconds and pause_started_at columns
    try:
        c_tmp.execute("ALTER TABLE attendance ADD COLUMN paused_seconds INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        c_tmp.execute("ALTER TABLE attendance ADD COLUMN pause_started_at TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()

    if first_time:
        c = conn.cursor()

        # 1) 스키마 생성 (users / attendance 테이블)
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                is_admin INTEGER DEFAULT 0,
                status_msg TEXT,
                avatar_path TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                date TEXT,
                time_in TEXT,
                time_out TEXT,
                work_minutes INTEGER,
                paused_seconds INTEGER DEFAULT 0,
                pause_started_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        # 2) 직전 달 DB에서 users 복사 시도
        now_dt = datetime.now()
        cur_year = now_dt.year
        cur_month = now_dt.month
        if cur_month == 1:
            prev_year = cur_year - 1
            prev_month = 12
        else:
            prev_year = cur_year
            prev_month = cur_month - 1
        prev_ym = f"{prev_year}_{prev_month:02d}"
        prev_db_path = BASE_DIR / f"attendance_{prev_ym}.db"

        copied_any = False
        if prev_db_path.exists():
            src_conn = sqlite3.connect(prev_db_path)
            src_conn.row_factory = sqlite3.Row
            src_c = src_conn.cursor()
            try:
                src_c.execute(
                    "SELECT username, password, is_admin, status_msg, avatar_path FROM users"
                )
                rows = src_c.fetchall()
                for r in rows:
                    c.execute(
                        """
                        INSERT OR IGNORE INTO users (
                            username,
                            password,
                            is_admin,
                            status_msg,
                            avatar_path
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            r["username"],
                            r["password"],
                            r["is_admin"],
                            r["status_msg"],
                            r["avatar_path"],
                        ),
                    )
                if rows:
                    copied_any = True
            finally:
                src_conn.close()

        # 3) 직전 달 DB에서 아무도 못 가져온 경우: 기본 계정 시드
        if not copied_any:
            initial_users = [
                ("dongguk", "1234", 1),
                ("user1", "1111", 0),
                ("user2", "2222", 0),
                ("user3", "3333", 0),
                ("user4", "4444", 0),
                ("user5", "5555", 0),
            ]
            for u, p, admin_flag in initial_users:
                c.execute(
                    "INSERT OR IGNORE INTO users (username, password, is_admin, status_msg, avatar_path) VALUES (?, ?, ?, ?, ?)",
                    (u, p, admin_flag, None, None),
                )

        conn.commit()

    return conn

#############################################
# Lucky Event 전용 DB (lucky.db)
#############################################

LUCKY_DB_PATH = BASE_DIR / "lucky.db"

def get_lucky_db():
    """
    lucky.db에 연결하고, 없으면 생성 + 테이블 생성.
    테이블:
      picks(
        id INTEGER PK,
        date TEXT,
        user_id INTEGER,
        code TEXT,
        is_winner INTEGER DEFAULT 0,
        UNIQUE(date, user_id)
      )

      daily_draw(
        date TEXT PRIMARY KEY,
        winning_code TEXT,
        drawn_at TEXT
      )
    """
    first_time_lucky = not LUCKY_DB_PATH.exists()

    conn_l = sqlite3.connect(LUCKY_DB_PATH)
    conn_l.row_factory = sqlite3.Row
    c = conn_l.cursor()

    # picks 테이블
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS picks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            user_id INTEGER,
            code TEXT,
            is_winner INTEGER DEFAULT 0,
            UNIQUE(date, user_id)
        )
        """
    )

    # daily_draw 테이블
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_draw (
            date TEXT PRIMARY KEY,
            winning_code TEXT,
            drawn_at TEXT
        )
        """
    )

    conn_l.commit()
    return conn_l

def generate_random_winning_code():
    """
    1~5 사이에서 서로 다른 숫자 3개를 뽑아서 순서를 랜덤하게 섞은 뒤
    "a-b-c" 형태 문자열로 반환한다. 예: "2-5-1"
    """
    nums = [1, 2, 3, 4, 5]
    pick3 = random.sample(nums, 3)  # 예: [2,5,1]
    return f"{pick3[0]}-{pick3[1]}-{pick3[2]}"

def ensure_daily_draw(conn_lucky):
    """
    오늘 날짜에 대해 daily_draw 에 레코드가 있는지 확인하고,
    17:00 이후인데 winning_code 가 아직 없으면 뽑아서 확정 짓는다.

    이후 winners 업데이트:
      picks.code == winning_code 인 row 들은 is_winner=1 로 갱신.
    """
    today_str = date.today().isoformat()  # 'YYYY-MM-DD'
    now_hhmm = datetime.now().strftime("%H%M")  # '1704' 같은 문자열

    c = conn_lucky.cursor()

    # 오늘 daily_draw row 확보 (없으면 placeholder 생성)
    c.execute(
        "SELECT winning_code FROM daily_draw WHERE date=?",
        (today_str,)
    )
    row = c.fetchone()

    if row is None:
        c.execute(
            "INSERT INTO daily_draw(date, winning_code, drawn_at) VALUES (?, NULL, NULL)",
            (today_str,)
        )
        conn_lucky.commit()
        return

    winning_code = row["winning_code"]

    # 이미 추첨 완료된 경우
    if winning_code is not None and winning_code != "":
        return

    # 아직 미추첨이고, 17:00 이후면 추첨
    if now_hhmm >= "1700":
        draw_code = generate_random_winning_code()
        draw_time = datetime.now().strftime("%H:%M:%S")

        # daily_draw 업데이트
        c.execute(
            "UPDATE daily_draw SET winning_code=?, drawn_at=? WHERE date=?",
            (draw_code, draw_time, today_str)
        )

        # 당첨자들 is_winner=1
        c.execute(
            """
            UPDATE picks
            SET is_winner=1
            WHERE date=? AND code=?
            """,
            (today_str, draw_code)
        )
        conn_lucky.commit()

def get_today_lucky_info(conn_lucky, user_id):
    """
    대시보드/프로필에서 보여줄 정보를 한 번에 읽는다.
    반환 dict 예:
    {
      "my_code": "2-5-1" 또는 None,
      "my_win": True/False/None,
      "winning_code": "2-5-1" 또는 None,
      "winners_list": [user_id1, user_id2, ...]  # 오늘 당첨자 user_id 리스트
    }
    """
    today_str = date.today().isoformat()
    info = {
        "my_code": None,
        "my_win": None,
        "winning_code": None,
        "winners_list": [],
    }

    c = conn_lucky.cursor()

    # 내 pick
    c.execute(
        "SELECT code, is_winner FROM picks WHERE date=? AND user_id=?",
        (today_str, user_id)
    )
    r = c.fetchone()
    if r:
        info["my_code"] = r["code"]
        info["my_win"] = bool(r["is_winner"])

    # 오늘 winning_code
    c.execute(
        "SELECT winning_code FROM daily_draw WHERE date=?",
        (today_str,)
    )
    drow = c.fetchone()
    if drow:
        info["winning_code"] = drow["winning_code"]

    # 오늘 당첨자들(user_id만 가져온다)
    c.execute(
        "SELECT user_id FROM picks WHERE date=? AND is_winner=1",
        (today_str,)
    )
    wins = c.fetchall()
    info["winners_list"] = [w["user_id"] for w in wins]

    return info

def validate_lucky_numbers(n1, n2, n3):
    """
    사용자가 제출한 세 개의 숫자(n1,n2,n3)가 모두 '1'~'5' 범위인지,
    그리고 서로 다른지(중복 금지) 검사한다.
    유효하면 "a-b-c" 문자열을 반환하고,
    무효하면 None 을 반환한다.
    """
    nums = [n1, n2, n3]
    for v in nums:
        if v not in ["1", "2", "3", "4", "5"]:
            return None
    if len(set(nums)) != 3:
        return None
    return f"{nums[0]}-{nums[1]}-{nums[2]}"

#############################################
# 기존 기능들 (자동 퇴근 등)
#############################################

def get_active_user_ids_for_today(conn):
    """
    오늘 날짜 기준으로 time_out 이 아직 NULL 인 출근 레코드가 있는 user_id 들을 set 으로 반환한다.
    즉, '출근 찍고 아직 퇴근 안 한 사람들' = 현재 근무 중 (초록불)
    퇴근까지 끝난 사람은 이 set 에 안 들어감 (빨간불)
    """
    today = date.today().isoformat()
    c = conn.cursor()
    c.execute(
        """
        SELECT DISTINCT user_id
        FROM attendance
        WHERE date=? AND time_out IS NULL
        """,
        (today,)
    )
    rows = c.fetchall()
    active_ids = {r[0] for r in rows}
    return active_ids

def auto_close_old_open_shifts(conn):
    """
    어제(또는 그 이전 날) 출근만 찍고 퇴근(time_out)이 비어 있는 레코드를 자동으로 마감한다.
    time_out='23:59:59', work_minutes = time_in ~ 23:59:59 분.
    오늘의 열린 레코드는 건드리지 않는다.
    """
    cur_date = date.today().isoformat()
    c = conn.cursor()

    c.execute(
        """
        SELECT id, date, time_in
        FROM attendance
        WHERE time_out IS NULL
        AND date < ?
        """,
        (cur_date,)
    )
    rows = c.fetchall()

    for r in rows:
        rec_id = r["id"]
        t_in_str = r["time_in"]
        forced_out_str = "23:59:59"

        try:
            t_in_dt = datetime.strptime(t_in_str, "%H:%M:%S")
            t_out_dt = datetime.strptime(forced_out_str, "%H:%M:%S")
            delta_min = int((t_out_dt - t_in_dt).total_seconds() // 60)
            if delta_min < 0:
                delta_min = 0
        except Exception:
            delta_min = 0

        c.execute(
            """
            UPDATE attendance
            SET time_out=?, work_minutes=?
            WHERE id=?
            """,
            (forced_out_str, delta_min, rec_id)
        )

    if rows:
        conn.commit()

def hash_password(plain_password: str) -> str:
    return generate_password_hash(plain_password)

def verify_password(stored_password: str, provided_password: str) -> bool:
    if not stored_password:
        return False
    if stored_password.startswith("pbkdf2:") or "$" in stored_password:
        return check_password_hash(stored_password, provided_password)
    return stored_password == provided_password

# --- User ID resolver based on session username (stable across month DBs) ---
def get_current_user_id():
    """
    Resolve the current user's id from the *current month DB* using the session username.
    If the user row does not exist in this month's users table (e.g., new DB after month roll-over),
    create it on-the-fly to keep ids consistent for this month.
    Returns integer user_id or None if not logged in.
    """
    uname = session.get("username")
    if not uname:
        return None

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT id FROM users WHERE username=?", (uname,))
    row = c.fetchone()
    if row:
        uid = row[0]
        conn.close()
        return uid

    # If not found in this month's DB, insert a minimal user row (non-admin, no password change here)
    c.execute(
        "INSERT INTO users (username, password, is_admin, status_msg, avatar_path) VALUES (?, ?, ?, ?, ?)",
        (uname, None, 0, None, None)
    )
    conn.commit()
    uid = c.lastrowid
    conn.close()
    return uid

#############################################
# 라우트들
#############################################

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and verify_password(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            return redirect(url_for("dashboard"))
        else:
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    username = session["username"]
    today = date.today().isoformat()

    conn = get_db()
    c = conn.cursor()

    # 전날(또는 그 이전) 퇴근 안 찍은 기록 자동 마감
    auto_close_old_open_shifts(conn)

    # 오늘 출근했는데 퇴근 안 찍은거
    c.execute("""
        SELECT * FROM attendance
        WHERE user_id=? AND date=? AND time_out IS NULL
    """, (user_id, today))
    open_rec = c.fetchone()

    is_paused = False
    if open_rec and "pause_started_at" in open_rec.keys():
        is_paused = bool(open_rec["pause_started_at"])

    # 이번달 누적
    month_prefix = today[:7]  # YYYY-MM
    c.execute("""
        SELECT COALESCE(SUM(work_minutes), 0) AS total_min
        FROM attendance
        WHERE user_id=? AND date LIKE ?
    """, (user_id, month_prefix + "%"))
    total_min = c.fetchone()["total_min"]

    conn.close()

    hours = total_min // 60
    mins = total_min % 60

    # 이번주 누적 근무 시간 (월~일 기준)
    monday, sunday = get_week_range()
    week_data = collect_week_minutes_per_user(monday, sunday)

    week_total_min = 0
    for row in week_data:
        if row["username"] == username:
            week_total_min = row["week_minutes"]
            break

    week_hours = week_total_min // 60
    week_mins = week_total_min % 60

    # ----- Lucky info -----
    lconn = get_lucky_db()
    ensure_daily_draw(lconn)  # 17:00 이후면 추첨/당첨 반영
    lucky_info = get_today_lucky_info(lconn, user_id)
    lconn.close()

    return render_template(
        "dashboard.html",
        username=username,
        open_rec=open_rec,
        month_hours=hours,
        month_mins=mins,
        week_hours=week_hours,
        week_mins=week_mins,
        is_admin=session.get("is_admin", False),
        # lucky info
        my_lucky_code=lucky_info["my_code"],
        my_lucky_win=lucky_info["my_win"],
        winning_code_today=lucky_info["winning_code"],
        is_paused=is_paused,
    )

@app.route("/punch_form", methods=["GET"])
def punch_form():
    if "user_id" not in session:
        return redirect(url_for("login"))

    now_t = datetime.now().time()
    allow_lucky = now_t < time(17, 0)  # 5시 이전에만 lucky 입력 가능

    return render_template("punch_form.html", allow_lucky=allow_lucky)

@app.route("/punch_in", methods=["POST"])
def punch_in():
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    now_dt = datetime.now()
    today = now_dt.date().isoformat()
    now = now_dt.strftime("%H:%M:%S")
    allow_lucky = now_dt.time() < time(17, 0)  # 5시 이전에만 lucky 코드 유효

    lucky_code = None

    if allow_lucky:
        # 사용자가 제출한 lucky numbers (세 칸)
        n1 = request.form.get("n1", "").strip()
        n2 = request.form.get("n2", "").strip()
        n3 = request.form.get("n3", "").strip()

        lucky_code = validate_lucky_numbers(n1, n2, n3)
        if lucky_code is None:
            flash("형식이 올바르지 않습니다. 1~5에서 서로 다른 숫자 3개를 입력하세요.")
            return redirect(url_for("punch_form"))

    # 근태 DB에 출근 기록
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT id FROM attendance
        WHERE user_id=? AND date=? AND time_out IS NULL
        """,
        (user_id, today)
    )
    exists = c.fetchone()
    if not exists:
        c.execute(
            """
            INSERT INTO attendance (user_id, date, time_in)
            VALUES (?, ?, ?)
            """,
            (user_id, today, now)
        )
        conn.commit()
    conn.close()

    # lucky.db 에 오늘 pick 저장 (5시 이전에만)
    if lucky_code is not None:
        lconn = get_lucky_db()
        lc = lconn.cursor()
        lc.execute(
            """
            INSERT OR IGNORE INTO picks(date, user_id, code, is_winner)
            VALUES (?, ?, ?, 0)
            """,
            (today, user_id, lucky_code)
        )
        lconn.commit()
        lconn.close()
        flash("출근 완료! 오늘의 럭키 이벤트에 참여되었습니다.")
    else:
        flash("출근 완료! (오늘의 럭키 이벤트 참여 시간은 마감되었습니다.)")

    return redirect(url_for("dashboard"))

@app.route("/punch_out", methods=["POST"])
def punch_out():
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    today = date.today().isoformat()
    now = datetime.now().strftime("%H:%M:%S")

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM attendance
        WHERE user_id=? AND date=? AND time_out IS NULL
    """, (user_id, today))
    rec = c.fetchone()

    if rec:
        t_in = datetime.strptime(rec["time_in"], "%H:%M:%S")
        t_out = datetime.strptime(now, "%H:%M:%S")
        delta_min = int((t_out - t_in).total_seconds() // 60)
        # Subtract paused_seconds if present
        paused_sec = rec["paused_seconds"] if "paused_seconds" in rec.keys() and rec["paused_seconds"] is not None else 0
        paused_min = int(paused_sec // 60)
        work_minutes = delta_min - paused_min
        if work_minutes < 0:
            work_minutes = 0
        c.execute("""
            UPDATE attendance
            SET time_out=?, work_minutes=?
            WHERE id=?
        """, (now, work_minutes, rec["id"]))
        conn.commit()

    conn.close()
    return redirect(url_for("dashboard"))

@app.route("/admin")
def admin():
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    today = date.today().isoformat()
    month_prefix = today[:7]

    conn = get_db()
    c = conn.cursor()

    auto_close_old_open_shifts(conn)

    active_user_ids = get_active_user_ids_for_today(conn)

    c.execute(
        """
        SELECT u.id AS uid,
               u.username,
               COALESCE(SUM(a.work_minutes), 0) AS total_min
        FROM users u
        LEFT JOIN attendance a ON u.id = a.user_id AND a.date LIKE ?
        GROUP BY u.id
        ORDER BY u.username
        """,
        (month_prefix + "%",)
    )
    per_user = c.fetchall()

    c.execute(
        """
        SELECT a.date, u.username, a.time_in, a.time_out, a.work_minutes
        FROM attendance a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.date DESC, a.time_in DESC
        LIMIT 50
        """
    )
    recent = c.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        per_user=per_user,
        recent=recent,
        month=month_prefix,
        active_user_ids=active_user_ids,
    )

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_pw = request.form.get("current_password", "").strip()
        new_pw = request.form.get("new_password", "").strip()
        new_pw2 = request.form.get("new_password2", "").strip()

        if not new_pw:
            flash("새 비밀번호를 입력하세요.")
            return redirect(url_for("change_password"))
        if new_pw != new_pw2:
            flash("새 비밀번호 확인이 일치하지 않습니다.")
            return redirect(url_for("change_password"))

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (session.get("username"),))
        row = c.fetchone()
        if not row:
            conn.close()
            flash("사용자를 찾을 수 없습니다.")
            return redirect(url_for("change_password"))

        stored_pw = row["password"]
        if not verify_password(stored_pw, current_pw):
            conn.close()
            flash("현재 비밀번호가 올바르지 않습니다.")
            return redirect(url_for("change_password"))

        new_hashed = hash_password(new_pw)
        c.execute("UPDATE users SET password=? WHERE username=?", (new_hashed, session.get("username")))
        conn.commit()
        conn.close()

        flash("비밀번호가 변경되었습니다.")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

@app.route("/admin_reset/<username>", methods=["POST"])
def admin_reset(username):
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    default_pw = "1111"
    new_hashed = hash_password(default_pw)

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE username=?", (new_hashed, username))
    conn.commit()
    conn.close()

    flash(f"{username} 계정의 비밀번호를 {default_pw} 로 초기화했습니다.")
    return redirect(url_for("admin"))

@app.route("/admin_add_user", methods=["GET", "POST"])
def admin_add_user():
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        make_admin = request.form.get("is_admin", "0")

        if not username or not password:
            flash("아이디와 비밀번호를 입력하세요.")
            return redirect(url_for("admin_add_user"))

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                (username, hash_password(password), 1 if make_admin == "1" else 0)
            )
            conn.commit()
            flash(f"{username} 계정을 추가했습니다.")
        except sqlite3.IntegrityError:
            flash("이미 존재하는 사용자입니다.")
        finally:
            conn.close()

        return redirect(url_for("admin"))

    return render_template("add_user.html")


@app.route("/admin_delete_user/<username>", methods=["POST"])
def admin_delete_user(username):
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT is_admin FROM users WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash(f"{username} 계정을 찾을 수 없습니다.")
        return redirect(url_for("admin"))
    if row["is_admin"]:
        conn.close()
        flash("관리자 계정은 삭제할 수 없습니다.")
        return redirect(url_for("admin"))

    # attendance 까지 삭제하려면 여기에 DELETE FROM attendance ... 넣을 수 있음
    c.execute("DELETE FROM users WHERE username=?", (username,))

    conn.commit()
    conn.close()

    flash(f"{username} 계정을 완전히 삭제했습니다.")
    return redirect(url_for("admin"))

# ---- Admin force checkout route ----
@app.route("/admin/force_checkout/<int:user_id>", methods=["POST"])
def admin_force_checkout(user_id):
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    today = date.today().isoformat()
    now = datetime.now().strftime("%H:%M:%S")

    conn = get_db()
    c = conn.cursor()

    # 오늘 미체크아웃(열린) 기록 하나를 찾아 강제 퇴근 처리
    c.execute(
        """
        SELECT id, time_in
        FROM attendance
        WHERE user_id=? AND date=? AND time_out IS NULL
        ORDER BY id DESC
        LIMIT 1
        """,
        (user_id, today)
    )
    rec = c.fetchone()

    if rec:
        try:
            t_in = datetime.strptime(rec[1], "%H:%M:%S")
            t_out = datetime.strptime(now, "%H:%M:%S")
            delta_min = int((t_out - t_in).total_seconds() // 60)
            if delta_min < 0:
                delta_min = 0
        except Exception:
            delta_min = 0

        c.execute(
            """
            UPDATE attendance
            SET time_out=?, work_minutes=?
            WHERE id=?
            """,
            (now, delta_min, rec[0])
        )
        conn.commit()
        flash("해당 사용자를 퇴근 처리했습니다.")
    else:
        flash("해당 사용자의 오늘 열린 근무 기록이 없습니다.")

    conn.close()
    return redirect(url_for("admin"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        password2 = request.form.get("password2", "").strip()

        if not username or not password:
            flash("아이디와 비밀번호를 입력하세요.")
            return redirect(url_for("register"))

        if password != password2:
            flash("비밀번호 확인이 일치하지 않습니다.")
            return redirect(url_for("register"))

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
                (username, hash_password(password))
            )
            conn.commit()
            flash("회원가입이 완료되었습니다. 이제 로그인하세요.")
        except sqlite3.IntegrityError:
            flash("이미 존재하는 아이디입니다.")
        finally:
            conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------------- Board routes (chat-like guestbook) ----------------------
@app.route("/board", methods=["GET"])
def board():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    # 최근 200개 메시지를 시간순(오래된→최신)으로 보여줌
    c.execute(
        """
        SELECT bm.id,
               bm.created_at,
               bm.content,
               u.username,
               u.avatar_path,
               COALESCE(bm.like_count, 0) AS like_count,
               COALESCE(bm.sad_count, 0) AS sad_count
        FROM board_messages bm
        JOIN users u ON bm.user_id = u.id
        ORDER BY bm.id ASC
        LIMIT 200
        """
    )
    messages = c.fetchall()
    conn.close()

    return render_template("board.html", messages=messages)

@app.route("/board/post", methods=["POST"])
def board_post():
    if "user_id" not in session:
        return redirect(url_for("login"))

    uid = get_current_user_id()
    if not uid:
        return redirect(url_for("login"))

    content = (request.form.get("content", "") or "").strip()
    # 간단한 길이 제한 (이모지/멀티바이트 감안해 여유)
    if not content:
        flash("메시지를 입력하세요.")
        return redirect(url_for("board"))
    if len(content) > 280:
        flash("메시지는 280자 이내로 작성해주세요.")
        return redirect(url_for("board"))

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO board_messages (user_id, created_at, content)
        VALUES (?, ?, ?)
        """,
        (uid, created_at, content)
    )
    conn.commit()
    conn.close()

    return redirect(url_for("board"))


# --- Board message reaction route ---
@app.route("/board/react", methods=["POST"])
def board_react():
    if "user_id" not in session:
        return redirect(url_for("login"))

    uid = get_current_user_id()
    if not uid:
        return redirect(url_for("login"))

    msg_id = request.form.get("message_id", type=int)
    kind = request.form.get("kind", "").strip()

    if not msg_id or kind not in ("like", "sad"):
        return redirect(url_for("board"))

    conn = get_db()
    c = conn.cursor()
    if kind == "like":
        c.execute(
            "UPDATE board_messages SET like_count = COALESCE(like_count, 0) + 1 WHERE id=?",
            (msg_id,)
        )
    else:
        c.execute(
            "UPDATE board_messages SET sad_count = COALESCE(sad_count, 0) + 1 WHERE id=?",
            (msg_id,)
        )
    conn.commit()
    conn.close()

    return redirect(url_for("board"))


@app.route("/profiles")
def profiles():
    if "user_id" not in session:
        return redirect(url_for("login"))

    today_str = date.today().isoformat()

    conn = get_db()
    c = conn.cursor()

    auto_close_old_open_shifts(conn)

    # 전체 유저
    c.execute(
        """
        SELECT id, username, status_msg, avatar_path
        FROM users
        ORDER BY username
        """
    )
    raw_people = c.fetchall()

    # 오늘 근무중(아직 퇴근 안 한) 사람들
    active_user_ids = get_active_user_ids_for_today(conn)

    # 일시정지 중인 사람들
    c.execute(
        """
        SELECT DISTINCT user_id
        FROM attendance
        WHERE date=? AND time_out IS NULL AND pause_started_at IS NOT NULL
        """,
        (today_str,)
    )
    paused_rows = c.fetchall()
    paused_user_ids = {r[0] for r in paused_rows}

    # id -> username 매핑 (당첨자 이름 보여줄때 필요)
    id_to_username = {u["id"]: u["username"] for u in raw_people}

    people = []
    for u in raw_people:
        uid = u["id"]

        # 오늘 완료된 근무시간
        c.execute(
            """
            SELECT COALESCE(SUM(work_minutes), 0) AS done_min
            FROM attendance
            WHERE user_id=? AND date=? AND time_out IS NOT NULL
            """,
            (uid, today_str)
        )
        done_row = c.fetchone()
        done_min = done_row["done_min"] if done_row else 0

        # 아직 진행중이면 현재까지 경과시간 추가
        c.execute(
            """
            SELECT time_in, paused_seconds, pause_started_at
            FROM attendance
            WHERE user_id=? AND date=? AND time_out IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (uid, today_str)
        )
        open_row = c.fetchone()

        extra_min = 0
        if open_row:
            t_in_str = open_row["time_in"]
            paused_sec = open_row["paused_seconds"] if "paused_seconds" in open_row.keys() and open_row["paused_seconds"] is not None else 0
            pause_started_at = open_row["pause_started_at"] if "pause_started_at" in open_row.keys() else None
            try:
                t_in_dt = datetime.strptime(t_in_str, "%H:%M:%S")
                now_dt = datetime.now()
                elapsed_sec = (now_dt - now_dt.replace(hour=t_in_dt.hour,
                                                       minute=t_in_dt.minute,
                                                       second=t_in_dt.second,
                                                       microsecond=0)).total_seconds()
                # If currently paused, add current pause to paused_sec
                if pause_started_at:
                    try:
                        pause_start_dt = datetime.strptime(pause_started_at, "%H:%M:%S")
                        now_sec = now_dt.hour * 3600 + now_dt.minute * 60 + now_dt.second
                        pause_start_sec = pause_start_dt.hour * 3600 + pause_start_dt.minute * 60 + pause_start_dt.second
                        extra_paused = now_sec - pause_start_sec
                        if extra_paused > 0:
                            paused_sec += extra_paused
                    except Exception:
                        pass
                elapsed_min = int((elapsed_sec - paused_sec) // 60)
                if elapsed_min < 0:
                    elapsed_min = 0
                extra_min = elapsed_min
            except Exception:
                extra_min = 0

        today_minutes = done_min + extra_min

        # 오늘 하루 진행률 (8시간=480분 기준)
        full_day_min = 8 * 60
        progress_ratio = today_minutes / full_day_min if full_day_min > 0 else 0
        if progress_ratio > 1:
            progress_ratio = 1
        progress_percent = int(progress_ratio * 100)

        people.append({
            "id": uid,
            "username": u["username"],
            "status_msg": u["status_msg"],
            "avatar_path": u["avatar_path"],
            "today_minutes": today_minutes,
            "today_hours": today_minutes // 60,
            "today_mins": today_minutes % 60,
            "progress_percent": progress_percent,
        })

    conn.close()

    # Lucky info for team banner
    lconn = get_lucky_db()
    ensure_daily_draw(lconn)
    cur_uid = get_current_user_id()
    lucky_info_for_profiles = get_today_lucky_info(lconn, cur_uid if cur_uid else 0)

    winner_usernames = []
    for uid in lucky_info_for_profiles["winners_list"]:
        if uid in id_to_username:
            winner_usernames.append(id_to_username[uid])

    lconn.close()

    return render_template(
        "profiles.html",
        people=people,
        active_user_ids=active_user_ids,
        paused_user_ids=paused_user_ids,
        winning_code_today=lucky_info_for_profiles["winning_code"],
        winner_usernames=winner_usernames,
    )

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    uid = session["user_id"]

    if request.method == "POST":
        new_msg = request.form.get("status_msg", "").strip()
        avatar_file = request.files.get("avatar")

        avatar_path_to_save = None

        if avatar_file and avatar_file.filename:
            fname_original = avatar_file.filename
            fname_secure = secure_filename(fname_original)

            save_path = AVATAR_DIR / fname_secure
            avatar_file.save(save_path)

            avatar_path_to_save = f"static/avatars/{fname_secure}"

        conn = get_db()
        c = conn.cursor()

        if avatar_path_to_save:
            c.execute(
                "UPDATE users SET status_msg=?, avatar_path=? WHERE id=?",
                (new_msg, avatar_path_to_save, uid)
            )
        else:
            c.execute(
                "UPDATE users SET status_msg=? WHERE id=?",
                (new_msg, uid)
            )

        conn.commit()
        conn.close()

        flash("프로필이 업데이트되었습니다.")
        return redirect(url_for("profiles"))

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT username, status_msg, avatar_path FROM users WHERE id=?",
        (uid,)
    )
    me = c.fetchone()
    conn.close()

    return render_template("edit_profile.html", me=me)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

#############################################
# 월간 / 주간 통계 유틸 & 라우트 (기존)
#############################################

def get_month_range(target_date=None):
    if target_date is None:
        target_date = datetime.now().date()

    first_day = target_date.replace(day=1)
    last_day_num = calendar.monthrange(first_day.year, first_day.month)[1]
    last_day = target_date.replace(day=last_day_num)

    label = f"{first_day.strftime('%Y-%m-%d')} ~ {last_day.strftime('%Y-%m-%d')}"
    return first_day, last_day, label

def count_business_days(start_date, end_date):
    d = start_date
    cnt = 0
    while d <= end_date:
        if d.weekday() < 5:  # 월(0)~금(4)
            cnt += 1
        d += timedelta(days=1)
    return cnt

def collect_monthly_stats(month_start, month_end):
    ym = month_start.strftime("%Y_%m")
    db_path = BASE_DIR / f"attendance_{ym}.db"

    results = []
    if not db_path.exists():
        return results, 0

    biz_days = count_business_days(month_start, month_end)
    month_target_minutes = biz_days * 8 * 60
    month_target_hours = biz_days * 8

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    auto_close_old_open_shifts(conn)

    c.execute(
        """
        SELECT u.username,
               u.avatar_path,
               SUM(COALESCE(a.work_minutes, 0)) AS total_minutes
        FROM attendance a
        JOIN users u ON a.user_id = u.id
        WHERE a.date BETWEEN ? AND ?
        GROUP BY u.username, u.avatar_path
        ORDER BY total_minutes DESC
        """,
        (month_start.strftime("%Y-%m-%d"), month_end.strftime("%Y-%m-%d"))
    )
    rows = c.fetchall()
    conn.close()

    for r in rows:
        total_minutes = r["total_minutes"] or 0
        h = total_minutes // 60
        m = total_minutes % 60

        if month_target_minutes > 0:
            pct = (total_minutes / month_target_minutes) * 100.0
        else:
            pct = 0.0

        capped_pct = pct if pct < 100 else 100
        overwork = (pct > 100)

        results.append({
            "username": r["username"],
            "avatar_path": r["avatar_path"],
            "month_hours": h,
            "month_mins": m,
            "track_percent": round(capped_pct, 2),
            "overwork": overwork,
        })

    return results, month_target_hours

def get_week_range(today=None):
    if today is None:
        today = date.today()
    monday = today - timedelta(days=today.weekday())  # Mon=0
    sunday = monday + timedelta(days=6)
    return monday, sunday

def collect_week_minutes_per_user(monday: date, sunday: date):
    monday_str = monday.isoformat()
    sunday_str = sunday.isoformat()

    ym_keys = set()
    cur_day = monday
    while cur_day <= sunday:
        ym_keys.add(cur_day.strftime("%Y_%m"))
        cur_day += timedelta(days=1)

    per_user_minutes = {}
    user_meta = {}

    for ym in ym_keys:
        db_path = BASE_DIR / f"attendance_{ym}.db"
        if not db_path.exists():
            continue

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute(
            """
            SELECT u.username AS username,
                   COALESCE(SUM(a.work_minutes),0) AS total_min
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            WHERE a.date >= ? AND a.date <= ?
            GROUP BY u.username
            """,
            (monday_str, sunday_str)
        )
        rows = c.fetchall()
        for r in rows:
            uname = r["username"]
            tmin = r["total_min"] if r["total_min"] else 0
            per_user_minutes[uname] = per_user_minutes.get(uname, 0) + tmin

        c.execute(
            """
            SELECT username, status_msg, avatar_path
            FROM users
            """
        )
        urows = c.fetchall()
        for ur in urows:
            uname = ur["username"]
            if uname not in user_meta:
                user_meta[uname] = {
                    "status_msg": ur["status_msg"],
                    "avatar_path": ur["avatar_path"],
                }

        conn.close()

    week_data = []
    FULL_WEEK_MIN = 40 * 60  # 40시간

    for uname, total_min in per_user_minutes.items():
        hours = total_min // 60
        mins = total_min % 60

        ratio = total_min / FULL_WEEK_MIN if FULL_WEEK_MIN > 0 else 0
        if ratio > 1:
            ratio = 1
        percent = int(ratio * 100)

        meta = user_meta.get(uname, {
            "status_msg": None,
            "avatar_path": None,
        })

        week_data.append({
            "id": uname,
            "username": uname,
            "status_msg": meta["status_msg"],
            "avatar_path": meta["avatar_path"],
            "week_minutes": total_min,
            "week_hours": hours,
            "week_mins": mins,
            "track_percent": percent,
            "overwork": (total_min > FULL_WEEK_MIN),
        })

    week_data.sort(key=lambda x: x["username"].lower())
    return week_data

@app.route("/weekly")
def weekly():
    if "user_id" not in session:
        return redirect(url_for("login"))

    monday, sunday = get_week_range()

    ym_keys = set()
    cur_day = monday
    while cur_day <= sunday:
        ym_keys.add(cur_day.strftime("%Y_%m"))
        cur_day += timedelta(days=1)

    for ym in ym_keys:
        db_path = BASE_DIR / f"attendance_{ym}.db"
        if not db_path.exists():
            continue
        tmp_conn = sqlite3.connect(db_path)
        tmp_conn.row_factory = sqlite3.Row
        auto_close_old_open_shifts(tmp_conn)
        tmp_conn.close()

    week_data = collect_week_minutes_per_user(monday, sunday)

    week_range_label = f"{monday.isoformat()} ~ {sunday.isoformat()}"

    return render_template(
        "weekly.html",
        week_data=week_data,
        week_range_label=week_range_label,
    )

@app.route("/monthly")
def monthly():
    if "user_id" not in session:
        return redirect(url_for("login"))

    month_start, month_end, month_label = get_month_range()

    month_data, month_target_hours = collect_monthly_stats(month_start, month_end)

    total_team_minutes = sum(
        u["month_hours"] * 60 + u["month_mins"] for u in month_data
    )
    team_h = total_team_minutes // 60
    team_m = total_team_minutes % 60

    top_user = month_data[0] if len(month_data) > 0 else None

    return render_template(
        "monthly.html",
        month_range_label=month_label,
        month_data=month_data,
        team_total_hours=team_h,
        team_total_mins=team_m,
        top_user=top_user,
        month_target_hours=month_target_hours,
    )


# ---------------------- API: Monthly work per day (JSON) ----------------------
@app.route('/api_monthly_work')
def api_monthly_work():
    """Return JSON of {day: minutes} for the logged-in user's selected month.
    Query params: year=YYYY, month=MM (1-12)
    Includes confirmed (work_minutes) + today's in-progress time if applicable.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    try:
        y = int(request.args.get('year', date.today().year))
        m = int(request.args.get('month', date.today().month))
    except Exception:
        y, m = date.today().year, date.today().month

    # Guard values
    if m < 1 or m > 12:
        return jsonify({'error': 'bad_request'}), 400

    db_name = f"attendance_{y:04d}_{m:02d}.db"
    db_path = BASE_DIR / db_name
    minutes = {}

    if db_path.exists():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # 1) Sum confirmed work_minutes per date for this user
        c.execute(
            """
            SELECT date, SUM(work_minutes) AS mins
            FROM attendance
            WHERE user_id=?
            GROUP BY date
            """,
            (session['user_id'],)
        )
        for r in c.fetchall():
            dstr = r['date']
            if not dstr:
                continue
            try:
                day = int(dstr.split('-')[2])
            except Exception:
                continue
            minutes[day] = int(r['mins'] or 0)

        # 2) If today belongs to this month and user is currently clocked in, add live elapsed
        today = date.today()
        if today.year == y and today.month == m:
            c.execute(
                """
                SELECT time_in, paused_seconds, pause_started_at
                FROM attendance
                WHERE user_id=? AND date=? AND time_out IS NULL
                ORDER BY id DESC LIMIT 1
                """,
                (session['user_id'], today.isoformat())
            )
            rec = c.fetchone()
            if rec and rec['time_in']:
                try:
                    t_in = datetime.strptime(rec['time_in'], '%H:%M:%S')
                    now = datetime.now()
                    elapsed_sec = (now - now.replace(hour=t_in.hour, minute=t_in.minute, second=t_in.second, microsecond=0)).total_seconds()
                    paused_sec = rec['paused_seconds'] if 'paused_seconds' in rec.keys() and rec['paused_seconds'] is not None else 0
                    pause_started_at = rec['pause_started_at'] if 'pause_started_at' in rec.keys() else None
                    # If currently paused, add current pause to paused_sec
                    if pause_started_at:
                        try:
                            pause_start_dt = datetime.strptime(pause_started_at, "%H:%M:%S")
                            now_sec = now.hour * 3600 + now.minute * 60 + now.second
                            pause_start_sec = pause_start_dt.hour * 3600 + pause_start_dt.minute * 60 + pause_start_dt.second
                            extra_paused = now_sec - pause_start_sec
                            if extra_paused > 0:
                                paused_sec += extra_paused
                        except Exception:
                            pass
                    elapsed = int((elapsed_sec - paused_sec) // 60)
                    if elapsed < 0:
                        elapsed = 0
                    minutes[today.day] = minutes.get(today.day, 0) + elapsed
                except Exception:
                    pass


        conn.close()

    return jsonify({'year': y, 'month': m, 'minutes': minutes})


# ---------------- Pause/Resume routes -----------------

@app.route("/pause", methods=["POST"])
def pause():
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    today = date.today().isoformat()
    now = datetime.now().strftime("%H:%M:%S")
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id, pause_started_at
        FROM attendance
        WHERE user_id=? AND date=? AND time_out IS NULL
        ORDER BY id DESC LIMIT 1
    """, (user_id, today))
    rec = c.fetchone()
    if rec and not rec["pause_started_at"]:
        c.execute(
            "UPDATE attendance SET pause_started_at=? WHERE id=?",
            (now, rec["id"])
        )
        conn.commit()
        flash("근무가 일시정지되었습니다.")
    elif rec and rec["pause_started_at"]:
        flash("이미 일시정지 중입니다.")
    else:
        flash("진행 중인 근무 기록이 없습니다.")
    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/resume", methods=["POST"])
def resume():
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    today = date.today().isoformat()
    now_dt = datetime.now()
    now_str = now_dt.strftime("%H:%M:%S")
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id, pause_started_at, paused_seconds
        FROM attendance
        WHERE user_id=? AND date=? AND time_out IS NULL AND pause_started_at IS NOT NULL
        ORDER BY id DESC LIMIT 1
    """, (user_id, today))
    rec = c.fetchone()
    if rec and rec["pause_started_at"]:
        try:
            pause_start_dt = datetime.strptime(rec["pause_started_at"], "%H:%M:%S")
            now_sec = now_dt.hour * 3600 + now_dt.minute * 60 + now_dt.second
            pause_start_sec = pause_start_dt.hour * 3600 + pause_start_dt.minute * 60 + pause_start_dt.second
            elapsed = now_sec - pause_start_sec
            if elapsed < 0:
                elapsed = 0
        except Exception:
            elapsed = 0
        prev_paused = rec["paused_seconds"] if rec["paused_seconds"] is not None else 0
        total_paused = prev_paused + elapsed
        c.execute(
            "UPDATE attendance SET paused_seconds=?, pause_started_at=NULL WHERE id=?",
            (total_paused, rec["id"])
        )
        conn.commit()
        flash("근무가 재개되었습니다.")
    else:
        flash("일시정지 중인 근무 기록이 없습니다.")
    conn.close()
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    # 0.0.0.0 으로 열어야 다른 PC에서 접속 가능
    app.run(host="0.0.0.0", port=5001, debug=False)