# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime, date
from datetime import timedelta
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

import os
from werkzeug.utils import secure_filename

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

    if first_time:
        c = conn.cursor()
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
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        # 기본 유저가 비어있다면 초기 유저 세팅 (dongguk/admin 등)
        # 이 로직은 새 달로 넘어갔을 때도 동일하게 사용자 목록을 복사하기 위함
        # 기존 달의 DB에서 유저 정보를 가져와 복사 시도
        # 1) 가장 최근 DB를 찾는다
        existing_dbs = sorted(BASE_DIR.glob("attendance_*.db"))
        if existing_dbs:
            # 마지막(가장 최신) DB에서 users를 읽어와서 현재 DB에 넣는다
            last_db = existing_dbs[-1]
            # 자기 자신일 수도 있으니 체크
            if last_db != db_path:
                src_conn = sqlite3.connect(last_db)
                src_conn.row_factory = sqlite3.Row
                src_c = src_conn.cursor()
                src_c.execute("SELECT username, password, is_admin, status_msg, avatar_path FROM users")
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
                            r.get("status_msg") if hasattr(r, "get") else r["status_msg"] if "status_msg" in r.keys() else None,
                            r.get("avatar_path") if hasattr(r, "get") else r["avatar_path"] if "avatar_path" in r.keys() else None,
                        ),
                    )
                src_conn.close()
        else:
            # 정말 첫 달이라 기존 DB가 전혀 없을 때만 초기 유저 직접 생성
            initial_users = [
                ("dongguk", "1234", 1),
                ("user1", "1111", 0),
                ("user2", "2222", 0),
                ("user3", "3333", 0),
                ("user4", "4444", 0),
                ("user5", "5555", 0),
            ]
            for u, p, admin in initial_users:
                c.execute(
                    "INSERT OR IGNORE INTO users (username, password, is_admin, status_msg, avatar_path) VALUES (?, ?, ?, ?, ?)",
                    (u, p, admin, None, None),
                )
        conn.commit()

    return conn


# 오늘 날짜 기준으로 time_out 이 아직 NULL 인 출근 레코드가 있는 user_id 들을 set 으로 반환한다.
# 즉, '출근 찍고 아직 퇴근 안 한 사람들' = 현재 근무 중 (초록불)
# 퇴근까지 끝난 사람은 이 set 에 안 들어감 (빨간불)
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


def hash_password(plain_password: str) -> str:
    """주어진 비밀번호를 해시 문자열로 변환한다."""
    return generate_password_hash(plain_password)

def verify_password(stored_password: str, provided_password: str) -> bool:
    """
    DB에 저장된 비밀번호(`stored_password`)와 사용자가 입력한 비밀번호(`provided_password`)가
    일치하는지 확인한다.

    - 과거 버전: 비밀번호를 평문으로 저장했을 수 있음 (예: "1111").
    - 새 버전: generate_password_hash()로 해시된 문자열 (pbkdf2:sha256:... 형태).

    전략:
    1) stored_password가 해시 형태면 check_password_hash()로 검증.
    2) 아니면 평문 비교.
    """
    if not stored_password:
        return False
    # 해시 방식으로 저장된 경우 (werkzeug 스타일)
    if stored_password.startswith("pbkdf2:") or "$" in stored_password:
        return check_password_hash(stored_password, provided_password)
    # 평문으로 저장된 경우
    return stored_password == provided_password


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
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    username = session["username"]
    today = date.today().isoformat()

    conn = get_db()
    c = conn.cursor()

    # 오늘 출근했는데 퇴근 안 찍은거
    c.execute("""
        SELECT * FROM attendance
        WHERE user_id=? AND date=? AND time_out IS NULL
    """, (user_id, today))
    open_rec = c.fetchone()

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

    return render_template(
        "dashboard.html",
        username=username,
        open_rec=open_rec,
        month_hours=hours,
        month_mins=mins,
        is_admin=session.get("is_admin", False)
    )


@app.route("/punch_in", methods=["POST"])
def punch_in():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    today = date.today().isoformat()
    now = datetime.now().strftime("%H:%M:%S")

    conn = get_db()
    c = conn.cursor()
    # 이미 오늘 열린 기록이 있는지 확인
    c.execute("""
        SELECT id FROM attendance
        WHERE user_id=? AND date=? AND time_out IS NULL
    """, (user_id, today))
    exists = c.fetchone()
    if not exists:
        c.execute("""
            INSERT INTO attendance (user_id, date, time_in)
            VALUES (?, ?, ?)
        """, (user_id, today, now))
        conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))


@app.route("/punch_out", methods=["POST"])
def punch_out():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
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
        c.execute("""
            UPDATE attendance
            SET time_out=?, work_minutes=?
            WHERE id=?
        """, (now, delta_min, rec["id"]))
        conn.commit()

    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/admin")
def admin():
    # 관리자만
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    today = date.today().isoformat()
    month_prefix = today[:7]

    conn = get_db()
    c = conn.cursor()

    # 현재 근무중(출근 찍고 아직 퇴근 안 한) 사용자 ID set
    active_user_ids = get_active_user_ids_for_today(conn)

    # 사람별 이번달 합계 (id 포함)
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

    # 최근 기록 50개
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
    # 로그인 안 되어 있으면 로그인 페이지로 넘긴다
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_pw = request.form.get("current_password", "").strip()
        new_pw = request.form.get("new_password", "").strip()
        new_pw2 = request.form.get("new_password2", "").strip()

        # 새 비밀번호 유효성 검사
        if not new_pw:
            flash("새 비밀번호를 입력하세요.")
            return redirect(url_for("change_password"))
        if new_pw != new_pw2:
            flash("새 비밀번호 확인이 일치하지 않습니다.")
            return redirect(url_for("change_password"))

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE id=?", (session["user_id"],))
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

        # 새 비밀번호를 해시로 저장한다
        new_hashed = hash_password(new_pw)
        c.execute("UPDATE users SET password=? WHERE id=?", (new_hashed, session["user_id"]))
        conn.commit()
        conn.close()

        flash("비밀번호가 변경되었습니다.")
        return redirect(url_for("dashboard"))

    # GET 요청이면 비밀번호 변경 폼을 보여준다
    return render_template("change_password.html")



@app.route("/admin_reset/<username>", methods=["POST"])
def admin_reset(username):
    # 관리자 권한 확인
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    # 예: 모든 유저의 비밀번호를 "1111"로 초기화 가능
    default_pw = "1111"
    new_hashed = hash_password(default_pw)

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE username=?", (new_hashed, username))
    conn.commit()
    conn.close()

    flash(f"{username} 계정의 비밀번호를 {default_pw} 로 초기화했습니다.")
    return redirect(url_for("admin"))


# 관리자만 접근 가능한 유저 추가 라우트
@app.route("/admin_add_user", methods=["GET", "POST"])
def admin_add_user():
    # 관리자만 접근 가능
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        make_admin = request.form.get("is_admin", "0")  # '1'이면 관리자, 아니면 일반

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

    # GET 요청이면 유저 추가 폼 렌더링
    return render_template("add_user.html")


@app.route("/admin_delete_user/<username>", methods=["POST"])
def admin_delete_user(username):
    # 관리자만 삭제 가능
    if not session.get("is_admin", False):
        return redirect(url_for("dashboard"))

    conn = get_db()
    c = conn.cursor()

    # 1) 먼저 해당 사용자가 관리자이면(=is_admin=1) 삭제를 막고 싶다면 이 블록을 사용한다.
    #    지금은 실수 방지차원에서 넣어둔다. 관리자를 지우고 싶으면 이 if 블록을 지워도 된다.
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

    # 2) 근무 기록(attendance)은 남겨두고, users 테이블에서만 계정 삭제한다.
    #    만약 attendance까지 같이 지우고 싶으면 아래 DELETE FROM attendance ... 를 주석 해제.

    # attendance까지 완전히 제거하려면 다음 줄 주석 해제:
    # c.execute("DELETE FROM attendance WHERE user_id = (SELECT id FROM users WHERE username=?)", (username,))

    # users 테이블에서 삭제
    c.execute("DELETE FROM users WHERE username=?", (username,))

    conn.commit()
    conn.close()

    flash(f"{username} 계정을 완전히 삭제했습니다.")
    return redirect(url_for("admin"))



# 공개 회원가입 라우트
@app.route("/register", methods=["GET", "POST"])
def register():
    # 이미 로그인 되어 있으면 대시보드로
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


@app.route("/profiles")
def profiles():
    if "user_id" not in session:
        return redirect(url_for("login"))

    today_str = date.today().isoformat()

    conn = get_db()
    c = conn.cursor()

    # 전체 유저 정보 불러오기
    c.execute(
        """
        SELECT id, username, status_msg, avatar_path
        FROM users
        ORDER BY username
        """
    )
    raw_people = c.fetchall()

    # 오늘 아직 퇴근 안 한(=근무중) 유저들의 id 세트 (초록불 표시용)
    active_user_ids = get_active_user_ids_for_today(conn)

    people = []
    for u in raw_people:
        uid = u["id"]

        # 1) 오늘 완료된(퇴근까지 한) 레코드들의 work_minutes 합
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

        # 2) 아직 퇴근 안 한(open) 레코드가 있으면 현재까지 경과시간 추가
        c.execute(
            """
            SELECT time_in
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
            t_in_str = open_row["time_in"]  # 'HH:MM:SS'
            try:
                t_in_dt = datetime.strptime(t_in_str, "%H:%M:%S")
                now_dt = datetime.now()
                # now_dt.time() is today's time, so this diff is OK intra-day
                delta_min = int((now_dt - now_dt.replace(hour=t_in_dt.hour,
                                                         minute=t_in_dt.minute,
                                                         second=t_in_dt.second,
                                                         microsecond=0)).total_seconds() // 60)
                if delta_min < 0:
                    delta_min = 0
                extra_min = delta_min
            except Exception:
                extra_min = 0

        today_minutes = done_min + extra_min

        # 진행률: 8시간 = 480분 기준
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

    return render_template(
        "profiles.html",
        people=people,
        active_user_ids=active_user_ids,
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

        # 파일 업로드가 실제로 있었는지 체크
        if avatar_file and avatar_file.filename:
            # 보안적으로 안전한 파일명으로 변환
            fname_original = avatar_file.filename
            fname_secure = secure_filename(fname_original)

            # username 기반으로 강제 이름 지정하려면 예:
            # fname_secure = f"{session['username']}.png"

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

    # GET이면 현재 내 정보 읽어서 폼 보여주기
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


if __name__ == "__main__":
    # 0.0.0.0 으로 열어야 다른 PC에서 접속 가능
    app.run(host="0.0.0.0", port=5001, debug=True)