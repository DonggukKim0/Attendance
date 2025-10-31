# init_db.py
import sqlite3
from datetime import datetime
from pathlib import Path

# 월별 DB 파일 이름을 현재 연도_월 기준으로 만든다. 예: attendance_2025_10.db
BASE_DIR = Path(__file__).resolve().parent
ym = datetime.now().strftime("%Y_%m")
DB = BASE_DIR / f"attendance_{ym}.db"

conn = sqlite3.connect(DB)
c = conn.cursor()

# users 테이블
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0
)
""")

# attendance 테이블
c.execute("""
CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    date TEXT,
    time_in TEXT,
    time_out TEXT,
    work_minutes INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")

# 기본 유저 계정 생성
initial_users = [
    ("dongguk", "1234", 1),  # 관리자
]

for u, p, admin in initial_users:
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", (u, p, admin))

# 이 스크립트는 최초 1회(또는 새 환경 세팅 시)만 실행하면 된다.
conn.commit()
conn.close()

print("DB initialized.")