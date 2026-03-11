from flask import Flask, render_template, request
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)

DATABASE = "/tmp/behavior.db"
LOCK_MINUTES = 5

# ===============================
# DATABASE INIT
# ===============================
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        avg_total REAL,
        avg_user REAL,
        avg_pass REAL,
        login_count INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        blocked_until TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        total REAL,
        user_time REAL,
        pass_time REAL,
        risk REAL,
        decision TEXT,
        ip TEXT,
        device TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ===============================
# HOME
# ===============================
@app.route("/")
def home():
    return render_template("login.html")

# ===============================
# LOGIN
# ===============================
@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    total = float(request.form["total_time"])
    user_time = float(request.form["username_time"])
    pass_time = float(request.form["password_time"])

    now = datetime.now()
    ip = request.remote_addr
    device = request.headers.get("User-Agent")

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()

    risk = 0
    decision = "Allowed"

    # ===============================
    # FIRST LOGIN
    # ===============================
    if not user:
        c.execute("""
        INSERT INTO users (username, avg_total, avg_user, avg_pass, login_count)
        VALUES (?, ?, ?, ?, 1)
        """, (username, total, user_time, pass_time))
        decision = "Baseline Created"

    else:
        user_id = user[0]
        avg_total = user[2]
        avg_user = user[3]
        avg_pass = user[4]
        login_count = user[5]
        failed = user[6]
        blocked_until = user[7]

        # ===============================
        # CHECK LOCK
        # ===============================
        if blocked_until:
            blocked_time = datetime.strptime(blocked_until, "%Y-%m-%d %H:%M:%S")
            if now < blocked_time:
                conn.close()
                return render_template(
                    "result.html",
                    username=username,
                    total=total,
                    user_time=user_time,
                    pass_time=pass_time,
                    risk=100,
                    decision="Blocked (Locked)"
                )
            else:
                # unlock
                c.execute("UPDATE users SET failed_attempts=0, blocked_until=NULL WHERE id=?", (user_id,))
                failed = 0

        # ===============================
        # SAFE RISK CALCULATION
        # ===============================
        diff_total = abs(total - avg_total) / avg_total * 100
        diff_user = abs(user_time - avg_user) / avg_user * 100
        diff_pass = abs(pass_time - avg_pass) / avg_pass * 100

        risk = (diff_total * 0.4 + diff_user * 0.3 + diff_pass * 0.3)
        risk = min(risk, 100)

        # ===============================
        # DECISION
        # ===============================
        if risk < 40:
            decision = "Allowed"
            failed = 0

            # update averages
            new_count = login_count + 1
            new_avg_total = (avg_total * login_count + total) / new_count
            new_avg_user = (avg_user * login_count + user_time) / new_count
            new_avg_pass = (avg_pass * login_count + pass_time) / new_count

            c.execute("""
            UPDATE users SET
            avg_total=?, avg_user=?, avg_pass=?,
            login_count=?, failed_attempts=0
            WHERE id=?
            """, (new_avg_total, new_avg_user, new_avg_pass, new_count, user_id))

        else:
            decision = "High Risk"
            failed += 1

            if failed >= 3:
                lock_time = now + timedelta(minutes=LOCK_MINUTES)
                decision = "Blocked (Locked)"
                c.execute("""
                UPDATE users SET failed_attempts=?, blocked_until=?
                WHERE id=?
                """, (failed, lock_time.strftime("%Y-%m-%d %H:%M:%S"), user_id))
            else:
                c.execute("UPDATE users SET failed_attempts=? WHERE id=?", (failed, user_id))

        conn.commit()

    # ===============================
    # SAVE HISTORY
    # ===============================
    c.execute("""
    INSERT INTO login_history
    (username, total, user_time, pass_time, risk, decision, ip, device, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (username, total, user_time, pass_time,
          round(risk,2), decision, ip, device,
          now.strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()

    return render_template("result.html",
                           username=username,
                           total=total,
                           user_time=user_time,
                           pass_time=pass_time,
                           risk=round(risk,2),
                           decision=decision)

# ===============================
# HISTORY
# ===============================
@app.route("/history")
def history():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM login_history ORDER BY id DESC")
    records = c.fetchall()
    conn.close()
    return render_template("history.html", records=records)

# ===============================
# ADMIN
# ===============================
@app.route("/admin")
def admin():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT username, login_count, failed_attempts, blocked_until FROM users")
    users = c.fetchall()
    conn.close()
    return render_template("admin.html", users=users)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
