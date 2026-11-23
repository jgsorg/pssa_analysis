import os
import re
import hmac
from functools import wraps
from datetime import timedelta
from flask import Flask, render_template, request, session, redirect, url_for, abort
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
import pymysql
from pymysql.cursors import DictCursor

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=4),
)
SUBJECTS = {"E": "English", "M": "Math", "S": "Science"}

# all sql queries are made from a read-only user

def query(sql, values=()):
    connection = pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        cursorclass=DictCursor, # makes dictionary
        charset="utf8mb4",
        connect_timeout=8,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql, values)
            return cursor.fetchall()
    finally:
        connection.close()


def login_required(function): # security measure to make logins required
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper

#https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
# docs on secrets + hmac
def csrf_token(): # more security, cross site request forgery protection.
    import secrets
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        token = request.form.get("csrf", "")
        if not token or not hmac.compare_digest(token, session.get("csrf", "")): # csrf talked abt earlier, retrieves the token through login form
            abort(400) # if token bad/missing
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        expected_username = os.getenv("ADMIN_USERNAME", "admin")
        stored_hash = os.getenv("ADMIN_PASSWORD_HASH", "")
        if (hmac.compare_digest(username, expected_username)
                and stored_hash and check_password_hash(stored_hash, password)):
            session.clear()
            session["authenticated"] = True
            session.permanent = True
            return redirect(url_for("index"))
        error = "Incorrect username or password."
    return render_template("login.html", error=error)


@app.post("/logout")
@login_required
def logout():
    token = request.form.get("csrf", "")
    if not token or not hmac.compare_digest(token, session.get("csrf", "")):
        abort(400)
    session.clear()
    return redirect(url_for("login"))


def student_ids(text):
    # allow more than 1 id with spaces, commas, or new lines
    ids = list(dict.fromkeys(re.split(r"[,\\s]+", text.strip()))) if text.strip() else []
    if len(ids) > 100 or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,30}", x) for x in ids):
        raise ValueError("Enter up to 100 valid student IDs.")
    return ids


@app.get("/")
@login_required
def index():
    # filters are avail in url
    mode = request.args.get("mode", "")
    year = request.args.get("year", "").strip()
    grade = request.args.get("grade", "").strip()
    subject = request.args.get("subject", "").strip().upper()
    ids_text = request.args.get("student_ids", "").strip()
    anchor = request.args.get("anchor", "").strip()

    # initialize
    error = None
    assessments = []
    anchors = []
    students = []

    # input validation
    try:
        if year and (not year.isdigit() or len(year) != 4):
            raise ValueError("Choose a valid year.")
        if grade and grade not in [str(x) for x in range(3, 9)]:
            raise ValueError("Choose a grade from 3 to 8.")
        if subject and subject not in SUBJECTS: # subjects defined in beginning (E, M, S)
            raise ValueError("Choose a valid subject.")
        ids = student_ids(ids_text)

        if mode == "students":
            if not ids and not (year or grade or subject):
                raise ValueError("Enter student IDs or choose a filter.")
            filters = []
            values = []
            for field, value in (("year", year), ("grade", grade), ("subject", subject)):
                if value:
                    filters.append("t." + field + " = %s")
                    values.append(value)
            if ids:
                filters.append("t.local_student_id IN (" + ",".join(["%s"] * len(ids)) + ")")
                values.extend(ids)
            sql = """SELECT t.local_student_id, t.year, t.grade, t.subject,
                t.scale_score, t.total_raw_score, t.performance_level_name
                FROM test_results t WHERE """ + " AND ".join(filters) + """
                ORDER BY t.year DESC, t.grade, t.subject, t.local_student_id
                LIMIT 500"""
            assessments = query(sql, values)

        if mode in ("skills", "rank"):
            if not (year and grade and subject):
                raise ValueError("Choose a year, grade, and subject to find skills.")
            # restrict to anchors with scores for selected
            anchors = query("""SELECT DISTINCT v.anchor_code,
                (SELECT MIN(a.description) FROM anchors a
                 WHERE a.subject = v.subject AND a.grade = v.grade
                   AND a.anchor_code = v.anchor_code) AS description
                FROM student_anchor_scores v
                WHERE v.year = %s AND v.grade = %s AND v.subject = %s
                  AND (v.subject <> 'E' OR
                       (v.anchor_code NOT LIKE '6.%%' AND v.anchor_code NOT LIKE '7.%%'))
                ORDER BY v.anchor_code""", (year, grade, subject))

        if mode == "rank":
            allowed = {str(row["anchor_code"]) for row in anchors}
            if anchor not in allowed:
                raise ValueError("Choose an available skill before ranking students.")
            # score only compare w same anchors
            extra = ""
            values = [year, grade, subject, anchor]
            if ids:
                extra = " AND v.student_id IN (" + ",".join(["%s"] * len(ids)) + ")"
                values.extend(ids)
            students = query("""SELECT v.student_id, MIN(v.score) AS score
                FROM student_anchor_scores v
                WHERE v.year = %s AND v.grade = %s AND v.subject = %s
                  AND v.anchor_code = %s AND v.score IS NOT NULL""" + extra + """
                GROUP BY v.student_id
                ORDER BY score ASC, v.student_id ASC LIMIT 1000""", values)

    except ValueError as exc:
        error = str(exc)
    except pymysql.MySQLError:
        app.logger.exception("Database query failed")
        error = "Could not load the results."

    try:
        years = [row["year"] for row in query(
            "SELECT DISTINCT year FROM test_results ORDER BY year DESC")]
    except pymysql.MySQLError:
        app.logger.exception("Could not load years")
        years = []
        error = error or "Could not connect to the database."

    return render_template(
        "index.html", mode=mode, year=year, grade=grade, subject=subject,
        ids_text=ids_text, anchor=anchor, error=error, years=years,
        subjects=SUBJECTS, assessments=assessments, anchors=anchors,
        students=students,
    )


if __name__ == "__main__":
    app.run(debug=False)
