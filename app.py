import sqlite3
import random
from datetime import datetime
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "hackathon-demo-secret-key-change-in-production"
DATABASE = "blood_bank.db"

BLOOD_TYPES = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
RARE_TYPES = ["AB-", "B-", "O-"]

BANK_NAMES = [
    "St. Xavier General Hospital",
    "Metro Red Cross Centre",
    "City Care Blood Bank",
    "Sunrise Medical Trust",
    "Apex Diagnostics & Blood Bank",
    "Grace Hospital Transfusion Unit",
]


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('donor','requester')),
            location TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS donor_profiles (
            user_id INTEGER PRIMARY KEY,
            blood_type TEXT NOT NULL,
            available INTEGER DEFAULT 1,
            last_donation_date TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS blood_banks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            distance_km REAL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS bank_stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bank_id INTEGER NOT NULL,
            blood_type TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('available','low','out')),
            FOREIGN KEY(bank_id) REFERENCES blood_banks(id)
        );

        CREATE TABLE IF NOT EXISTS sos_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            blood_type TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(requester_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sos_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sos_id INTEGER NOT NULL,
            donor_id INTEGER NOT NULL,
            responded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sos_id) REFERENCES sos_requests(id),
            FOREIGN KEY(donor_id) REFERENCES users(id)
        );
        """
    )

    existing = db.execute("SELECT COUNT(*) AS c FROM blood_banks").fetchone()["c"]
    if existing == 0:
        random.seed(42)
        for i, name in enumerate(BANK_NAMES):
            distance = round(1.0 + i * 1.1, 1)
            cur = db.execute(
                "INSERT INTO blood_banks (name, distance_km) VALUES (?, ?)",
                (name, distance),
            )
            bank_id = cur.lastrowid
            for bt in BLOOD_TYPES:
                roll = random.random()
                if bt in RARE_TYPES:
                    status = "out" if roll < 0.55 else ("low" if roll < 0.8 else "available")
                else:
                    status = "out" if roll < 0.15 else ("low" if roll < 0.35 else "available")
                db.execute(
                    "INSERT INTO bank_stock (bank_id, blood_type, status) VALUES (?, ?, ?)",
                    (bank_id, bt, status),
                )
        db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(role=None):
    def decorator(f):
        from functools import wraps

        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("You don't have access to that page.")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)

        return wrapped

    return decorator


# ---------------------------------------------------------------------------
# Routes: home / auth
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        db = get_db()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role")
        location = request.form.get("location", "").strip()

        if not name or not email or not password or role not in ("donor", "requester"):
            flash("Please fill in all required fields.")
            return redirect(url_for("signup"))

        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("An account with that email already exists.")
            return redirect(url_for("signup"))

        password_hash = generate_password_hash(password)
        cur = db.execute(
            "INSERT INTO users (name, email, password_hash, role, location) VALUES (?, ?, ?, ?, ?)",
            (name, email, password_hash, role, location),
        )
        user_id = cur.lastrowid

        if role == "donor":
            blood_type = request.form.get("blood_type")
            last_donation = request.form.get("last_donation_date") or None
            if blood_type not in BLOOD_TYPES:
                flash("Please select a valid blood type.")
                return redirect(url_for("signup"))
            db.execute(
                "INSERT INTO donor_profiles (user_id, blood_type, available, last_donation_date) VALUES (?, ?, 1, ?)",
                (user_id, blood_type, last_donation),
            )

        db.commit()

        session["user_id"] = user_id
        session["role"] = role
        session["name"] = name
        flash(f"Welcome, {name}! Your account has been created.")
        return redirect(url_for("dashboard"))

    return render_template("signup.html", blood_types=BLOOD_TYPES)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Incorrect email or password.")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["name"] = user["name"]
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session["role"] == "donor":
        return redirect(url_for("donor_dashboard"))
    return redirect(url_for("requester_dashboard"))


# ---------------------------------------------------------------------------
# Routes: donor
# ---------------------------------------------------------------------------
@app.route("/donor")
@login_required(role="donor")
def donor_dashboard():
    db = get_db()
    profile = db.execute(
        "SELECT * FROM donor_profiles WHERE user_id = ?", (session["user_id"],)
    ).fetchone()

    alerts = db.execute(
        """
        SELECT sos_requests.id, sos_requests.blood_type, sos_requests.created_at,
               users.name AS requester_name, users.location AS requester_location,
               EXISTS(
                   SELECT 1 FROM sos_responses
                   WHERE sos_responses.sos_id = sos_requests.id
                   AND sos_responses.donor_id = ?
               ) AS already_responded
        FROM sos_requests
        JOIN users ON users.id = sos_requests.requester_id
        WHERE sos_requests.blood_type = ? AND sos_requests.status = 'active'
        ORDER BY sos_requests.created_at DESC
        """,
        (session["user_id"], profile["blood_type"]),
    ).fetchall()

    return render_template("donor_dashboard.html", profile=profile, alerts=alerts)


@app.route("/donor/toggle-availability", methods=["POST"])
@login_required(role="donor")
def toggle_availability():
    db = get_db()
    profile = db.execute(
        "SELECT available FROM donor_profiles WHERE user_id = ?", (session["user_id"],)
    ).fetchone()
    new_value = 0 if profile["available"] else 1
    db.execute(
        "UPDATE donor_profiles SET available = ? WHERE user_id = ?",
        (new_value, session["user_id"]),
    )
    db.commit()
    return jsonify({"available": bool(new_value)})


@app.route("/api/sos/<int:sos_id>/respond", methods=["POST"])
@login_required(role="donor")
def respond_to_sos(sos_id):
    db = get_db()
    already = db.execute(
        "SELECT 1 FROM sos_responses WHERE sos_id = ? AND donor_id = ?",
        (sos_id, session["user_id"]),
    ).fetchone()
    if not already:
        db.execute(
            "INSERT INTO sos_responses (sos_id, donor_id) VALUES (?, ?)",
            (sos_id, session["user_id"]),
        )
        db.commit()
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Routes: requester
# ---------------------------------------------------------------------------
@app.route("/requester")
@login_required(role="requester")
def requester_dashboard():
    return render_template("requester_dashboard.html", blood_types=BLOOD_TYPES, rare_types=RARE_TYPES)


@app.route("/api/banks/<blood_type>")
@login_required(role="requester")
def api_banks(blood_type):
    db = get_db()
    rows = db.execute(
        """
        SELECT blood_banks.name, blood_banks.distance_km, bank_stock.status, blood_banks.updated_at
        FROM bank_stock
        JOIN blood_banks ON blood_banks.id = bank_stock.bank_id
        WHERE bank_stock.blood_type = ?
        ORDER BY CASE bank_stock.status
            WHEN 'available' THEN 0 WHEN 'low' THEN 1 ELSE 2 END,
            blood_banks.distance_km ASC
        """,
        (blood_type,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/sos/broadcast", methods=["POST"])
@login_required(role="requester")
def broadcast_sos():
    db = get_db()
    blood_type = request.json.get("blood_type")
    if blood_type not in BLOOD_TYPES:
        return jsonify({"error": "invalid blood type"}), 400

    cur = db.execute(
        "INSERT INTO sos_requests (requester_id, blood_type) VALUES (?, ?)",
        (session["user_id"], blood_type),
    )
    db.commit()
    sos_id = cur.lastrowid

    matching_donors = db.execute(
        "SELECT COUNT(*) AS c FROM donor_profiles WHERE blood_type = ? AND available = 1",
        (blood_type,),
    ).fetchone()["c"]

    return jsonify({"sos_id": sos_id, "matching_donors": matching_donors})


@app.route("/api/sos/<int:sos_id>/responses")
@login_required(role="requester")
def sos_responses(sos_id):
    db = get_db()
    rows = db.execute(
        """
        SELECT users.name, users.location, sos_responses.responded_at
        FROM sos_responses
        JOIN users ON users.id = sos_responses.donor_id
        WHERE sos_responses.sos_id = ?
        ORDER BY sos_responses.responded_at ASC
        """,
        (sos_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)