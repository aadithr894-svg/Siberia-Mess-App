

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, g
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor
import qrcode
import io
import base64
import os
from datetime import datetime, date, timedelta
from config import Config

# ---------------- Flask App ----------------
app = Flask(__name__)
app.config.from_object(Config)

# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------- DATABASE CONNECTION ----------------
def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            database=Config.DB_NAME,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            cursor_factory=RealDictCursor
        )
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    data = cur.fetchone()
    cur.close()
    if data:
        return User(data['id'], data['name'], data['email'], data['user_type'])
    return None

# ---------------- CREATE DEFAULT ADMIN ----------------
def create_admin():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", ("admin@example.com",))
    admin = cur.fetchone()
    hashed_password = generate_password_hash("admin123")
    if not admin:
        cur.execute("""
            INSERT INTO users (name, email, phone, course, password, user_type, approved)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, ("Super Admin", "admin@example.com", "0000000000", "N/A", hashed_password, "admin", True))
        conn.commit()
        print("✅ Default admin created")
    cur.close()


# ---------------- ROUTES ----------------

@app.route('/')
def index():
    return render_template('index.html')

# -------- REGISTER --------
# -------- REGISTER --------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        course = request.form['course']
        phone = request.form['phone']
        password = request.form['password']
        user_type = request.form['user_type']  # student or admin

        # ✅ Basic required fields check
        if not name or not email or not password or not user_type:
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        # ✅ Phone number validation
        if not phone.isdigit() or len(phone) != 10:
            flash("Phone number must be exactly 10 digits.", "danger")
            return redirect(url_for('register'))

        # ✅ Hash password
        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)

            # Insert into new_users table
            cur.execute("""
                INSERT INTO new_users (name, email, phone, course, password, user_type)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, email, phone, course, hashed_password, user_type))
            conn.commit()

            flash("Registration successful! Await admin approval.", "success")

        except Exception as e:
            flash(f"Database error: {e}", "danger")

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

# -------- LOGIN --------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user['password'], password):
            if user['user_type'] != "admin" and not user['approved']:
                flash("Your account is awaiting admin approval.", "warning")
                return redirect(url_for('login'))
            login_user(User(user['id'], user['name'], user['email'], user['user_type']))
            flash("Login successful!", "success")
            if user['user_type'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

# -------- USER DASHBOARD --------
@app.route('/dashboard')
@login_required
def user_dashboard():
    # Generate QR
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(str(current_user.id))
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_b64 = base64.b64encode(buffer.getvalue()).decode('ascii')

    # Connect to Postgres
    conn = get_db()
    cur = conn.cursor()

    # Fetch late mess requests for the logged-in user
    cur.execute("""
        SELECT id, user_id, date_requested, status
        FROM late_mess
        WHERE user_id = %s
        ORDER BY date_requested DESC
    """, (current_user.id,))

    late_requests = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('dashboard.html', qr_code=qr_code_b64, late_requests=late_requests)



# -------- ADMIN DASHBOARD --------
@app.route('/admin')
@login_required
def admin_dashboard():
    if not getattr(current_user, "is_admin", False):
        flash("Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))
    return render_template('admin_base.html')


# -------- LOGOUT --------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "info")
    return redirect(url_for('index'))


# ----------------- START APP -----------------
if __name__ == "__main__":
    # Only for local development
    with app.app_context():
        create_admin()   # Ensure default admin exists only once
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)



# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.login_view = "login"   # Redirects to 'login' if not logged in
login_manager.login_message_category = "info"  # Bootstrap-friendly flash category
login_manager.init_app(app)

# ---------------- USER CLASS ----------------
class User(UserMixin):
    def __init__(self, id, name, email, user_type):
        self.id = id
        self.name = name
        self.email = email
        self.user_type = user_type
        self.is_admin = user_type == 'admin'

        
@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, name, email, user_type FROM users WHERE id = %s",
        (user_id,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        return User(*row)  # maps to id, name, email, user_type
    return None

# ---------------- CREATE ADMIN ----------------
# ---------------- CREATE ADMIN ----------------
# ---------------- CREATE ADMIN ----------------
from flask import Flask

from werkzeug.security import generate_password_hash
import MySQLdb


# -----------------------------
# Function to create default admin
# -----------------------------
# ---------------- CREATE ADMIN ----------------
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash

def create_admin():
    try:
        conn = psycopg2.connect(
            host="dpg-d2kbemv5r7bs73eljh4g-a",   # Render internal hostname
            database="siberia_mess_app",
            user="siberia_mess_app_user",
            password="lfFfFk3uGBHj5nkdrowYYHMlVGzyUB0o",
            port=5432
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Check if admin already exists
        cur.execute("SELECT * FROM users WHERE email = %s", ("admin@example.com",))
        admin = cur.fetchone()

        hashed_password = generate_password_hash("admin123")

        if not admin:
            # Insert new admin
            cur.execute("""
                INSERT INTO users (name, email, phone, course, password, user_type, approved)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, ("Super Admin", "admin@example.com", "0000000000", "N/A", hashed_password, "admin", 1))
            conn.commit()
            print("✅ Default admin created: email=admin@example.com, password=admin123")
        else:
            # Make sure admin is approved and user_type is admin
            cur.execute("""
                UPDATE users
                SET user_type=%s, approved=%s, password=%s
                WHERE email=%s
            """, ("admin", 1, hashed_password, "admin@example.com"))
            conn.commit()
            print("ℹ️ Admin already exists. Reset password and ensured approved=1.")

        cur.close()
        conn.close()

    except Exception as e:
        print("❌ Error creating admin:", str(e))




# -----------------------------
# Call this once at startup
# -----------------------------









# REPLACE your current /new_users route with this

from psycopg2.extras import RealDictCursor

@app.route('/new_users')
@login_required
def new_users_list():
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM new_users")
        users = cur.fetchall()

    except Exception as e:
        flash(f"Database error: {e}", "danger")
        users = []

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return render_template("new_users.html", users=users)


# -------- LOGIN --------
from psycopg2.extras import RealDictCursor

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)

            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

        except Exception as e:
            flash(f"Database error: {e}", "danger")
            return redirect(url_for('login'))

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

        if user and check_password_hash(user['password'], password):
            # Admin bypass approval check
            if user['user_type'] != "admin" and user['approved'] == 0:
                flash("Your account is awaiting admin approval.", "warning")
                return redirect(url_for('login'))

            login_user(User(user['id'], user['name'], user['email'], user['user_type']))
            flash("Login successful!", "success")

            if user['user_type'] == "admin":
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid credentials", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')






@app.route('/reset_admin')
def reset_admin():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        hashed_password = generate_password_hash("admin123")

        # Delete duplicates if any
        cur.execute("DELETE FROM users WHERE email=%s", ("admin@example.com",))

        # Insert fresh admin
        cur.execute("""
            INSERT INTO users (name, email, phone, course, password, user_type, approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ("Super Admin", "admin@example.com", "0000000000", "N/A",
              hashed_password, "admin", 1))

        conn.commit()
        return "✅ Admin reset: email=admin@example.com, password=admin123"

    except Exception as e:
        return f"❌ Error resetting admin: {e}"

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()




#Approval

from flask import send_file, flash, redirect, url_for
import qrcode
import io
import os
from flask_login import login_required, current_user
from psycopg2.extras import RealDictCursor

@app.route('/approve_user/<int:user_id>')
@login_required
def approve_user(user_id):
    if not getattr(current_user, "is_admin", False):   # ensure only admin can approve
        flash("❌ Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    conn = None
    cur = None

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # 1. Fetch user details from new_users
        cur.execute("SELECT * FROM new_users WHERE id = %s", (user_id,))
        user = cur.fetchone()

        if not user:
            flash("⚠️ User not found!", "warning")
            return redirect(url_for('new_users_list'))

        # 2. Prevent duplicate email
        cur.execute("SELECT id FROM users WHERE email = %s", (user['email'],))
        if cur.fetchone():
            flash("⚠️ A user with this email already exists!", "danger")
            return redirect(url_for('new_users_list'))

        # 3. Insert into users (qr_path left empty initially)
        cur.execute("""
            INSERT INTO users (name, email, phone, course, password, user_type, approved, qr_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            user['name'], user['email'], user['phone'], user['course'],
            user['password'], user['user_type'], 1, ""
        ))

        new_user_id = cur.fetchone()['id']

        # 4. Generate QR Code
        qr_data = f"ID:{new_user_id}|Name:{user['name']}|Email:{user['email']}|Type:{user['user_type']}"
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')

        # Save QR code in static/qrcodes/
        qr_folder = os.path.join("static", "qrcodes")
        os.makedirs(qr_folder, exist_ok=True)
        qr_filename = f"user_{new_user_id}.png"
        qr_path = os.path.join(qr_folder, qr_filename)
        img.save(qr_path)

        # Store relative path
        db_qr_path = f"qrcodes/{qr_filename}"

        # 5. Update QR path in users table
        cur.execute("UPDATE users SET qr_path = %s WHERE id = %s", (db_qr_path, new_user_id))

        # 6. Delete from new_users
        cur.execute("DELETE FROM new_users WHERE id=%s", (user_id,))

        # ✅ Commit once after all queries
        conn.commit()

        flash("✅ User approved successfully and QR code generated.", "success")

    except Exception as e:
        if conn:
            conn.rollback()
        flash(f"❌ Error approving user: {str(e)}", "danger")
        print("Approve user error:", e)  # debug log

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return redirect(url_for('new_users_list'))


from psycopg2.extras import RealDictCursor

@app.route('/reject_user/<int:user_id>')
@login_required
def reject_user(user_id):
    if not getattr(current_user, "is_admin", False):   # ensure only admin can reject
        flash("❌ Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    conn = None
    cur = None

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Delete user from new_users
        cur.execute("DELETE FROM new_users WHERE id = %s", (user_id,))
        conn.commit()

        flash("🚫 User rejected and removed.", "danger")

    except Exception as e:
        if conn:
            conn.rollback()
        flash(f"❌ Error rejecting user: {str(e)}", "danger")
        print("Reject user error:", e)  # debug log

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return redirect(url_for('new_users_list'))


# -------- LOGOUT --------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "info")
    return redirect(url_for('index'))

# -------- USER DASHBOARD --------
@app.route('/dashboard')
@login_required
def user_dashboard():
    # -------- Generate QR code --------
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(str(current_user.id))
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_b64 = base64.b64encode(buffer.getvalue()).decode('ascii')

    # -------- Fetch late mess requests from Postgres --------
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # returns dict rows
    cur.execute(
        "SELECT * FROM late_mess WHERE user_id = %s ORDER BY date DESC",
        (current_user.id,)
    )
    late_requests = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        'dashboard.html',
        qr_code=qr_code_b64,
        late_requests=late_requests
    )
# -------- ADMIN DASHBOARD --------
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Unauthorized access", "danger")
        return redirect(url_for('user_dashboard'))

    # Example: fetch all late mess requests for admin view
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT lm.id, lm.date, u.name AS user_name, u.email
        FROM late_mess lm
        JOIN users u ON lm.user_id = u.id
        ORDER BY lm.date DESC
    """)
    all_requests = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("admin_base.html", all_requests=all_requests)



# -------- ADMIN: USERS LIST --------
@app.route('/admin/users')
@login_required
def users_list():
    if not current_user.is_admin:
        flash("Unauthorized access", "danger")
        return redirect(url_for('user_dashboard'))

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, name, email, course, phone FROM users ORDER BY id ASC")
    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("admin_users.html", users=users)




# -------- ADMIN: DELETE USER --------
@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for("user_dashboard"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash("User deleted successfully", "success")
    return redirect(url_for("users_list"))





# -------- ADMIN: LIVE QR SCANNER --------
@app.route('/admin/qr_scan')
@login_required
def admin_qr_scan():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for("user_dashboard"))

    # In future: you could preload recent scans or logs from DB here
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.name, u.email, l.date
        FROM late_mess l
        JOIN users u ON l.user_id = u.id
        ORDER BY l.date DESC
        LIMIT 10
    """)
    recent_scans = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("admin_qr_scan.html", recent_scans=recent_scans)






@app.route('/my_mess_cuts')
@login_required
def my_mess_cuts():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(
        "SELECT * FROM mess_cut WHERE user_id = %s ORDER BY start_date DESC",
        (current_user.id,)
    )
    cuts = cur.fetchall()
    cur.close()
    conn.close()

    # Convert start_date/end_date to date objects and calculate number of days
    for cut in cuts:
        if isinstance(cut["start_date"], str):
            cut["start_date"] = datetime.strptime(cut["start_date"], "%Y-%m-%d").date()
        if isinstance(cut["end_date"], str):
            cut["end_date"] = datetime.strptime(cut["end_date"], "%Y-%m-%d").date()
        cut["num_days"] = (cut["end_date"] - cut["start_date"]).days + 1

    return render_template("my_mess_cuts.html", cuts=cuts)







from flask import request, jsonify
import psycopg2.extras

@app.route('/admin/validate_qr', methods=['POST'])
@login_required
def validate_qr():
    if not current_user.is_admin:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.get_json()
    qr_data = data.get("qr_data", "")

    # Expected format: "user_id:123,email:test@example.com"
    try:
        parts = dict(part.split(":", 1) for part in qr_data.split(","))
        user_id = int(parts.get("user_id"))
    except Exception:
        return jsonify({"success": False, "message": "Invalid QR code"}), 400

    # Check if user exists in DB
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT id, name, email FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user:
        # Example: Mark attendance (optional)
        # cur.execute("INSERT INTO attendance (user_id, scan_time) VALUES (%s, NOW())", (user_id,))
        # conn.commit()

        return jsonify({
            "success": True,
            "message": f"{user['name']} ({user['email']}) is valid."
        })
    else:
        return jsonify({"success": False, "message": "User not found."})




from datetime import datetime, timedelta, date
from flask import Flask

@app.template_filter('add_days')
def add_days_filter(value, days):
    """
    Add `days` to a date (string in YYYY-MM-DD, datetime, or date object).
    Returns ISO format string (YYYY-MM-DD).
    Compatible with PostgreSQL date formats.
    """
    if isinstance(value, str):
        # PostgreSQL often returns date strings as 'YYYY-MM-DD'
        dt = datetime.strptime(value, "%Y-%m-%d").date()
    elif isinstance(value, datetime):
        dt = value.date()
    elif isinstance(value, date):
        dt = value
    else:
        raise ValueError("Unsupported date type for add_days filter")

    return (dt + timedelta(days=int(days))).isoformat()




from datetime import datetime, date, timedelta
from flask import flash, redirect, url_for, render_template, request
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor

# assume you set up connection like:
# pg_conn = psycopg2.connect(os.environ["DATABASE_URL"], cursor_factory=RealDictCursor)

@app.route('/apply_mess_cut', methods=['GET', 'POST'])
@login_required
def apply_mess_cut():
    today = date.today()
    tomorrow = today + timedelta(days=1)
    current_time = datetime.now().time()
    cutoff_time = datetime.strptime("22:00", "%H:%M").time()  # 10 PM cutoff

    # Minimum end date = start_date + 2 days (so 3 consecutive days total)
    min_end_date = today + timedelta(days=3)

    if request.method == 'POST':
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')

        # ✅ Validate inputs
        if not start_date_str or not end_date_str:
            flash("Start and end dates are required.", "danger")
            return redirect(url_for('apply_mess_cut'))

        try:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for('apply_mess_cut'))

        # ✅ Prevent past or today’s dates
        if start_date <= today or end_date <= today:
            flash("Cannot select today or past dates.", "danger")
            return redirect(url_for('apply_mess_cut'))

        # ✅ Cutoff check for tomorrow
        if start_date == tomorrow and current_time >= cutoff_time:
            flash("Cannot apply mess cut for tomorrow after 10 PM today.", "danger")
            return redirect(url_for('apply_mess_cut'))

        # ✅ Minimum 3-day rule
        if (end_date - start_date).days + 1 < 3:
            flash("Minimum duration is 3 consecutive days.", "danger")
            return redirect(url_for('apply_mess_cut'))

        try:
            cur = pg_conn.cursor(cursor_factory=RealDictCursor)

            # ✅ Check overlapping requests
            cur.execute("""
                SELECT 1 FROM mess_cut
                WHERE user_id=%s AND (
                    (start_date <= %s AND end_date >= %s) OR
                    (start_date <= %s AND end_date >= %s) OR
                    (start_date >= %s AND end_date <= %s)
                )
            """, (current_user.id, start_date, start_date, end_date, end_date, start_date, end_date))
            
            if cur.fetchone():
                flash("You already have a mess cut that overlaps these dates.", "danger")
                cur.close()
                return redirect(url_for('apply_mess_cut'))

            # ✅ Fetch user’s course
            cur.execute("SELECT course FROM users WHERE id=%s", (current_user.id,))
            user = cur.fetchone()
            if not user or not user.get('course'):
                flash("Course not found. Please update your profile.", "danger")
                cur.close()
                return redirect(url_for('apply_mess_cut'))

            course = user['course']

            # ✅ Insert mess cut
            cur.execute("""
                INSERT INTO mess_cut (user_id, start_date, end_date, course, date_applied)
                VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
            """, (current_user.id, start_date, end_date, course))
            pg_conn.commit()

            flash("Mess cut applied successfully!", "success")
            return redirect(url_for('my_mess_cuts'))
        except psycopg2.Error as e:
            flash(f"Database error: {e}", "danger")
        finally:
            cur.close()
            return redirect(url_for('apply_mess_cut'))

    # ✅ GET request → render form
    return render_template(
        'apply_mess_cut.html',
        min_start_date=tomorrow.isoformat(),   # earliest = tomorrow
        min_end_date=min_end_date.isoformat()  # ensures 3-day min
    )



# ---------------- ADMIN: MESS CUT LIST ----------------
from datetime import datetime, timedelta, date
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required, current_user
import psycopg2
from psycopg2.extras import RealDictCursor

@app.route('/admin/mess_cuts', methods=['GET'])
@login_required
def mess_cut_list():
    if not getattr(current_user, "is_admin", False):
        flash("Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    # --- Handle month filter (default: current month) ---
    try:
        month_filter = request.args.get('month', datetime.now().strftime("%Y-%m"))
        filter_year, filter_month = map(int, month_filter.split("-"))
    except Exception:
        flash("Invalid month format. Use YYYY-MM.", "danger")
        return redirect(url_for('mess_cut_list'))

    # --- Compute month start and end ---
    month_start = date(filter_year, filter_month, 1)
    if filter_month == 12:
        next_month = date(filter_year + 1, 1, 1)
    else:
        next_month = date(filter_year, filter_month + 1, 1)
    month_end = next_month - timedelta(days=1)

    # --- Query mess cuts overlapping the selected month ---
    conn = psycopg2.connect(current_app.config['DATABASE_URL'])
    cur = conn.cursor(cursor_factory=RealDictCursor)

    query = """
        SELECT m.user_id, u.name, u.course, m.start_date, m.end_date
        FROM mess_cut m
        JOIN users u ON m.user_id = u.id
        WHERE m.start_date <= %s AND m.end_date >= %s
        ORDER BY u.name, m.start_date
    """
    cur.execute(query, (month_end, month_start))
    cuts = cur.fetchall()
    cur.close()
    conn.close()

    # --- Process and group cuts by user ---
    cuts_by_user = {}
    for cut in cuts:
        user_id = cut['user_id']
        start_date = cut['start_date']
        end_date = cut['end_date']

        # Ensure they are date objects
        if isinstance(start_date, datetime):
            start_date = start_date.date()
        if isinstance(end_date, datetime):
            end_date = end_date.date()

        # Clip to current month
        effective_start = max(start_date, month_start)
        effective_end = min(end_date, month_end)
        total_days = (effective_end - effective_start).days + 1

        if total_days <= 0:
            continue

        if user_id not in cuts_by_user:
            cuts_by_user[user_id] = {
                "name": cut['name'],
                "course": cut['course'],
                "ranges": [],
                "total_days": 0
            }

        cuts_by_user[user_id]["ranges"].append({
            "start": effective_start.strftime("%d-%m-%Y"),
            "end": effective_end.strftime("%d-%m-%Y"),
            "days": total_days
        })
        cuts_by_user[user_id]["total_days"] += total_days

    # --- Count mess cuts for tomorrow ---
    tomorrow = datetime.now().date() + timedelta(days=1)
    tomorrow_count = sum(
        1 for cut in cuts
        if cut['start_date'] <= tomorrow <= cut['end_date']
    )

    # --- Render template ---
    return render_template(
        'mess_cut_list.html',
        cuts_by_user=cuts_by_user,
        month_filter=month_filter,
        tomorrow_count=tomorrow_count
    )




# -------- USER: REQUEST LATE MESS (Postgres) --------
from datetime import datetime, time
from flask import flash, redirect, url_for, render_template, request
from flask_login import login_required, current_user
import psycopg2
import psycopg2.extras

@app.route('/request_late_mess', methods=['GET', 'POST'])
@login_required
def request_late_mess():
    now = datetime.now()
    now_time = now.time()
    today = now.date()

    start_time = time(16, 0)   # 4:00 PM
    end_time = time(20, 30)    # 8:30 PM

    conn = get_db_connection()  # <-- make sure you have this helper
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST':
        if not (start_time <= now_time <= end_time):
            flash("Late mess can only be requested between 4:00 PM and 8:30 PM.", "danger")
            cur.close()
            conn.close()
            return redirect(url_for('request_late_mess'))

        # --- Check if already requested today ---
        cur.execute(
            "SELECT id FROM late_mess WHERE user_id=%s AND date_requested=%s",
            (current_user.id, today)
        )
        existing = cur.fetchone()

        if existing:
            flash("You have already requested late mess for today.", "warning")
        else:
            cur.execute(
                "INSERT INTO late_mess (user_id, date_requested) VALUES (%s, %s)",
                (current_user.id, today)
            )
            conn.commit()
            flash("Late mess requested successfully.", "success")

        cur.close()
        conn.close()
        return redirect(url_for('request_late_mess'))

    # --- Fetch user’s request history ---
    cur.execute(
        "SELECT * FROM late_mess WHERE user_id=%s ORDER BY date_requested DESC",
        (current_user.id,)
    )
    late_requests = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        'request_late_mess.html',
        late_requests=late_requests,
        now_time=now_time,
        start_time=start_time,
        end_time=end_time
    )


# -------- USER: GENERATE QR --------
import qrcode
import io
import json
from flask import send_file, flash, redirect, url_for
from flask_login import login_required, current_user
import psycopg2
import psycopg2.extras
from datetime import datetime

@app.route('/my_qr')
@login_required
def my_qr():
    try:
        conn = get_db_connection()  # <-- Postgres helper
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("SELECT mess_count FROM users WHERE id=%s", (current_user.id,))
        data = cur.fetchone()
        mess_count = data['mess_count'] if data else 0

        cur.close()
        conn.close()
    except Exception as e:
        flash("Error fetching mess count.", "danger")
        return redirect(url_for('user_dashboard'))

    # Add timestamp to make QR unique and time-bound
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    qr_data = {
        "user_id": current_user.id,
        "email": current_user.email,
        "mess_count": mess_count,
        "generated_at": timestamp
    }

    # Generate QR (store JSON instead of str(dict) for safe parsing)
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(json.dumps(qr_data))   # JSON string
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    img_bytes = io.BytesIO()
    img.save(img_bytes, format="PNG")
    img_bytes.seek(0)

    return send_file(img_bytes, mimetype="image/png")


# -------- ADMIN: SCAN QR AND INCREMENT MESS COUNT --------
from datetime import date
from flask import request, jsonify
from flask_login import login_required, current_user
import psycopg2
import psycopg2.extras

@app.route('/admin/scan_qr', methods=['POST'])
@login_required
def scan_qr():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json() or {}
    user_id = data.get('user_id')
    meal_type = data.get('meal_type')
    today = date.today()

    if not user_id or meal_type not in ['breakfast', 'lunch', 'dinner']:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400

    conn, cur = None, None
    try:
        conn = get_db_connection()  # 🔑 Helper for psycopg2 connection
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # --- Check if user exists ---
        cur.execute("SELECT id, name FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # --- Check if already marked today ---
        cur.execute("""
            SELECT id FROM meal_attendance
            WHERE user_id = %s AND meal_type = %s AND attendance_date = %s
        """, (user_id, meal_type, today))
        existing = cur.fetchone()

        if existing:
            return jsonify({'success': False, 'message': f"{user['name']} already marked for {meal_type}"}), 409

        # --- Insert attendance ---
        cur.execute("""
            INSERT INTO meal_attendance (user_id, meal_type, attendance_date)
            VALUES (%s, %s, %s)
        """, (user_id, meal_type, today))
        conn.commit()

        # --- Count total attendance for this meal today ---
        cur.execute("""
            SELECT COUNT(*) AS count
            FROM meal_attendance
            WHERE meal_type = %s AND attendance_date = %s
        """, (meal_type, today))
        result = cur.fetchone()

        return jsonify({
            'success': True,
            'name': user['name'],
            'meal_type': meal_type,
            'count': result['count'],
            'message': f"{user['name']} marked for {meal_type}"
        })

    except Exception as e:
        if conn:
            conn.rollback()  # rollback in case of error
        return jsonify({'success': False, 'message': str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()



from datetime import date
from flask import request, jsonify
from flask_login import login_required, current_user
import psycopg2
import psycopg2.extras

@app.route('/admin/meal_counts')
@login_required
def meal_counts():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    month = request.args.get('month', date.today().strftime("%Y-%m"))
    year, month_num = map(int, month.split("-"))

    conn, cur = None, None
    try:
        conn = get_db_connection()  # 🔑 helper function for psycopg2
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        counts = {}
        for meal in ['breakfast', 'lunch', 'dinner']:
            cur.execute("""
                SELECT attendance_date, COUNT(*) AS total_users
                FROM meal_attendance
                WHERE meal_type = %s
                  AND EXTRACT(YEAR FROM attendance_date) = %s
                  AND EXTRACT(MONTH FROM attendance_date) = %s
                GROUP BY attendance_date
                ORDER BY attendance_date
            """, (meal, year, month_num))
            counts[meal] = [dict(row) for row in cur.fetchall()]

        return jsonify(counts)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()







# -------- ADMIN: GET TOTAL SCAN COUNT --------
@app.route('/admin/qr_scan_count')
@login_required
def qr_scan_count():
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    conn, cur = None, None
    try:
        conn = get_db_connection()  # 🔑 helper function for psycopg2
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Count of users who scanned at least once
        cur.execute("SELECT COUNT(*) AS scanned_users FROM users WHERE mess_count > 0")
        scanned_users = cur.fetchone()['scanned_users']

        # Total number of scans across all users
        cur.execute("SELECT COALESCE(SUM(mess_count), 0) AS total_scans FROM users")
        total_scans = cur.fetchone()['total_scans']

        return jsonify({
            "scanned_users": scanned_users,
            "total_scans": total_scans
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()



@app.route('/admin/users_meal_counts')
@login_required
def users_meal_counts():
    if not current_user.is_admin:
        return jsonify({'users': [], 'error': 'Unauthorized'}), 403

    conn, cur = None, None
    try:
        conn = get_db_connection()  # 🔑 Your psycopg2 connection helper
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT user_id, meal_type, scan_date, scan_count
            FROM user_meal_counts
        """)
        users = cur.fetchall()

        return jsonify({'users': [dict(row) for row in users]})

    except Exception as e:
        return jsonify({'users': [], 'error': str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()



from flask import jsonify
from flask_login import login_required
import psycopg2
import psycopg2.extras

@app.route('/admin/users_mess_count')
@login_required
def users_mess_count():
    conn, cur = None, None
    try:
        conn = get_db_connection()  # 🔑 your psycopg2 connection helper
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("SELECT name, email, user_type, mess_count FROM users")
        users = cur.fetchall()

        return jsonify({
            'users': [
                {
                    'name': u['name'],
                    'email': u['email'],
                    'user_type': u['user_type'],
                    'mess_count': u['mess_count']
                }
                for u in users
            ]
        })

    except Exception as e:
        return jsonify({'users': [], 'error': str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()





@app.route('/admin/validate_qr', methods=['POST'])
@login_required
def admin_validate_qr():
    if not current_user.is_admin:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.get_json()
    qr_data = data.get("qr_data")

    # Try to parse QR data (expected JSON/dict string)
    try:
        if isinstance(qr_data, str):
            qr_dict = json.loads(qr_data.replace("'", '"'))  # handle dict-like strings
        elif isinstance(qr_data, dict):
            qr_dict = qr_data
        else:
            return jsonify({"success": False, "message": "Invalid QR format"}), 400

        user_id = int(qr_dict.get("user_id"))
    except Exception:
        return jsonify({"success": False, "message": "Invalid QR Code"}), 400

    conn, cur = None, None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("UPDATE users SET mess_count = mess_count + 1 WHERE id = %s", (user_id,))
        conn.commit()

        return jsonify({"success": True, "message": f"Attendance recorded for user ID {user_id}"})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()




# -------- ADMIN: LATE MESS LIST --------
@app.route('/admin/late_mess_list')
@login_required
def late_mess_list():
    if not current_user.is_admin:
        return "Unauthorized", 403

    conn, cur = None, None
    late_mess_requests = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT lm.id, u.name, u.email, lm.date_requested, lm.reason
            FROM late_mess lm
            JOIN users u ON u.id = lm.user_id
            WHERE lm.status = 'pending'
            ORDER BY lm.date_requested DESC
        """)
        late_mess_requests = cur.fetchall()

    except Exception as e:
        return f"Database error: {e}", 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return render_template('admin_late_mess.html', late_mess_requests=late_mess_requests)





#Late mess rest

from flask import redirect, url_for, flash
from flask_login import login_required, current_user

# Reset Late Mess
from flask import flash, redirect, url_for
from flask_login import login_required, current_user

@app.route('/admin/reset_late_mess', methods=['POST'])
@login_required
def reset_late_mess():
    if not current_user.is_admin:
        return "Unauthorized", 403

    conn, cur = None, None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE late_mess SET status = 'reset' WHERE status = 'pending'")
        conn.commit()
        flash("Late mess requests have been reset.", "success")

    except Exception as e:
        if conn:
            conn.rollback()
        flash(f"Error resetting late mess requests: {e}", "danger")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return redirect(url_for('late_mess_list'))  # ✅ Correct endpoint


from flask import jsonify

# Approve Late Mess
@app.route('/admin/approve_late/<int:late_mess_id>', methods=['POST'])
@login_required
def approve_late(late_mess_id):
    if not current_user.is_admin:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    conn, cur = None, None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("UPDATE late_mess SET status = 'approved' WHERE id = %s", (late_mess_id,))
        conn.commit()

        return jsonify({"success": True, "message": "Late mess approved"})

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": f"Error approving late mess: {str(e)}"}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
# ----------------- START APP -----------------
# ----------------- START APP -----------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # fallback for local testing
    app.run(host="0.0.0.0", port=port)

