from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
import io
import base64
from datetime import datetime, time
from config import Config
from mysql.connector import pooling
from flask_mysqldb import MySQL


# ---------------- Flask App ----------------
app = Flask(__name__)

dbconfig = {
    "host": "localhost",    # or "localhost"
    "user": "root",         # your MySQL username
    "password": "mysql123",         # your MySQL password
    "database": "w_mess_app"  # your database name
}
# ---------------- MySQL Connection Pool ----------------
# app.py (or wherever you configure your DB)
import os
from mysql.connector import pooling, Error
from mysql.connector import pooling

mysql_pool = pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=5,
    pool_reset_session=True,
    host="mydb.cfc0uui6evlw.eu-north-1.rds.amazonaws.com",  # ✅ RDS endpoint
    database="mess_app",  # ✅ your database name
    user="root",          # ✅ your RDS username
    password="Admin321"   # ✅ your RDS password
)
app = Flask(__name__)
app.config.from_object(Config)

mysql = MySQL(app)
# Connect directly
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='mysql123',
        database='w_mess_app'
    )
# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------- USER CLASS ----------------
class User(UserMixin):
    def __init__(self, id, name, email, user_type):
        self.id = id
        self.name = name
        self.email = email
        self.user_type = user_type
        self.is_admin = user_type == 'admin'


# --- Setup MySQL connection pool ---
try:
    mysql_pool = pooling.MySQLConnectionPool(
        pool_name="mypool",
        pool_size=10,          # number of connections in the pool
        pool_reset_session=True,
        **dbconfig
    )
    print("✅ MySQL connection pool created successfully")
except Error as e:
    print(f"❌ Error creating MySQL connection pool: {e}")
    raise

# --- Helper function to get connection ---
def get_db_connection():
    try:
        return mysql_pool.get_connection()
    except Error as e:
        print(f"❌ Error getting connection from pool: {e}")
        raise


# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------- USER CLASS ----------------
class User(UserMixin):
    def __init__(self, id, name, email, user_type):
        self.id = id
        self.name = name
        self.email = email
        self.user_type = user_type
        self.is_admin = user_type == 'admin'

# ---------------- USER LOADER WITH POOL ----------------
@login_manager.user_loader
def load_user(user_id):
    conn = mysql_pool.get_connection()             # Get connection from pool
    cur = conn.cursor(dictionary=True)            # DictCursor equivalent
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    data = cur.fetchone()
    cur.close()
    conn.close()                                  # Return connection to pool
    if data:
        return User(data['id'], data['name'], data['email'], data['user_type'])
    return None

# ---------------- CREATE ADMIN ----------------
# ---------------- CREATE ADMIN ----------------
# ---------------- CREATE ADMIN ----------------
from werkzeug.security import generate_password_hash

def create_admin():
    conn = mysql_pool.get_connection()             # Get connection from pool
    cur = conn.cursor(dictionary=True)            # DictCursor equivalent

    # Check if admin already exists
    cur.execute("SELECT * FROM users WHERE email = %s", ("hostelmess@gmail.com",))
    admin = cur.fetchone()

    hashed_password = generate_password_hash("hostel@123")

    if not admin:
        # Insert new admin
        cur.execute("""
            INSERT INTO users (name, email, phone, course, password, user_type, approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ("Admin", "hostelmess@gmail.com", "0000000000", "N/A", hashed_password, "admin", 1))
        conn.commit()
        print("✅ Default admin created: hostelmess@gmail.com, password=hostel@123")
    else:
        # Make sure admin is approved and user_type is admin
        cur.execute("""
            UPDATE users
            SET user_type=%s, approved=%s, password=%s
            WHERE email=%s
        """, ("admin", 1, hashed_password, "hostelmess@gmail.com"))
        conn.commit()
        print("ℹ️ Admin already exists. Reset password and ensured approved=1.")

    cur.close()
    conn.close()  # Return connection to pool


# -----------------------------
# Call this once at startup
# -----------------------------
with app.app_context():
    create_admin()






# ---------------- ROUTES ----------------

@app.route('/')
def index():
    return render_template("index.html")


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
        food_type = request.form['food_type']  # veg or non-veg  ✅

        # Basic required fields check
        if not name or not email or not password or not user_type or not food_type:
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        # Phone number validation: must be 10 digits
        if not phone.isdigit() or len(phone) != 10:
            flash("Phone number must be exactly 10 digits.", "danger")
            return redirect(url_for('register'))

        # ---------------- POOL CONNECTION ----------------
        conn = mysql_pool.get_connection()
        cur = conn.cursor(dictionary=True)

        # Hash the password
        hashed_password = generate_password_hash(password)

        try:
            # Insert into new_users table (added food_type)
            cur.execute("""
                INSERT INTO new_users (name, email, phone, course, password, user_type, food_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (name, email, phone, course, hashed_password, user_type, food_type))
            conn.commit()
            flash("Registration successful! Await admin approval.", "success")
        except Exception as e:
            flash(f"Database error: {e}", "danger")
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')



# REPLACE your current /new_users route with this

# ---------------- NEW USERS LIST ----------------
@app.route('/new_users')
@login_required
def new_users_list():
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))

    conn = mysql_pool.get_connection()          # Get connection from pool
    cur = conn.cursor(dictionary=True)          # DictCursor equivalent
    cur.execute("SELECT * FROM new_users")
    users = cur.fetchall()
    cur.close()
    conn.close()                                # Return connection to pool

    return render_template("new_users.html", users=users)


# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = mysql_pool.get_connection()       # Get connection from pool
        cur = conn.cursor(dictionary=True)      # DictCursor equivalent
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()                            # Return connection to pool

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
    conn = mysql_pool.get_connection()            # Get connection from pool
    cur = conn.cursor()                           # Regular cursor, no dict needed
    hashed_password = generate_password_hash("admin123")

    try:
        # Delete duplicates
        cur.execute("DELETE FROM users WHERE email=%s", ("admin@example.com",))

        # Insert fresh admin
        cur.execute("""
            INSERT INTO users (name, email, phone, course, password, user_type, approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ("Admin", "hostelmess@gmail.com", "0000000000", "N/A",
              hashed_password, "admin", 1))
        conn.commit()
    except Exception as e:
        return f"❌ Database error: {e}"
    finally:
        cur.close()
        conn.close()                              # Return connection to pool

    return "✅ Admin reset: hostelmess@gmail.com, password=hostel@123"


#Approval

from flask import send_file, flash, redirect, url_for
import qrcode
import os
from flask_login import login_required, current_user

@app.route('/approve_user/<int:user_id>')
@login_required
def approve_user(user_id):
    if not current_user.is_admin:   # ensure only admin can approve
        flash("❌ Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    conn = mysql_pool.get_connection()         # Get connection from pool
    cur = conn.cursor(dictionary=True)         # DictCursor equivalent

    try:
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
            INSERT INTO users (name, email, phone, course, password, user_type,food_type, approved, qr_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s ,%s )
        """, (
            user['name'], user['email'], user['phone'], user['course'],
            user['password'], user['user_type'],user['food_type'], 1, ""
        ))

        new_user_id = cur.lastrowid

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

        # Store relative path so template can use {{ url_for('static', filename='qrcodes/xxx.png') }}
        db_qr_path = f"qrcodes/{qr_filename}"

        # 5. Update QR path in users table
        cur.execute("UPDATE users SET qr_path = %s WHERE id = %s", (db_qr_path, new_user_id))

        # 6. Delete from new_users
        cur.execute("DELETE FROM new_users WHERE id=%s", (user_id,))

        # ✅ Commit once after all queries
        conn.commit()

        flash("✅ User approved successfully and QR code generated.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"❌ Error approving user: {str(e)}", "danger")
        print("Approve user error:", e)  # debug log

    finally:
        cur.close()
        conn.close()                          # Return connection to pool

    return redirect(url_for('new_users_list'))




# ---------------- REJECT USER ----------------
@app.route('/reject_user/<int:user_id>')
def reject_user(user_id):
    conn = mysql_pool.get_connection()          # Get connection from pool
    cur = conn.cursor(dictionary=True)          # DictCursor equivalent

    try:
        cur.execute("DELETE FROM new_users WHERE id = %s", (user_id,))
        conn.commit()
        flash("User rejected and removed.", "danger")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error rejecting user: {e}", "danger")
        print("Reject user error:", e)
    finally:
        cur.close()
        conn.close()                            # Return connection to pool

    return redirect(url_for('new_users_list'))

# ---------------- LOGOUT ----------------
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
    import io, base64, qrcode

    # ---------------- Generate QR code ----------------
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(str(current_user.id))
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_b64 = base64.b64encode(buffer.getvalue()).decode('ascii')

    # ---------------- Fetch late mess requests ----------------
    conn = mysql_pool.get_connection()         # Get connection from pool
    cur = conn.cursor(dictionary=True)         # DictCursor equivalent

    try:
        cur.execute(
            "SELECT * FROM late_mess WHERE user_id = %s ORDER BY date_requested DESC",
            (current_user.id,)
        )
        late_requests = cur.fetchall()
    except Exception as e:
        flash(f"❌ Error fetching late mess requests: {e}", "danger")
        late_requests = []
        print("Dashboard DB error:", e)
    finally:
        cur.close()
        conn.close()                            # Return connection to pool

    return render_template('dashboard.html', qr_code=qr_code_b64, late_requests=late_requests)


# -------- ADMIN DASHBOARD --------
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))
    return render_template('admin_base.html')



# -------- ADMIN: USERS LIST --------
# ---------------- ADMIN: LIST USERS ----------------
@app.route('/admin/users')
@login_required
def users_list():
    conn = mysql_pool.get_connection()          # Get connection from pool
    cur = conn.cursor(dictionary=True)          # DictCursor equivalent

    try:
        cur.execute("SELECT * FROM users")
        users = cur.fetchall()
    except Exception as e:
        flash(f"❌ Error fetching users: {e}", "danger")
        users = []
        print("Admin users_list DB error:", e)
    finally:
        cur.close()
        conn.close()                            # Return connection to pool

    return render_template('admin_users.html', users=users)


# ---------------- ADMIN: DELETE USER ----------------
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    conn = mysql_pool.get_connection()          # Get connection from pool
    cur = conn.cursor()                          # Regular cursor

    try:
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        flash("User deleted successfully", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error deleting user: {e}", "danger")
        print("Admin delete_user DB error:", e)
    finally:
        cur.close()
        conn.close()                             # Return connection to pool

    return redirect(url_for('users_list'))





from datetime import datetime
from flask import request, jsonify, flash, redirect, url_for, render_template
from flask_login import login_required, current_user

# ---------------- USER: MY MESS CUTS ----------------
@app.route('/my_mess_cuts')
@login_required
def my_mess_cuts():
    conn = mysql_pool.get_connection()            # Get connection from pool
    cur = conn.cursor(dictionary=True)            # DictCursor equivalent

    try:
        cur.execute(
            "SELECT * FROM mess_cut WHERE user_id=%s ORDER BY start_date DESC",
            (current_user.id,)
        )
        cuts = cur.fetchall()
    except Exception as e:
        flash(f"❌ Error fetching mess cuts: {e}", "danger")
        cuts = []
        print("my_mess_cuts DB error:", e)
    finally:
        cur.close()
        conn.close()                              # Return connection to pool

    # Convert start_date/end_date to date objects and calculate number of days
    for cut in cuts:
        if isinstance(cut['start_date'], str):
            cut['start_date'] = datetime.strptime(cut['start_date'], "%Y-%m-%d").date()
        if isinstance(cut['end_date'], str):
            cut['end_date'] = datetime.strptime(cut['end_date'], "%Y-%m-%d").date()
        cut['num_days'] = (cut['end_date'] - cut['start_date']).days + 1

    return render_template('my_mess_cuts.html', cuts=cuts)


# ---------------- ADMIN: VALIDATE QR ----------------
@app.route('/admin/validate_qr', methods=['POST'])
@login_required
def validate_qr():
    if not current_user.is_admin:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.get_json()
    qr_data = data.get("qr_data", "")

    # Assuming QR is "user_id:{id},email:{email}"
    try:
        parts = dict(part.split(":") for part in qr_data.split(","))
        user_id = int(parts.get("user_id"))
    except:
        return jsonify({"success": False, "message": "Invalid QR code"}), 400

    conn = mysql_pool.get_connection()             # Get connection from pool
    cur = conn.cursor(dictionary=True)             # DictCursor equivalent

    try:
        cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
    except Exception as e:
        print("validate_qr DB error:", e)
        return jsonify({"success": False, "message": "Database error"}), 500
    finally:
        cur.close()
        conn.close()                               # Return connection to pool

    if user:
        # Optional: update attendance or mess count here
        return jsonify({"success": True, "message": f"{user['name']} is valid."})
    else:
        return jsonify({"success": False, "message": "User not found."})




from datetime import datetime, date, timedelta
from flask import flash, redirect, url_for, render_template, request
from flask_login import login_required, current_user

@app.template_filter('add_days')
def add_days_filter(value, days):
    """Add `days` to a date string in YYYY-MM-DD format."""
    dt = datetime.strptime(value, "%Y-%m-%d").date()
    return (dt + timedelta(days=days)).isoformat()


# ---------------- USER: APPLY MESS CUT ----------------
@app.route('/apply_mess_cut', methods=['GET', 'POST'])
@login_required
def apply_mess_cut():
    today = date.today()
    tomorrow = today + timedelta(days=1)
    current_time = datetime.now().time()
    cutoff_time = datetime.strptime("22:00", "%H:%M").time()  # 10 PM
    min_end_date = today + timedelta(days=3)

    if request.method == 'POST':
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')

        if not start_date_str or not end_date_str:
            flash("Start and end dates are required.", "danger")
            return redirect(url_for('apply_mess_cut'))

        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()

        # Cannot select past dates
        if start_date <= today or end_date <= today:
            flash("Cannot select today or past dates.", "danger")
            return redirect(url_for('apply_mess_cut'))

        # Cannot apply for tomorrow after 10 PM
        if start_date == tomorrow and current_time >= cutoff_time:
            flash("Cannot apply mess cut for tomorrow after 10 PM today.", "danger")
            return redirect(url_for('apply_mess_cut'))

        # Minimum 3-day range
        if (end_date - start_date).days + 1 < 3:
            flash("Minimum duration is 3 consecutive days.", "danger")
            return redirect(url_for('apply_mess_cut'))

        # ---------------- POOL CONNECTION ----------------
        conn = mysql_pool.get_connection()  # Get connection from pool

        try:
            # Use buffered cursor to avoid "Unread result found"
            with conn.cursor(dictionary=True, buffered=True) as cur:
                # Check overlapping
                cur.execute("""
                    SELECT * FROM mess_cut
                    WHERE user_id=%s AND (
                        (start_date <= %s AND end_date >= %s) OR
                        (start_date <= %s AND end_date >= %s) OR
                        (start_date >= %s AND end_date <= %s)
                    )
                """, (current_user.id, start_date, start_date, end_date, end_date, start_date, end_date))
                overlapping = cur.fetchone()
                if overlapping:
                    flash("You already have a mess cut that overlaps these dates.", "danger")
                    return redirect(url_for('apply_mess_cut'))

                # Fetch user's course
                cur.execute("SELECT course FROM users WHERE id=%s", (current_user.id,))
                user = cur.fetchone()
                if not user or not user.get('course'):
                    flash("Course not found. Please update your profile.", "danger")
                    return redirect(url_for('apply_mess_cut'))

                course = user['course']

                # Insert mess cut
                cur.execute("""
                    INSERT INTO mess_cut (user_id, start_date, end_date, course, date_applied)
                    VALUES (%s, %s, %s, %s, NOW())
                """, (current_user.id, start_date, end_date, course))
                conn.commit()

            flash("Mess cut applied successfully!", "success")
            return redirect(url_for('my_mess_cuts'))

        except Exception as e:
            conn.rollback()
            flash(f"Database error: {e}", "danger")
            print("apply_mess_cut DB error:", e)
            return redirect(url_for('apply_mess_cut'))

        finally:
            conn.close()  # Return connection to pool

    # GET request: render form
    return render_template(
        'apply_mess_cut.html',
        min_start_date=(today + timedelta(days=1)).isoformat(),  # can't select today
        min_end_date=min_end_date.isoformat()
    )


from datetime import datetime, timedelta
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required, current_user

# ---------------- ADMIN: MESS CUT LIST ----------------
@app.route('/admin/mess_cuts', methods=['GET'])
@login_required
def mess_cut_list():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    # Month filter for listing
    month_filter = request.args.get('month', datetime.now().strftime("%Y-%m"))
    filter_year, filter_month = map(int, month_filter.split("-"))

    conn = mysql_pool.get_connection()          # Get connection from pool
    cur = conn.cursor(dictionary=True)          # DictCursor equivalent

    try:
        query = """
            SELECT m.user_id, u.name, u.course, m.start_date, m.end_date
            FROM mess_cut m
            JOIN users u ON m.user_id = u.id
            WHERE (m.start_date <= LAST_DAY(%s) AND m.end_date >= %s)
            ORDER BY u.name, m.start_date
        """
        month_start = f"{filter_year}-{filter_month:02d}-01"
        cur.execute(query, (month_start, month_start))
        cuts = cur.fetchall()
    except Exception as e:
        flash(f"❌ Error fetching mess cuts: {e}", "danger")
        cuts = []
        print("mess_cut_list DB error:", e)
    finally:
        cur.close()
        conn.close()                            # Return connection to pool

    # Organize cuts by user
    cuts_by_user = {}
    for cut in cuts:
        user_id = cut['user_id']
        start_date = cut['start_date']
        end_date = cut['end_date']

        # Convert to datetime.date if needed
        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, "%Y-%m-%d").date()

        # Clip dates to selected month
        month_start_date = datetime(filter_year, filter_month, 1).date()
        next_month = datetime(filter_year + filter_month // 12, (filter_month % 12) + 1, 1).date()
        month_end_date = next_month - timedelta(days=1)

        effective_start = max(start_date, month_start_date)
        effective_end = min(end_date, month_end_date)
        total_days = (effective_end - effective_start).days + 1

        if total_days <= 0:
            continue  # Skip if no overlap

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

    # Calculate total number of mess cuts for tomorrow
    tomorrow = datetime.now().date() + timedelta(days=1)
    tomorrow_count = 0
    for cut in cuts:
        start_date = cut['start_date']
        end_date = cut['end_date']

        # Convert to date if needed
        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, "%Y-%m-%d").date()

        if start_date <= tomorrow <= end_date:
            tomorrow_count += 1

    # Pass data to template
    return render_template(
        'mess_cut_list.html',
        cuts_by_user=cuts_by_user,
        month_filter=month_filter,
        tomorrow_count=tomorrow_count
    )





# -------- USER: REQUEST LATE MESS --------
from datetime import datetime, time
import pytz
from flask import flash, redirect, url_for, render_template, request
from flask_login import login_required, current_user

# ---------------- USER: REQUEST LATE MESS ----------------
@app.route('/request_late_mess', methods=['GET', 'POST'])
@login_required
def request_late_mess():
    # Use IST timezone
    tz = pytz.timezone("Asia/Kolkata")
    now = datetime.now(tz)
    now_time = now.time()
    today = now.date()

    # Allowed time window: 4:00 PM - 8:30 PM IST
    start_time = time(16, 0)  # 16:00
    end_time = time(20, 30)   # 20:30

    conn = mysql_pool.get_connection()
    # ✅ Use buffered cursor so all results are consumed
    cur = conn.cursor(dictionary=True, buffered=True)

    try:
        # ✅ Check if user is under mess cut (start, end, or in between)
        cur.execute("""
            SELECT * FROM mess_cut 
            WHERE user_id=%s AND %s BETWEEN start_date AND end_date
        """, (current_user.id, today))
        mess_cut = cur.fetchone()  # buffered=True ensures all results are consumed

        if mess_cut:
            flash("❌ You cannot request late mess because you are under a mess cut today.", "danger")
            can_request = False
        else:
            can_request = start_time <= now_time <= end_time

        if request.method == 'POST':
            if not can_request:
                flash("You cannot request late mess at this time or due to a mess cut.", "warning")
                return redirect(url_for('request_late_mess'))

            reason = request.form.get("reason")  # ✅ capture reason

            # Check if the user already requested today
            cur.execute(
                "SELECT * FROM late_mess WHERE user_id=%s AND date_requested=%s",
                (current_user.id, today)
            )
            existing = cur.fetchone()
            if existing:
                flash("ℹ️ You have already requested late mess today.", "info")
            else:
                cur.execute("""
                    INSERT INTO late_mess(user_id, date_requested, reason, status)
                    VALUES (%s, %s, %s, %s)
                """, (current_user.id, today, reason, "pending"))
                conn.commit()
                flash("✅ Late mess requested successfully!", "success")

            return redirect(url_for('request_late_mess'))

        # GET request: fetch previous requests
        cur.execute(
            "SELECT * FROM late_mess WHERE user_id=%s ORDER BY date_requested DESC",
            (current_user.id,)
        )
        late_requests = cur.fetchall()

    except Exception as e:
        conn.rollback()
        flash(f"❌ Database error: {e}", "danger")
        late_requests = []
        print("request_late_mess DB error:", e)

    finally:
        cur.close()
        conn.close()

    return render_template(
        'request_late_mess.html',
        late_requests=late_requests,
        can_request=can_request,
        now_time=now_time.strftime("%H:%M"),
        start_time=start_time.strftime("%H:%M"),
        end_time=end_time.strftime("%H:%M")
    )



# ---------------- USER: GENERATE QR ----------------
@app.route('/my_qr')
@login_required
def my_qr():
    conn = mysql_pool.get_connection()          # Get connection from pool
    cur = conn.cursor(dictionary=True)          # DictCursor equivalent

    try:
        cur.execute("SELECT mess_count FROM users WHERE id=%s", (current_user.id,))
        data = cur.fetchone()
        mess_count = data['mess_count'] if data else 0
    except Exception as e:
        print("my_qr DB error:", e)
        mess_count = 0
    finally:
        cur.close()
        conn.close()                            # Return connection to pool

    qr_data = f"user_id:{current_user.id},email:{current_user.email},mess_count:{mess_count}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    return send_file(img_bytes, mimetype='image/png')


# ---------------- ADMIN: SCAN QR ----------------
@app.route('/admin/qr_scan')
@login_required
def admin_qr_scan():
    if not getattr(current_user, 'is_admin', False):
        return "Unauthorized", 403
    return render_template('admin_qr_scan.html', current_date=date.today().strftime("%Y-%m-%d"))



from flask import jsonify, request
from flask_login import login_required, current_user
from datetime import date
import MySQLdb.cursors

# In-memory live count cache
live_counts = {'breakfast': 0, 'lunch': 0, 'dinner': 0}

@app.route('/admin/scan_qr', methods=['POST'])
@login_required
def scan_qr():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json(silent=True) or request.form
    user_id = data.get('user_id')
    meal_type = data.get('meal_type')
    today = date.today()

    if not user_id or meal_type not in ['breakfast', 'lunch', 'dinner']:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400

    conn = mysql_pool.get_connection()  # Get connection from pool
    try:
        with conn.cursor(dictionary=True, buffered=True) as cur:  
            # 🔹 Fetch user name
            cur.execute("SELECT name FROM users WHERE id=%s", (user_id,))
            user = cur.fetchone()
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404

            # 🔹 Check mess cut
            cur.execute("""
                SELECT 1 FROM mess_cut
                WHERE user_id=%s AND start_date <= %s AND end_date >= %s
            """, (user_id, today, today))
            if cur.fetchone():
                return jsonify({
                    'success': False,
                    'message': 'User has a mess cut today. Scan not allowed.',
                    'name': user['name']
                }), 403

            # 🔹 Check mess skip in mess_skips table
            cur.execute(f"""
                SELECT {meal_type} FROM mess_skips
                WHERE user_id=%s AND skip_date=%s
            """, (user_id, today))
            skip = cur.fetchone()
            if skip and skip[meal_type] == 1:
                return jsonify({
                    'success': False,
                    'message': f'User has skipped {meal_type} today.',
                    'name': user['name']
                }), 403

            # 🔹 Check duplicate scan
            cur.execute("""
                SELECT id FROM meal_attendance
                WHERE user_id=%s AND meal_type=%s AND attendance_date=%s
            """, (user_id, meal_type, today))
            if cur.fetchone():
                return jsonify({
                    'success': False,
                    'message': f'Already scanned for {meal_type} today',
                    'name': user['name']
                }), 400

            # 🔹 Insert attendance
            cur.execute("""
                INSERT INTO meal_attendance (user_id, meal_type, attendance_date)
                VALUES (%s, %s, %s)
            """, (user_id, meal_type, today))

            # 🔹 Increment mess_count
            cur.execute("UPDATE users SET mess_count = mess_count + 1 WHERE id = %s", (user_id,))
            conn.commit()

            # 🔹 Increment temporary live counter
            live_counts[meal_type] += 1  

            # 🔹 Get updated count from DB
            cur.execute("""
                SELECT COUNT(*) AS count FROM meal_attendance
                WHERE meal_type=%s AND attendance_date=%s
            """, (meal_type, today))
            result = cur.fetchone()

            return jsonify({
                'success': True,
                'name': user['name'],
                'count': result['count'],
                'live_count': live_counts[meal_type]
            })

    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

    finally:
        conn.close()


# -------- ADMIN: VIEW CONFIRMED QR COUNTS --------
from flask import render_template, jsonify, request, flash
from datetime import date
import MySQLdb

# ---------------- TEMP LIVE COUNTERS ----------------
live_counts = {"breakfast": 0, "lunch": 0, "dinner": 0}

# ---------------- ADMIN: VIEW QR SCAN COUNTS ----------------
@app.route('/admin/qr_scan_counts')
@login_required
def qr_scan_counts():
    counts_by_date = {}
    conn = mysql_pool.get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT meal_date, meal_type, total_count
            FROM daily_meal_attendance
            ORDER BY meal_date ASC   -- calendar order
        """)
        rows = cur.fetchall()

        for row in rows:
            date_obj = row[0]          # might be date/datetime OR string
            meal = row[1]
            count = row[2]

            # Ensure we always have a date object
            from datetime import datetime, date
            if isinstance(date_obj, str):
                date_obj = datetime.strptime(date_obj, "%Y-%m-%d").date()
            elif isinstance(date_obj, datetime):
                date_obj = date_obj.date()  # strip time if needed

            if date_obj not in counts_by_date:
                counts_by_date[date_obj] = {'breakfast': 0, 'lunch': 0, 'dinner': 0}
            counts_by_date[date_obj][meal] = count

    except Exception as e:
        flash(f"Error fetching counts: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    from calendar import month_name
    from datetime import datetime

    months = [{'value': f"{datetime.now().year}-{i:02}", 'name': month_name[i]} for i in range(1, 13)]

    # Sort ascending
    sorted_counts = []
    for date_obj, meals in sorted(counts_by_date.items(), key=lambda x: x[0]):
        sorted_counts.append({
            "date": date_obj.strftime("%d-%m-%Y"),   # formatted for display
            "month_key": date_obj.strftime("%Y-%m"), # for filtering
            "meals": meals
        })

    return render_template("admin_qr_count.html", counts_by_date=sorted_counts, months=months)



# ---------------- ADMIN: GET LIVE COUNT ----------------
@app.route('/admin/live_count/<meal_type>')
@login_required
def get_live_count(meal_type):
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    return jsonify({'success': True, 'count': live_counts.get(meal_type, 0)})


# ---------------- ADMIN: RESET LIVE COUNT ----------------
@app.route('/admin/reset_count', methods=['POST'])
@login_required
def reset_count():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    meal = request.json.get('meal_type')
    today = date.today()
    conn = mysql_pool.get_connection()
    cur = conn.cursor()

    try:
        # Clear today's attendance for that meal (so users can re-scan)
        cur.execute("""
            DELETE FROM meal_attendance
            WHERE meal_type=%s AND attendance_date=%s
        """, (meal, today))
        conn.commit()

        # Reset live count only
        live_counts[meal] = 0

        return jsonify({'success': True, 'message': f'{meal.capitalize()} reset done'})

    except MySQLdb.Error as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)})

    finally:
        cur.close()
        conn.close()


from flask import jsonify, render_template
from datetime import date
import MySQLdb

# ---------------- ADMIN: LIVE COUNT FOR TODAY ----------------
@app.route('/admin/live_count/<meal_type>')
@login_required
def live_count(meal_type):
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    today = date.today()
    conn = mysql_pool.get_connection()          # Get connection from pool
    cur = conn.cursor(dictionary=True)          # DictCursor

    try:
        cur.execute("""
            SELECT COUNT(*) AS total FROM meal_attendance
            WHERE attendance_date=%s AND meal_type=%s
        """, (today, meal_type))
        result = cur.fetchone()
        total = result['total'] if result else 0
    except MySQLdb.Error as e:
        total = 0
        print("DB error in live_count:", e)
    finally:
        cur.close()
        conn.close()                            # Return connection to pool

    return jsonify({'success': True, 'meal_type': meal_type, 'count': total})


# ---------------- ADMIN: VIEW HISTORICAL QR SCAN COUNTS ----------------
@app.route('/admin/qr_scan_counts')
@login_required
def admin_qr_count():
    if not getattr(current_user, 'is_admin', False):
        flash("Unauthorized access", "danger")
        return redirect(url_for('user_dashboard'))

    counts_by_date = {}
    conn = mysql_pool.get_connection()          # Get connection from pool
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT meal_date, meal_type, total_count
            FROM daily_meal_attendance
            ORDER BY meal_date ASC
        """)
        rows = cur.fetchall()

        for row in rows:
            date_str = row[0].strftime("%Y-%m-%d")
            meal_type = row[1]
            count = row[2]

            if date_str not in counts_by_date:
                counts_by_date[date_str] = {}
            counts_by_date[date_str][meal_type] = count

    except MySQLdb.Error as e:
        flash(f"Error fetching counts: {e}", "danger")
    finally:
        cur.close()
        conn.close()                            # Return connection to pool

    return render_template("admin_qr_count.html", counts_by_date=counts_by_date)





from flask import jsonify, request
from datetime import date
import MySQLdb

@app.route('/admin/add_count', methods=['POST'])
@login_required
def add_count():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json(silent=True) or request.form
    meal_type = data.get('meal_type')
    meal_date = data.get('meal_date') or date.today().isoformat()

    if meal_type not in ['breakfast', 'lunch', 'dinner']:
        return jsonify({'success': False, 'message': 'Invalid meal type'}), 400

    count = live_counts.get(meal_type, 0)
    if count == 0:
        return jsonify({'success': False, 'message': 'No live count to save'}), 400

    conn = mysql_pool.get_connection()   # Get connection from pool
    cur = conn.cursor()

    try:
        # Insert or update total count
        cur.execute("""
            INSERT INTO daily_meal_attendance (meal_date, meal_type, total_count)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE total_count = total_count + VALUES(total_count)
        """, (meal_date, meal_type, count))
        conn.commit()

        # Reset live count
        live_counts[meal_type] = 0

        return jsonify({
            'success': True,
            'meal_type': meal_type,
            'total_people_added': count,
            'meal_date': meal_date
        })

    except MySQLdb.Error as e:
        conn.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

    finally:
        cur.close()
        conn.close()  # Return connection to pool


from flask import flash, redirect, url_for, render_template, request
import MySQLdb

@app.route('/admin/add_meal_count', methods=['GET', 'POST'])
@login_required
def add_meal_count():
    if not getattr(current_user, 'is_admin', False):
        flash("Unauthorized access", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        meal_date = request.form.get('meal_date')
        meal_type = request.form.get('meal_type')

        if not meal_date or meal_type not in ['breakfast', 'lunch', 'dinner']:
            flash("Invalid input", "danger")
            return redirect(url_for('add_meal_count'))

        conn = mysql_pool.get_connection()  # Get connection from pool
        cur = conn.cursor()

        try:
            # Insert or update count
            cur.execute("""
                INSERT INTO meal_counts (meal_date, meal_type, count)
                VALUES (%s, %s, 1)
                ON DUPLICATE KEY UPDATE count = count + 1
            """, (meal_date, meal_type))
            conn.commit()
            flash(f"{meal_type.capitalize()} count added for {meal_date}", "success")

        except Exception as e:
            conn.rollback()
            flash(f"Database error: {str(e)}", "danger")

        finally:
            cur.close()
            conn.close()  # Return connection to pool

        return redirect(url_for('add_meal_count'))

    # ---------------- GET: fetch counts ----------------
    conn = mysql_pool.get_connection()
    cur = conn.cursor(MySQLdb.cursors.DictCursor)

    try:
        cur.execute("SELECT meal_date, meal_type, count FROM meal_counts ORDER BY meal_date DESC")
        rows = cur.fetchall()
    except Exception as e:
        flash(f"Database error: {str(e)}", "danger")
        rows = []
    finally:
        cur.close()
        conn.close()  # Return connection to pool

    # Organize by date
    counts_by_date = {}
    for row in rows:
        date_str = row['meal_date'].strftime("%Y-%m-%d")
        if date_str not in counts_by_date:
            counts_by_date[date_str] = {}
        counts_by_date[date_str][row['meal_type']] = row['count']

    return render_template("admin_meal_count.html", counts_by_date=counts_by_date)


from flask import jsonify, flash, redirect, url_for, render_template, request
from datetime import date
import MySQLdb

# ---------------- ADMIN: Get today's meal counts per user ----------------
@app.route('/admin/users_meal_counts')
@login_required
def users_meal_counts():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized: admin only'}), 403

    today = date.today()
    counts = {}

    conn = mysql_pool.get_connection()
    cur = conn.cursor(MySQLdb.cursors.DictCursor)

    try:
        for meal in ['breakfast', 'lunch', 'dinner']:
            cur.execute("""
                SELECT u.name, u.email, u.course, COUNT(ma.id) AS total_scans
                FROM meal_attendance ma
                JOIN users u ON ma.user_id = u.id
                WHERE ma.meal_type=%s AND ma.attendance_date=%s
                GROUP BY ma.user_id
            """, (meal, today))
            counts[meal] = cur.fetchall()

        return jsonify({'success': True, 'data': counts})

    except MySQLdb.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

    finally:
        cur.close()
        conn.close()  # Return connection to pool


# ---------------- ADMIN: Add mess cut for any user ----------------
# ---------------- ADMIN: Add mess cut for any user ----------------
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
import mysql.connector
from datetime import datetime

@app.route('/admin/add_mess_cut', methods=['GET', 'POST'])
@login_required
def add_mess_cut_admin():
    if not getattr(current_user, 'is_admin', False):
        flash("Unauthorized access", "danger")
        return redirect(url_for('admin_dashboard'))

    conn = None
    cur = None
    users = []

    try:
        # ✅ Get connection from pool
        conn = mysql_pool.get_connection()
        cur = conn.cursor(dictionary=True)

        # ✅ Adjust these column names to match your DB!
        cur.execute("SELECT id, name, course FROM users")
        users = cur.fetchall()
        print("DEBUG USERS FETCHED:", users)

        if request.method == 'POST':
            user_id = request.form['user_id']
            start_date = request.form['start_date']
            end_date = request.form['end_date']

            # validate dates
            start_obj = datetime.strptime(start_date, "%Y-%m-%d")
            end_obj = datetime.strptime(end_date, "%Y-%m-%d")
            if start_obj > end_obj:
                flash("❌ Start date cannot be after end date!", "danger")
                return redirect(url_for('add_mess_cut_admin'))

            # ✅ Insert into mess_cut
            cur.execute(
                "INSERT INTO mess_cut (user_id, start_date, end_date) VALUES (%s, %s, %s)",
                (user_id, start_date, end_date)
            )
            conn.commit()
            flash("✅ Mess cut added successfully!", "success")
            return redirect(url_for('add_mess_cut_admin'))

    except mysql.connector.Error as e:
        if conn:
            conn.rollback()
        flash(f"Database error: {str(e)}", "danger")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return render_template('admin_add_mess_cut.html', users=users)


from datetime import date, datetime, timedelta
import calendar
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required, current_user

from datetime import date, datetime, timedelta
import calendar
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required, current_user

@app.route('/admin/generate_bills', methods=['GET', 'POST'])
@login_required
def generate_bills():
    if not getattr(current_user, 'is_admin', False):
        flash("Unauthorized", "danger")
        return redirect(url_for('admin_dashboard'))

    bills_generated = []
    conn = None
    cur = None

    if request.method == 'POST':
        try:
            daily_amount = float(request.form.get('daily_amount', 0))
            establishment_fee = float(request.form.get('establishment_fee', 0))
            bill_month = request.form.get('bill_month')  # format: 'YYYY-MM'

            if not daily_amount or not bill_month:
                flash("Please provide all required fields", "warning")
                return redirect(url_for('generate_bills'))

            # Compute first and last day of the month
            year, month = map(int, bill_month.split('-'))
            start_date_obj = date(year, month, 1)
            end_date_obj = date(year, month, calendar.monthrange(year, month)[1])

            # Parse mess closed dates (optional)
            closed_dates_str = request.form.get('mess_closed_dates', '')
            closed_dates = set()
            if closed_dates_str:
                closed_dates = set(datetime.strptime(d.strip(), "%d-%m-%Y").date() for d in closed_dates_str.split(','))

            # Active days in month minus closed dates
            active_days = (end_date_obj - start_date_obj).days + 1
            active_days -= sum(1 for d in closed_dates if start_date_obj <= d <= end_date_obj)

            # DB connection
            conn = mysql_pool.get_connection()
            cur = conn.cursor(dictionary=True)

            # Fetch all users
            cur.execute("SELECT id, name FROM users")
            users = cur.fetchall()

            for user in users:
                # Skip bills already generated for this month
                cur.execute("""
                    SELECT id FROM bills
                    WHERE user_id=%s AND bill_date BETWEEN %s AND %s
                """, (user['id'], start_date_obj, end_date_obj))
                if cur.fetchone():
                    continue

                # Fetch mess cuts overlapping with the month
                cur.execute("""
                    SELECT start_date, end_date
                    FROM mess_cut
                    WHERE user_id=%s
                      AND start_date <= %s
                      AND end_date >= %s
                """, (user['id'], end_date_obj, start_date_obj))
                cuts = cur.fetchall()

                mess_cut_days = 0
                for cut in cuts:
                    cut_start = max(cut['start_date'], start_date_obj)
                    cut_end = min(cut['end_date'], end_date_obj)

                    # Generate all dates in this mess cut
                    cut_dates = set(cut_start + timedelta(days=i) for i in range((cut_end - cut_start).days + 1))
                    # Only consider dates which are NOT closed
                    active_cut_dates = cut_dates - closed_dates

                    # Apply only if >=3 active days
                    if len(active_cut_dates) >= 3:
                        mess_cut_days += len(active_cut_dates)

                # Calculate reduction
                reduction_amount = round(0.67 * daily_amount * mess_cut_days, 2)

                # 🔹 Fetch fines for this user in billing month (scan fines included)
                cur.execute("""
                    SELECT SUM(fine_amount) AS total_fines
                    FROM fines
                    WHERE user_id=%s AND fine_date BETWEEN %s AND %s
                """, (user['id'], start_date_obj, end_date_obj))
                fine_row = cur.fetchone()
                total_fines = fine_row['total_fines'] or 0.0

                # Total amount including establishment fee and fines
                total_amount = round(daily_amount * active_days - reduction_amount + establishment_fee + total_fines, 2)

                # Insert bill into DB
                cur.execute("""
                    INSERT INTO bills
                    (user_id, bill_date, daily_amount, active_days, mess_cut_days, reduction_amount, establishment_fee, total_fines, total_amount)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    user['id'], date.today(), daily_amount, active_days,
                    mess_cut_days, reduction_amount, establishment_fee, total_fines, total_amount
                ))

                # Prepare for frontend display
                bills_generated.append({
                    'user': user['name'],
                    'mess_cut_days': mess_cut_days,
                    'closed_dates': sorted([d.strftime("%d-%m-%Y") for d in closed_dates if start_date_obj <= d <= end_date_obj]),
                    'establishment_fee': establishment_fee,
                    'total_fines': total_fines,
                    'total_amount': total_amount,
                    'bill_month': bill_month
                })

            conn.commit()
            flash(f"✅ Bills generated successfully for {len(bills_generated)} users!", "success")

        except Exception as e:
            if conn:
                conn.rollback()
            flash(f"Error generating bills: {str(e)}", "danger")

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    return render_template('admin_generate_bills.html', bills_generated=bills_generated)


from datetime import datetime, time

MESS_WINDOWS = {
    'breakfast': (time(7,30), time(9,30)),
    'lunch': (time(12,0), time(14,0)),
    'dinner': (time(19,0), time(21,0)),
}




from flask import jsonify, request, render_template
from flask_login import login_required, current_user
from datetime import date

@app.route('/admin/non_scanned/<meal_type>')
@login_required
def non_scanned_users(meal_type):
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for('admin_dashboard'))

    if meal_type not in ['breakfast','lunch','dinner']:
        flash("Invalid meal type", "danger")
        return redirect(url_for('admin_dashboard'))

    today = date.today()
    conn = mysql_pool.get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        # Users who didn't scan for this meal today
        cur.execute("""
            SELECT id, name FROM users
            WHERE id NOT IN (
                SELECT user_id FROM meal_attendance
                WHERE meal_type=%s AND attendance_date=%s
            )
        """, (meal_type, today))
        users = cur.fetchall()

        # Users who already got fine
        cur.execute("""
            SELECT user_id FROM fines
            WHERE fine_date=%s AND meal_type=%s
        """, (today, meal_type))
        fined = {row['user_id'] for row in cur.fetchall()}

        return render_template('admin_add_fine.html', users=users, fined=fined, meal_type=meal_type, today=today)
    finally:
        cur.close()
        conn.close()


        
def get_current_meal():
    now = datetime.now()
    hours = now.hour + now.minute / 60
    if 7.5 <= hours <= 9:
        return 'breakfast'
    elif 12 <= hours <= 14:
        return 'lunch'
    else:
        return 'dinner'



    
from flask import render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import date

@app.route('/admin/add_fine', methods=['GET', 'POST'])
@login_required
def add_fine():
    if not getattr(current_user, 'is_admin', False):
        flash("Unauthorized", "danger")
        return redirect(url_for('admin_dashboard'))

    conn = mysql_pool.get_connection()
    cur = conn.cursor(dictionary=True)

    today = date.today()
    non_scanned_users = []

    try:
        # Fetch users who have not scanned today for any meal
        cur.execute("""
            SELECT u.id, u.name
            FROM users u
            WHERE u.is_active = 1
            AND u.id NOT IN (
                SELECT user_id FROM meal_attendance WHERE attendance_date = %s
            )
        """, (today,))
        non_scanned_users = cur.fetchall()

        if request.method == 'POST':
            fines = request.form.getlist('fine')      # list of fine amounts
            user_ids = request.form.getlist('user_id') # list of user ids

            for uid, fine_amount in zip(user_ids, fines):
                fine_amount = float(fine_amount) if fine_amount else 0
                if fine_amount > 0:
                    # Insert into fines table
                    cur.execute("""
                        INSERT INTO fines (user_id, fine_date, amount)
                        VALUES (%s, %s, %s)
                        ON DUPLICATE KEY UPDATE amount=%s
                    """, (uid, today, fine_amount, fine_amount))
            conn.commit()
            flash(f"✅ Fines added for {len(user_ids)} students!", "success")
            return redirect(url_for('add_fine'))

    except Exception as e:
        conn.rollback()
        flash(f"Error: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()

    return render_template('admin_add_fine.html', non_scanned_users=non_scanned_users, today=today)



@app.route('/user/bills')
@login_required
def user_bills():
    conn = mysql_pool.get_connection()
    cur = conn.cursor(dictionary=True)

    bills = []
    try:
        cur.execute("""
            SELECT bill_date, daily_amount, active_days, mess_cut_days,
                   reduction_amount, establishment_fee, total_fines, total_amount
            FROM bills
            WHERE user_id=%s
            ORDER BY bill_date DESC
        """, (current_user.id,))
        bills = cur.fetchall()

        # Convert bill_date to date object if it's a string
        for bill in bills:
            if isinstance(bill['bill_date'], str):
                bill['bill_date'] = datetime.strptime(bill['bill_date'], "%Y-%m-%d").date()

    except Exception as e:
        flash(f"Error fetching bills: {str(e)}", "danger")

    finally:
        cur.close()
        conn.close()

    return render_template('user_bills.html', bills=bills)




# ---------------- ADMIN: Get all users' mess count ----------------
@app.route('/admin/users_mess_count')
@login_required
def users_mess_count():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'users': [], 'error': 'Unauthorized'}), 403

    try:
        conn = mysql_pool.get_connection()        # ✅ Get connection from pool
        cur = conn.cursor(MySQLdb.cursors.DictCursor)

        cur.execute("SELECT name, email, user_type, mess_count FROM users")
        users = cur.fetchall()
        cur.close()
        conn.close()                              # ✅ Return connection to pool

        return jsonify({
            'users': [
                {
                    'name': u['name'],
                    'email': u['email'],
                    'user_type': u['user_type'],
                    'mess_count': u['mess_count']
                } for u in users
            ]
        })

    except MySQLdb.Error as e:
        if cur:
            cur.close()
        if conn:
            conn.close()
        return jsonify({'users': [], 'error': str(e)})


# ---------------- ADMIN: Validate QR and increment mess_count ----------------
@app.route('/admin/validate_qr', methods=['POST'])
@login_required
def admin_validate_qr():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.get_json()
    qr_data = data.get("qr_data", "")

    try:
        user_id = int(qr_data.split("user_id:")[1].split(",")[0])
    except:
        return jsonify({"success": False, "message": "Invalid QR Code"}), 400

    try:
        conn = mysql_pool.get_connection()      # ✅ Get connection from pool
        cur = conn.cursor()
        cur.execute("UPDATE users SET mess_count = mess_count + 1 WHERE id = %s", (user_id,))
        conn.commit()
        cur.close()
        conn.close()                            # ✅ Return connection to pool

        return jsonify({"success": True, "message": f"Attendance recorded for user ID {user_id}"})

    except MySQLdb.Error as e:
        if cur:
            cur.close()
        if conn:
            conn.close()
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500






# -------- ADMIN: LATE MESS LIST --------
# -------- ADMIN: LATE MESS LIST --------
# -------- ADMIN: LATE MESS LIST --------
# ---------------- ADMIN: List late mess requests ----------------
@app.route('/admin/late_mess_list')
@login_required
def late_mess_list():
    if not getattr(current_user, 'is_admin', False):
        flash("Unauthorized access!", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        conn = mysql_pool.get_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("""
            SELECT lm.id, u.name, u.email, u.food_type, lm.date_requested, lm.reason, lm.status
            FROM late_mess lm
            JOIN users u ON u.id = lm.user_id
            ORDER BY lm.date_requested DESC
        """)
        late_mess_requests = cur.fetchall()

        cur.close()
        conn.close()

        return render_template('admin_late_mess.html', late_mess_requests=late_mess_requests)

    except Exception as e:
        if cur:
            cur.close()
        if conn:
            conn.close()
        flash(f"Database error: {e}", "danger")
        return redirect(url_for('admin_dashboard'))






# ---------------- ADMIN: Reset all late mess entries ----------------
@app.route('/admin/reset_late_mess', methods=['POST'])
@login_required
def reset_late_mess():
    if not getattr(current_user, 'is_admin', False):
        return "Unauthorized", 403

    try:
        conn = mysql_pool.get_connection()                  # ✅ Get connection from pool
        cur = conn.cursor()

        cur.execute("DELETE FROM late_mess")
        conn.commit()

        cur.close()
        conn.close()                                       # ✅ Return connection to pool

        flash("✅ All late mess requests have been removed.", "success")
        return redirect(url_for('late_mess_list'))

    except MySQLdb.Error as e:
        if cur:
            cur.close()
        if conn:
            conn.close()
        return f"❌ Error resetting late mess: {str(e)}", 500

from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required, current_user
from datetime import datetime
from mysql.connector import Error

@app.route('/user/mess_skip', methods=['GET', 'POST'])
@login_required
def mess_skip():
    if request.method == 'POST':
        skip_date = request.form.get('skip_date')
        meals = [meal for meal in ['breakfast', 'lunch', 'dinner'] if meal in request.form]

        conn = mysql_pool.get_connection()
        cur = conn.cursor()

        try:
            for meal in meals:
                cur.execute("""
                    INSERT INTO mess_skips (user_id, skip_date, meal_type)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE user_id=user_id
                """, (current_user.id, skip_date, meal))
            conn.commit()
            flash("✅ Mess skip updated successfully!", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error: {str(e)}", "danger")
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('mess_skip'))

    return render_template('user_mess_skip.html')




@app.route('/admin/mess_skips')
@login_required
def admin_mess_skips():
    if not getattr(current_user, 'is_admin', False):
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))

    tomorrow = date.today() + timedelta(days=1)
    skips = {'breakfast': [], 'lunch': [], 'dinner': []}
    skip_counts = {'breakfast': 0, 'lunch': 0, 'dinner': 0}

    conn = mysql_pool.get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        # 🔹 Explicitly print what we're querying
        print(f"Fetching mess skips for date: {tomorrow}")

        cur.execute("""
            SELECT s.meal_type, u.name
            FROM mess_skips s
            JOIN users u ON s.user_id = u.id
            WHERE s.skip_date = %s
        """, (tomorrow,))
        rows = cur.fetchall()

        if not rows:
            print("No skips found for tomorrow!")

        for row in rows:
            meal = row['meal_type']
            name = row['name']
            if meal in skips:
                skips[meal].append(name)
                skip_counts[meal] += 1
            else:
                print(f"Unexpected meal_type in DB: {meal}")

    except Exception as e:
        flash(f"Error fetching mess skips: {e}", "danger")
        print(f"DB Error: {e}")
    finally:
        cur.close()
        conn.close()

    print(f"Skip counts: {skip_counts}")
    print(f"Skips data: {skips}")

    return render_template("admin_mess_skips.html",
                           skips=skips,
                           skip_counts=skip_counts,
                           tomorrow=tomorrow)

from flask import jsonify, request, render_template
import MySQLdb.cursors

# ---------------- ADMIN: APPROVE LATE MESS ----------------
@app.route('/admin/approve_late/<int:lm_id>', methods=['POST'])
@login_required
def approve_late(lm_id):
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        conn = mysql_pool.get_connection()
        cur = conn.cursor()

        # Update the late_mess status to 'approved'
        cur.execute(
            "UPDATE late_mess SET status=%s WHERE id=%s",
            ("approved", lm_id)
        )
        conn.commit()

        cur.close()
        conn.close()

        return jsonify({'success': True})  # Return JSON for JS

    except Exception as e:
        if cur:
            cur.close()
        if conn:
            conn.close()
        return jsonify({'error': str(e)}), 500



# ---------------- ADMIN: BULK APPROVE NEW USERS ----------------
@app.route('/admin/approve_bulk', methods=['POST'])
@login_required
def approve_bulk():
    if not getattr(current_user, 'is_admin', False):
        return "Unauthorized", 403

    emails = request.json.get("emails", [])
    if not emails:
        return "No emails provided", 400

    try:
        conn = mysql_pool.get_connection()
        cur = conn.cursor(MySQLdb.cursors.DictCursor)

        for email in emails:
            cur.execute("SELECT * FROM new_users WHERE email=%s", (email,))
            user = cur.fetchone()
            if user:
                cur.execute("""
                    INSERT INTO users (name,email,phone,course,password,user_type,approved)
                    VALUES (%s,%s,%s,%s,%s,%s,1)
                """, (user['name'], user['email'], user['phone'], user['course'], user['password'], user['user_type']))
                cur.execute("DELETE FROM new_users WHERE email=%s", (email,))

        conn.commit()
        cur.close()
        conn.close()
        return f"Approved {len(emails)} users"
    except Exception as e:
        if cur:
            cur.close()
        if conn:
            conn.close()
        return f"Error: {str(e)}", 500


# ---------------- MESS MENU ----------------
@app.route("/mess_menu")
@login_required
def mess_menu():
    days = ["sunday","monday","tuesday","wednesday","thursday","friday","saturday"]

    try:
        conn = mysql_pool.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT day, meal_type, item FROM mess_menu")
        rows = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        if cur:
            cur.close()
        if conn:
            conn.close()
        flash(f"Error fetching menu: {str(e)}", "danger")
        rows = []

    menu = {day: {"breakfast": "", "lunch": "", "dinner": ""} for day in days}
    for row in rows:
        day, meal_type, item = row
        menu[day][meal_type] = item

    return render_template("mess_menu.html", menu=menu, days=days)


# ---------------- ADMIN: UPDATE MENU ----------------
@app.route("/update_menu", methods=["POST"])
@login_required
def update_menu():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()

    try:
        conn = mysql_pool.get_connection()
        cur = conn.cursor()
        for day, meals in data.items():
            for meal_type, item in meals.items():
                cur.execute("""
                    INSERT INTO mess_menu (day, meal_type, item)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE item = VALUES(item)
                """, (day, meal_type, item))

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Menu updated successfully ✅"})
    except Exception as e:
        if cur:
            cur.close()
        if conn:
            conn.close()
        return jsonify({"message": f"Database error: {str(e)}"}), 500



from flask import request, render_template, redirect, url_for, flash
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# Serializer for generating and validating tokens
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
mail = Mail(app)
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            flash("Please enter your email.", "danger")
            return redirect(url_for('forgot'))

        # Check if the email exists in the users table
        conn = None
        cur = None
        try:
            conn = mysql_pool.get_connection()
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cur.fetchone()

            if not user:
                flash("Email not found.", "danger")
                return redirect(url_for('forgot'))

            # Generate token valid for 30 minutes
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            # Prepare email
            msg = Message(
                subject="Password Reset Request",
                recipients=[email],
                body=f"Hello {user['name']},\n\nTo reset your password, click the link below:\n{reset_url}\n\nThis link is valid for 30 minutes.",
                sender=app.config['MAIL_DEFAULT_SENDER']
            )

            mail.send(msg)
            flash("Password reset link has been sent to your email.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Error sending email: {str(e)}", "danger")
            return redirect(url_for('forgot'))

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()  # Return connection to pool

    return render_template('forgot.html')






from werkzeug.security import generate_password_hash

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # get email from token
    except:
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)

        hashed_pw = generate_password_hash(password)

        conn = mysql_pool.get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_pw, email))
        conn.commit()
        cur.close()
        conn.close()

        flash("Your password has been reset. You can now login.", "success")
        return redirect(url_for('login'))

    return render_template('reset.html')




# ----------------- START APP -----------------
# ----------------- START APP -----------------
if __name__ == '__main__':
    app.run(debug=True)


