from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mysqldb import MySQL
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb.cursors
import qrcode
import io
import base64
from datetime import datetime, time
from flask import Flask
from config import Config  
# ---------------- Flask App ----------------
app = Flask(__name__)
app.config.from_object(Config)

mysql = MySQL(app)

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

        
@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    data = cur.fetchone()
    cur.close()
    if data:
        return User(data['id'], data['name'], data['email'], data['user_type'])  # ✅ fixed column
    return None

# ---------------- CREATE ADMIN ----------------
# ---------------- CREATE ADMIN ----------------
# ---------------- CREATE ADMIN ----------------
from flask import Flask
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash
import MySQLdb


# -----------------------------
# Function to create default admin
# -----------------------------
# ---------------- CREATE ADMIN ----------------
def create_admin():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if admin already exists
    cur.execute("SELECT * FROM users WHERE email = %s", ("siberiamess4@gmail.com",))
    admin = cur.fetchone()

    hashed_password = generate_password_hash("siberia@123")

    if not admin:
        # Insert new admin
        cur.execute("""
            INSERT INTO users (name, email, phone, course, password, user_type, approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ("Admin", "siberiamess4@gmail.com", "0000000000", "N/A", hashed_password, "admin", 1))
        mysql.connection.commit()
        print("✅ Default admin created: siberiamess4@gmail.com, password=siberia@123")
    else:
        # Make sure admin is approved and user_type is admin
        cur.execute("""
            UPDATE users
            SET user_type=%s, approved=%s, password=%s
            WHERE email=%s
        """, ("admin", 1, hashed_password, "siberiamess4@gmail.com"))
        mysql.connection.commit()
        print("ℹ️ Admin already exists. Reset password and ensured approved=1.")

    cur.close()



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

        # Basic required fields check
        if not name or not email or not password or not user_type:
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        # Phone number validation: must be 10 digits
        if not phone.isdigit() or len(phone) != 10:
            flash("Phone number must be exactly 10 digits.", "danger")
            return redirect(url_for('register'))

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert into new_users table
        try:
            cur.execute("""
                INSERT INTO new_users (name, email, phone, course, password, user_type)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, email, phone, course, hashed_password, user_type))
            mysql.connection.commit()
            flash("Registration successful! Await admin approval.", "success")
        except MySQLdb.Error as e:
            flash(f"Database error: {e}", "danger")
        finally:
            cur.close()

        return redirect(url_for('login'))

    return render_template('register.html')




# REPLACE your current /new_users route with this

@app.route('/new_users')
@login_required
def new_users_list():
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM new_users")
    users = cur.fetchall()
    cur.close()

    return render_template("new_users.html", users=users)




# -------- LOGIN --------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

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
    cur = mysql.connection.cursor()
    hashed_password = generate_password_hash("admin123")

    # Delete duplicates
    cur.execute("DELETE FROM users WHERE email=%s", ("admin@example.com",))

    # Insert fresh admin
    cur.execute("""
        INSERT INTO users (name, email, phone, course, password, user_type, approved)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, ("Admin", "siberiamess4@gmail.com", "0000000000", "N/A",
          hashed_password, "admin", 1))
    mysql.connection.commit()
    cur.close()

    return "✅ Admin reset: siberiamess4@gmail.com, password=siberia@123"




#Approval

from flask import send_file
import qrcode
import io
import os

import qrcode, os
from flask_login import login_required, current_user

@app.route('/approve_user/<int:user_id>')
@login_required
def approve_user(user_id):
    if not current_user.is_admin:   # ensure only admin can approve
        flash("❌ Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

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
            INSERT INTO users (name, email, phone, course, password, user_type, approved, qr_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user['name'], user['email'], user['phone'], user['course'],
            user['password'], user['user_type'], 1, ""
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
        mysql.connection.commit()

        flash("✅ User approved successfully and QR code generated.", "success")

    except Exception as e:
        mysql.connection.rollback()
        flash(f"❌ Error approving user: {str(e)}", "danger")
        print("Approve user error:", e)  # debug log

    finally:
        cur.close()

    return redirect(url_for('new_users_list'))




@app.route('/reject_user/<int:user_id>')
def reject_user(user_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("DELETE FROM new_users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("User rejected and removed.", "danger")
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
    # Generate QR code
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(str(current_user.id))
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_b64 = base64.b64encode(buffer.getvalue()).decode('ascii')

    # Fetch late mess requests
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM late_mess WHERE user_id = %s ORDER BY date_requested DESC", (current_user.id,))

    late_requests = cur.fetchall()
    cur.close()

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
@app.route('/admin/users')
@login_required
def users_list():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    cursor.close()
    return render_template('admin_users.html', users=users)



# -------- ADMIN: DELETE USER --------
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("User deleted successfully", "success")
    # FIX: use the correct endpoint name
    return redirect(url_for('users_list'))







@app.route('/my_mess_cuts')
@login_required
def my_mess_cuts():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM mess_cut WHERE user_id=%s ORDER BY start_date DESC", (current_user.id,))
    cuts = cur.fetchall()
    cur.close()

    # Convert start_date/end_date to date objects and calculate number of days
    for cut in cuts:
        if isinstance(cut['start_date'], str):
            cut['start_date'] = datetime.strptime(cut['start_date'], "%Y-%m-%d").date()
        if isinstance(cut['end_date'], str):
            cut['end_date'] = datetime.strptime(cut['end_date'], "%Y-%m-%d").date()
        cut['num_days'] = (cut['end_date'] - cut['start_date']).days + 1

    return render_template('my_mess_cuts.html', cuts=cuts)






from flask import request, jsonify

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

    # Check user exists
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if user:
        # Optional: update attendance or mess count
        return jsonify({"success": True, "message": f"{user['name']} is valid."})
    else:
        return jsonify({"success": False, "message": "User not found."})




from datetime import datetime, timedelta

@app.template_filter('add_days')
def add_days_filter(value, days):
    """Add `days` to a date string in YYYY-MM-DD format."""
    dt = datetime.strptime(value, "%Y-%m-%d").date()
    return (dt + timedelta(days=days)).isoformat()


# -------- USER: MESS CUT --------
from datetime import datetime, date, timedelta
from flask import flash, redirect, url_for, render_template, request
from flask_login import login_required, current_user
import MySQLdb

@app.route('/apply_mess_cut', methods=['GET', 'POST'])
@login_required
def apply_mess_cut():
    today = date.today()
    tomorrow = today + timedelta(days=1)
    current_time = datetime.now().time()
    cutoff_time = datetime.strptime("22:00", "%H:%M").time()  # 10 PM

    # Minimum end date for 3-day range
    min_end_date = today + timedelta(days=3)  # start date can be after today

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

        # Check overlapping
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
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
            cur.close()
            return redirect(url_for('apply_mess_cut'))

        # Fetch user's course
        cur.execute("SELECT course FROM users WHERE id=%s", (current_user.id,))
        user = cur.fetchone()
        if not user or not user.get('course'):
            flash("Course not found. Please update your profile.", "danger")
            cur.close()
            return redirect(url_for('apply_mess_cut'))

        course = user['course']

        # Insert mess cut
        try:
            cur.execute("""
                INSERT INTO mess_cut (user_id, start_date, end_date, course, date_applied)
                VALUES (%s, %s, %s, %s, NOW())
            """, (current_user.id, start_date, end_date, course))
            mysql.connection.commit()
            cur.close()
            flash("Mess cut applied successfully!", "success")
            return redirect(url_for('my_mess_cuts'))
        except MySQLdb.Error as e:
            flash(f"Database error: {e}", "danger")
            cur.close()
            return redirect(url_for('apply_mess_cut'))

    # GET request: render form
    return render_template(
        'apply_mess_cut.html',
        min_start_date=(today + timedelta(days=1)).isoformat(),  # can't select today
        min_end_date=min_end_date.isoformat()
    )


from datetime import datetime

# ---------------- ADMIN: MESS CUT LIST ----------------
from datetime import datetime, timedelta

@app.route('/admin/mess_cuts', methods=['GET'])
@login_required
def mess_cut_list():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for('user_dashboard'))

    # Month filter for listing
    month_filter = request.args.get('month', datetime.now().strftime("%Y-%m"))
    filter_year, filter_month = map(int, month_filter.split("-"))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
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
    cur.close()

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

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        # Check if current time is within allowed window
        if not (start_time <= now_time <= end_time):
            flash("Late mess can only be requested between 4:00 PM and 8:30 PM IST", "warning")
            return redirect(url_for('request_late_mess'))

        # Check if the user already requested today
        cur.execute(
            "SELECT * FROM late_mess WHERE user_id=%s AND date_requested=%s",
            (current_user.id, today)
        )
        existing = cur.fetchone()
        if existing:
            flash("You have already requested late mess today.", "info")
        else:
            cur.execute("""
                INSERT INTO late_mess(user_id, date_requested, status)
                VALUES (%s, %s, %s)
            """, (current_user.id, today, "pending"))
            mysql.connection.commit()
            flash("Late mess requested successfully!", "success")

        cur.close()
        return redirect(url_for('request_late_mess'))

    # GET request: fetch previous requests
    cur.execute(
        "SELECT * FROM late_mess WHERE user_id=%s ORDER BY date_requested DESC",
        (current_user.id,)
    )
    late_requests = cur.fetchall()
    cur.close()

    can_request = start_time <= now_time <= end_time

    return render_template(
        'request_late_mess.html',
        late_requests=late_requests,
        can_request=can_request,
        now_time=now_time.strftime("%H:%M"),
        start_time=start_time.strftime("%H:%M"),
        end_time=end_time.strftime("%H:%M")
    )



# -------- USER: GENERATE QR --------
@app.route('/my_qr')
@login_required
def my_qr():
    # Fetch current mess count from DB
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT mess_count FROM users WHERE id=%s", (current_user.id,))
    data = cursor.fetchone()
    mess_count = data['mess_count'] if data else 0
    cursor.close()

    qr_data = f"user_id:{current_user.id},email:{current_user.email},mess_count:{mess_count}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    return send_file(img_bytes, mimetype='image/png')

# -------- ADMIN: SCAN QR AND INCREMENT MESS COUNT --------
from flask import Flask, render_template, request, jsonify
from flask_login import login_required, current_user
import MySQLdb.cursors
from datetime import date, datetime

@app.route('/admin/qr_scan')
@login_required
def admin_qr_scan():
    if not getattr(current_user, 'is_admin', False):
        return "Unauthorized", 403
    return render_template('admin_qr_scan.html', current_date=date.today().strftime("%Y-%m-%d"))




from flask import Flask, render_template, request, jsonify
from flask_login import login_required, current_user
from datetime import date
import MySQLdb.cursors

# 🔹 Temporary in-memory storage for live counts
live_counts = {
    "breakfast": 0,
    "lunch": 0,
    "dinner": 0
}




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

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # 🔹 Check if user has an active mess cut today
        cur.execute("""
            SELECT * FROM mess_cut
            WHERE user_id=%s AND start_date <= %s AND end_date >= %s
        """, (user_id, today, today))
        if cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'message': 'User has a mess cut today. Scan not allowed.'}), 403

        # Check duplicate scan
        cur.execute("""
            SELECT id FROM meal_attendance
            WHERE user_id=%s AND meal_type=%s AND attendance_date=%s
        """, (user_id, meal_type, today))
        if cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'message': f'Already scanned for {meal_type} today'}), 400

        # Insert attendance
        cur.execute("""
            INSERT INTO meal_attendance (user_id, meal_type, attendance_date)
            VALUES (%s, %s, %s)
        """, (user_id, meal_type, today))

        cur.execute("""UPDATE users SET mess_count = mess_count + 1 WHERE id = %s""", (user_id,))
        mysql.connection.commit()

        # Increment temporary live counter
        live_counts[meal_type] += 1  

        # Get updated count from DB
        cur.execute("""
            SELECT COUNT(*) AS count FROM meal_attendance
            WHERE meal_type=%s AND attendance_date=%s
        """, (meal_type, today))
        result = cur.fetchone()

        cur.execute("SELECT name, course, mess_count FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        cur.close()

        return jsonify({
            'success': True,
            'name': user['name'],
            'course': user['course'],
            'mess_count': user['mess_count'],
            'count': result['count'],
            'live_count': live_counts[meal_type]  # 🔹 return live count
        })

    except MySQLdb.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500


# -------- ADMIN: VIEW CONFIRMED QR COUNTS --------
@app.route('/admin/qr_scan_counts')
@login_required
def qr_scan_counts():
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT DATE(scan_time) as date, meal_type, COUNT(*) as count
        FROM daily_meal_attendance
        GROUP BY DATE(scan_time), meal_type
        ORDER BY date ASC
    """)
    rows = cursor.fetchall()
    cursor.close()

    counts_by_date = {}
    for row in rows:
        date = str(row['date'])
        meal_type = row['meal_type']
        count = row['count']
        if date not in counts_by_date:
            counts_by_date[date] = {}
        counts_by_date[date][meal_type] = count

    print("DEBUG counts_by_date =", counts_by_date)  # 👈 check logs on Render

    return render_template(
        "admin_qr_count.html",
        counts_by_date=counts_by_date
    )





# Temporary live counters (resettable anytime)
live_counts = {"breakfast": 0, "lunch": 0, "dinner": 0}

# ✅ Get live count
@app.route('/admin/live_count/<meal_type>')
@login_required
def get_live_count(meal_type):
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    return jsonify({'success': True, 'count': live_counts.get(meal_type, 0)})

# ✅ Reset live count manually (no save)
@app.route('/admin/reset_count', methods=['POST'])
@login_required
def reset_count():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    meal = request.json.get('meal_type')
    today = date.today()

    try:
        cur = mysql.connection.cursor()

        # ✅ Clear today's attendance for that meal (so users can re-scan)
        cur.execute("""
            DELETE FROM meal_attendance
            WHERE meal_type=%s AND attendance_date=%s
        """, (meal, today))
        mysql.connection.commit()
        cur.close()

        # ✅ Reset live count only (daily_meal_counts stays untouched)
        live_counts[meal] = 0  

        return jsonify({'success': True, 'message': f'{meal.capitalize()} reset done'})
    except MySQLdb.Error as e:
        return jsonify({'success': False, 'message': str(e)})



@app.route('/admin/live_count/<meal_type>')
@login_required
def live_count(meal_type):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    today = date.today()
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT COUNT(*) AS total FROM meal_attendance
        WHERE attendance_date=%s AND meal_type=%s
    """, (today, meal_type))
    result = cur.fetchone()
    cur.close()

    return jsonify({'success': True, 'meal_type': meal_type, 'count': result['total']})



# Route to show counts and add count form
@app.route('/admin/qr_scan_counts')
@login_required
def admin_qr_count():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT meal_date, meal_type, total_count FROM daily_meal_attendance ORDER BY meal_date ASC")
    data = cursor.fetchall()
    cursor.close()

    # Transform data for template
    counts_by_date = {}
    for row in data:
        date = row[0].strftime("%Y-%m-%d")
        meal_type = row[1]
        count = row[2]

        if date not in counts_by_date:
            counts_by_date[date] = {}
        counts_by_date[date][meal_type] = count

    return render_template("admin_qr_count.html", counts_by_date=counts_by_date)

@app.route('/admin/add_count', methods=['POST'])
@login_required
def add_count():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json() or request.form
    meal_type = data.get('meal_type')
    meal_date = data.get('meal_date') or date.today().isoformat()

    if meal_type not in ['breakfast', 'lunch', 'dinner']:
        return jsonify({'success': False, 'message': 'Invalid meal type'}), 400

    count = live_counts.get(meal_type, 0)
    if count == 0:
        return jsonify({'success': False, 'message': 'No live count to save'}), 400

    try:
        cur = mysql.connection.cursor()
        # Insert or update total count
        cur.execute("""
            INSERT INTO daily_meal_attendance (meal_date, meal_type, total_count)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE total_count = total_count + VALUES(total_count)
        """, (meal_date, meal_type, count))
        mysql.connection.commit()
        cur.close()

        # Reset live count
        live_counts[meal_type] = 0

        return jsonify({
            'success': True,
            'meal_type': meal_type,
            'total_people_added': count,
            'meal_date': meal_date
        })

    except MySQLdb.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500




@app.route('/admin/add_meal_count', methods=['GET', 'POST'])
@login_required
def add_meal_count():
    if not current_user.is_admin:
        flash("Unauthorized access", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        meal_date = request.form.get('meal_date')
        meal_type = request.form.get('meal_type')

        if not meal_date or meal_type not in ['breakfast', 'lunch', 'dinner']:
            flash("Invalid input", "danger")
            return redirect(url_for('add_meal_count'))

        try:
            cur = mysql.connection.cursor()
            # Insert or update count
            cur.execute("""
                INSERT INTO meal_counts (meal_date, meal_type, count)
                VALUES (%s, %s, 1)
                ON DUPLICATE KEY UPDATE count = count + 1
            """, (meal_date, meal_type))
            mysql.connection.commit()
            cur.close()
            flash(f"{meal_type.capitalize()} count added for {meal_date}", "success")
        except Exception as e:
            flash(f"Database error: {str(e)}", "danger")
            return redirect(url_for('add_meal_count'))

    # Fetch counts to show in table
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT meal_date, meal_type, count FROM meal_counts ORDER BY meal_date DESC")
    rows = cur.fetchall()
    cur.close()

    # Organize by date
    counts_by_date = {}
    for row in rows:
        date = row['meal_date'].strftime("%Y-%m-%d")
        if date not in counts_by_date:
            counts_by_date[date] = {}
        counts_by_date[date][row['meal_type']] = row['count']

    return render_template("admin_meal_count.html", counts_by_date=counts_by_date)

@app.route('/admin/users_meal_counts')
@login_required
def users_meal_counts():
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized: admin only'}), 403

    from datetime import date
    today = date.today()

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        counts = {}

        for meal in ['breakfast', 'lunch', 'dinner']:
            cur.execute("""
                SELECT u.name, u.email, u.course, COUNT(ma.id) AS total_scans
                FROM meal_attendance ma
                JOIN users u ON ma.user_id = u.id
                WHERE ma.meal_type=%s AND ma.attendance_date=%s
                GROUP BY ma.user_id
            """, (meal, today))
            counts[meal] = cur.fetchall()

        cur.close()
        return jsonify({'success': True, 'data': counts})

    except MySQLdb.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500


@app.route('/admin/add_mess_cut', methods=['GET', 'POST'])
@login_required
def add_mess_cut_admin():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, name, course FROM users")  # ✅ ensure course exists in DB
    users = cursor.fetchall()

    if request.method == 'POST':
        user_id = request.form['user_id']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        cursor.execute(
            "INSERT INTO mess_cut (user_id, start_date, end_date) VALUES (%s, %s, %s)",
            (user_id, start_date, end_date)
        )
        mysql.connection.commit()
        flash("Mess cut added successfully!", "success")
        return redirect(url_for('add_mess_cut_admin'))

    return render_template('admin_add_mess_cut.html', users=users)





@app.route('/admin/users_mess_count')
@login_required
def users_mess_count():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT name, email, user_type, mess_count FROM users")
        users = cur.fetchall()
        cur.close()
        return jsonify({'users': [{'name': u[0], 'email': u[1], 'user_type': u[2], 'mess_count': u[3]} for u in users]})
    except MySQLdb.Error as e:
        return jsonify({'users': [], 'error': str(e)})




@app.route('/admin/validate_qr', methods=['POST'])
@login_required
def admin_validate_qr():
    if not current_user.is_admin:
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    data = request.get_json()
    qr_data = data.get("qr_data")
    try:
        user_id = int(qr_data.split("user_id:")[1].split(",")[0])
    except:
        return jsonify({"success": False, "message": "Invalid QR Code"}), 400

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET mess_count = mess_count + 1 WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({"success": True, "message": f"Attendance recorded for user ID {user_id}"})






# -------- ADMIN: LATE MESS LIST --------
# -------- ADMIN: LATE MESS LIST --------
# -------- ADMIN: LATE MESS LIST --------
@app.route('/admin/late_mess_list')
@login_required
def late_mess_list():
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('admin_dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT lm.id, u.name, u.email, lm.date_requested, lm.reason, lm.status
        FROM late_mess lm
        JOIN users u ON u.id = lm.user_id
        ORDER BY lm.date_requested DESC
    """)
    late_mess_requests = cur.fetchall()
    cur.close()

    return render_template('admin_late_mess.html', late_mess_requests=late_mess_requests)



#Late mess rest

from flask import redirect, url_for, flash
from flask_login import login_required, current_user

@app.route('/admin/reset_late_mess', methods=['POST'])
@login_required
def reset_late_mess():
    if not current_user.is_admin:
        return "Unauthorized", 403

    try:
        cur = mysql.connection.cursor()
        # Delete all late mess entries
        cur.execute("DELETE FROM late_mess")
        mysql.connection.commit()
        cur.close()
        
        flash("✅ All late mess requests have been removed.", "success")
        return redirect(url_for('late_mess_list'))  # admin late mess page
    except Exception as e:
        return f"❌ Error resetting late mess: {str(e)}", 500




from flask import jsonify

# -------- ADMIN: APPROVE LATE MESS --------
@app.route('/admin/approve_late/<int:late_mess_id>', methods=['POST'])
@login_required
def approve_late(late_mess_id):
    if not current_user.is_admin:
        return "", 403

    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE late_mess SET status='approved' WHERE id=%s", (late_mess_id,))
        mysql.connection.commit()
        cur.close()
        return "", 204
    except Exception as e:
        return "", 500




@app.route('/admin/approve_bulk', methods=['POST'])
@login_required
def approve_bulk():
    if not current_user.is_admin:
        return "Unauthorized", 403

    emails = request.json.get("emails", [])
    if not emails:
        return "No emails provided", 400

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    for email in emails:
        cur.execute("SELECT * FROM new_users WHERE email=%s", (email,))
        user = cur.fetchone()
        if user:
            # Insert into users
            cur.execute("""
                INSERT INTO users (name,email,phone,course,password,user_type,approved)
                VALUES (%s,%s,%s,%s,%s,%s,1)
            """, (user['name'], user['email'], user['phone'], user['course'], user['password'], user['user_type']))
            cur.execute("DELETE FROM new_users WHERE email=%s", (email,))
    mysql.connection.commit()
    cur.close()
    return f"Approved {len(emails)} users"

# ----------------- START APP -----------------
# ----------------- START APP -----------------
if __name__ == '__main__':
    app.run(debug=True)



