import pymysql
pymysql.install_as_MySQLdb()

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_mysqldb import MySQL
from functools import wraps
import os
import uuid
from collections import defaultdict
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from PIL import Image
import cloudinary
import cloudinary.uploader
from flask_mail import Mail, Message
import random
from datetime import datetime, timedelta

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')

app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3306))
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB upload limit

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

app.config['MYSQL_SSL'] = {'ssl': {}}

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

csrf = CSRFProtect(app)
mysql = MySQL(app)
mail = Mail(app)

def redirect_after_church_action(church_id, redirect_to=''):
    if redirect_to and redirect_to.startswith('dashboard_manage'):
        parts = redirect_to.split(':', 1)
        section = parts[1] if len(parts) > 1 and parts[1] else 'profile'
        return redirect(url_for('dashboard', manage_church=church_id, manage_section=section))

    if redirect_to == 'dashboard':
        return redirect(url_for('dashboard'))

    return redirect(url_for('church_detail', church_id=church_id))

def is_valid_image(file):
    try:
        img = Image.open(file)
        img.verify()
        file.seek(0)
        return True
    except Exception:
        return False

def generate_otp():
    return str(random.randint(100000, 999999))


def send_verification_email(recipient_email, otp):
    msg = Message(
        subject='Verify Your Email - Heritage Churches of Bohol',
        recipients=[recipient_email]
    )
    msg.body = f"""Hello,

Your verification code is: {otp}

This code will expire in 10 minutes.

If you did not request this, please ignore this email.

Heritage Churches of Bohol
DRRM Information System
"""
    mail.send(msg)
# ─── Upload Config ────────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
REPORT_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'reports')
CHURCH_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'churches')
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

os.makedirs(REPORT_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CHURCH_UPLOAD_FOLDER, exist_ok=True)


def allowed_image_file(filename):
    return (
        filename and
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS
    )


def save_report_images(files):
    saved_paths = []
    invalid_files = 0

    for file in files:
        if not file or not file.filename:
            continue

        if not allowed_image_file(file.filename) or not is_valid_image(file):
            invalid_files += 1
            continue

        try:
            original_name = secure_filename(file.filename)
            upload_result = cloudinary.uploader.upload(
                file,
                folder="heritage_church/reports",
                public_id=f"{uuid.uuid4().hex}_{os.path.splitext(original_name)[0]}",
                resource_type="image"
            )
            saved_paths.append({
                "url": upload_result["secure_url"],
                "public_id": upload_result["public_id"]
            })
        except Exception:
            invalid_files += 1

    if invalid_files > 0:
        flash(f"{invalid_files} invalid file(s) were skipped.", "warning")

    return saved_paths


def save_church_images(files):
    saved_paths = []
    invalid_files = 0

    for file in files:
        if not file or not file.filename:
            continue

        if not allowed_image_file(file.filename) or not is_valid_image(file):
            invalid_files += 1
            continue

        try:
            original_name = secure_filename(file.filename)
            upload_result = cloudinary.uploader.upload(
                file,
                folder="heritage_church/churches",
                public_id=f"{uuid.uuid4().hex}_{os.path.splitext(original_name)[0]}",
                resource_type="image"
            )
            saved_paths.append({
                "url": upload_result["secure_url"],
                "public_id": upload_result["public_id"]
            })
        except Exception:
            invalid_files += 1

    if invalid_files > 0:
        flash(f"{invalid_files} invalid file(s) were skipped.", "warning")

    return saved_paths

# ─── Helpers ──────────────────────────────────────────────────────────────────
def can_manage_church(church_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT municipality_id FROM churches WHERE church_id = %s", (church_id,))
    church = cur.fetchone()
    cur.close()

    if not church:
        return False

    if session.get('role_name') == 'Super Admin':
        return True

    return church['municipality_id'] == session.get('municipality_id')


def is_super_admin():
    return session.get('role_name') == 'Super Admin'


# ─── Audit Logger ─────────────────────────────────────────────────────────────
def log_audit(user_id, action_type, affected_table=None, record_id=None, description=None):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO audit_logs (user_id, action_type, affected_table, record_id, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, action_type, affected_table, record_id, description))
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        print("AUDIT LOG ERROR:", e)


# ─── Auth Decorators ──────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access that page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped_view


def super_admin_required(f):
    @wraps(f)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))

        if session.get('role_name') != 'Super Admin':
            flash('Access denied. Only Super Admin can manage users.', 'danger')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return wrapped_view


def admin_required(f):
    @wraps(f)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access that page.', 'warning')
            return redirect(url_for('login'))

        if session.get('role_name') not in ('Super Admin', 'Municipal Admin'):
            flash('You do not have permission to access that page.', 'danger')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return wrapped_view


# ─── Login ────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        if session.get('role_name') in ('Super Admin', 'Municipal Admin'):
            return redirect(url_for('dashboard'))
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT u.*, r.role_name
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE u.username = %s AND u.email = %s
        """, (username, email))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user['password_hash'], password):
            if not user.get('email_verified'):
                error = 'Your email is not yet verified. Please contact the administrator.'
            elif user.get('account_status') == 'inactive':
                error = 'Your account is inactive. Please contact the administrator.'
            else:
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['full_name'] = user['full_name']
                session['role_name'] = user['role_name']
                session['municipality_id'] = user['municipality_id']

                log_audit(
                    user['user_id'],
                    'LOGIN',
                    'users',
                    user['user_id'],
                    f"{user['full_name']} logged into the system."
                )

                flash(f"Welcome back, {user['full_name']}!", 'success')

                if user['role_name'] in ('Super Admin', 'Municipal Admin'):
                    return redirect(url_for('dashboard'))
                return redirect(url_for('index'))
        else:
            error = 'Invalid username, email, or password. Please try again.'

    return render_template('login.html', error=error)

#-------------public log-in------------
@app.route('/public-login', methods=['GET', 'POST'])
def public_login():
    if 'user_id' in session:
        if session.get('role_name') in ('Super Admin', 'Municipal Admin'):
            return redirect(url_for('dashboard'))
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                SELECT u.*, r.role_name
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                WHERE u.email = %s AND r.role_name = %s
            """, (email, 'Public User'))
            user = cur.fetchone()
            cur.close()

            if not user:
                flash('Invalid email or password.', 'danger')
                return render_template('public_login.html')

            if not user.get('email_verified'):
                flash('Please verify your email before logging in.', 'warning')
                session['pending_verification_email'] = email
                return redirect(url_for('verify_email'))

            if user.get('account_status') != 'active':
                flash('Your account is inactive.', 'danger')
                return render_template('public_login.html')

            if not check_password_hash(user['password_hash'], password):
                flash('Invalid email or password.', 'danger')
                return render_template('public_login.html')

            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['role_name'] = user['role_name']
            session['municipality_id'] = user['municipality_id']

            flash('Logged in successfully.', 'success')
            return redirect(url_for('public_reports'))

        except Exception as e:
            print('PUBLIC LOGIN ERROR:', e)
            flash('Unable to log in right now.', 'danger')

    return render_template('public_login.html')

# ─── Logout ───────────────────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    full_name = session.get('full_name', 'Unknown User')

    if user_id:
        log_audit(
            user_id,
            'LOGOUT',
            'users',
            user_id,
            f"{full_name} logged out of the system."
        )

    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

#-----------Sign-up---------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not full_name or not username or not email or not password:
            flash('Please fill in all required fields.', 'danger')
            return render_template('signup.html')

        try:
            cur = mysql.connection.cursor()

            cur.execute("""
                SELECT user_id
                FROM users
                WHERE username = %s OR email = %s
            """, (username, email))
            existing_user = cur.fetchone()

            if existing_user:
                cur.close()
                flash('Username or email already exists.', 'danger')
                return render_template('signup.html')

            cur.execute("""
                SELECT role_id
                FROM roles
                WHERE role_name = %s
            """, ('Public User',))
            public_role = cur.fetchone()

            if not public_role:
                cur.close()
                flash('Public User role not found. Please contact the administrator.', 'danger')
                return render_template('signup.html')

            otp = generate_otp()
            expiry = datetime.now() + timedelta(minutes=10)
            password_hash = generate_password_hash(password)

            cur.execute("""
                INSERT INTO users (
                    full_name,
                    username,
                    email,
                    password_hash,
                    role_id,
                    municipality_id,
                    account_status,
                    email_verified,
                    verification_code,
                    verification_expiry
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                full_name,
                username,
                email,
                password_hash,
                public_role['role_id'],
                None,
                'inactive',
                0,
                otp,
                expiry
            ))
            mysql.connection.commit()
            cur.close()

            send_verification_email(email, otp)
            session['pending_verification_email'] = email

            flash('Account created. Please check your email for the verification code.', 'success')
            return redirect(url_for('verify_email'))

        except Exception as e:
            print('SIGNUP ERROR:', e)
            flash('Unable to create account right now. Please try again.', 'danger')

    return render_template('signup.html')

#-----------public - logout----------
@app.route('/public-logout')
def public_logout():
    if session.get('role_name') == 'Public User':
        session.clear()
        flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

#---------------verify-email-------------
@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    email = session.get('pending_verification_email')

    if not email:
        flash('No pending verification found. Please sign up first.', 'warning')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()

        if not otp_input:
            flash('Please enter the verification code.', 'danger')
            return render_template('verify_email.html', email=email)

        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                SELECT user_id, verification_code, verification_expiry, email_verified
                FROM users
                WHERE email = %s
            """, (email,))
            user = cur.fetchone()

            if not user:
                cur.close()
                flash('Account not found.', 'danger')
                return redirect(url_for('signup'))

            if user['email_verified']:
                cur.close()
                session.pop('pending_verification_email', None)
                flash('Your email is already verified. You are now logged in.', 'info')
                return redirect(url_for('public_reports'))

            expiry = user['verification_expiry']
            if expiry and datetime.now() > expiry:
                cur.close()
                flash('Verification code expired. Please sign up again or request a new code later.', 'danger')
                return render_template('verify_email.html', email=email)

            if user['verification_code'] != otp_input:
                cur.close()
                flash('Invalid verification code.', 'danger')
                return render_template('verify_email.html', email=email)

            cur.execute("""
                UPDATE users
                SET email_verified = 1,
                    account_status = 'active',
                    verification_code = NULL,
                    verification_expiry = NULL,
                    verified_at = NOW()
                WHERE email = %s
            """, (email,))
            mysql.connection.commit()

            cur.execute("""
                SELECT u.*, r.role_name
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                WHERE u.email = %s
            """, (email,))
            verified_user = cur.fetchone()
            cur.close()

            session.pop('pending_verification_email', None)

            session['user_id'] = verified_user['user_id']
            session['username'] = verified_user['username']
            session['full_name'] = verified_user['full_name']
            session['role_name'] = verified_user['role_name']
            session['municipality_id'] = verified_user['municipality_id']

            flash('Email verified successfully. You are now logged in.', 'success')
            return redirect(url_for('public_reports'))

        except Exception as e:
            print('VERIFY EMAIL ERROR:', e)
            flash('Unable to verify email right now.', 'danger')

    return render_template('verify_email.html', email=email)
# ─── Admin Dashboard ──────────────────────────────────────────────────────────
@app.route('/dashboard')
@admin_required
def dashboard():
    cur = mysql.connection.cursor()

    if is_super_admin():
        cur.execute("SELECT COUNT(*) AS total FROM churches")
        total_churches = cur.fetchone()['total']

        cur.execute("SELECT COUNT(*) AS total FROM disaster_reports")
        total_reports = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(DISTINCT cha.church_id) AS total
            FROM church_hazard_assessments cha
            WHERE cha.risk_level = 'High'
        """)
        high_risk = cur.fetchone()['total']

        cur.execute("SELECT COUNT(*) AS total FROM users")
        total_users = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM disaster_reports
            WHERE report_status IN ('Pending Validation', 'Reported - Validated', 'Under Assessment')
        """)
        pending_reports = cur.fetchone()['total']

        cur.execute("""
            SELECT dr.*, c.church_name, m.municipality_name, ht.hazard_name
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            JOIN hazard_types ht ON dr.hazard_type_id = ht.hazard_type_id
            ORDER BY dr.report_date DESC
            LIMIT 8
        """)
        recent_reports = cur.fetchall()

        cur.execute("""
            SELECT
                c.*,
                m.municipality_name,
                cd.historical_background,
                cd.historical_period,
                cd.cultural_significance,
                cd.religious_significance,
                cd.notable_artifacts,
                MAX(CASE
                    WHEN cha.risk_level = 'High' THEN 'High'
                    WHEN cha.risk_level = 'Medium' THEN 'Medium'
                    WHEN cha.risk_level = 'Low' THEN 'Low'
                    ELSE NULL
                END) AS highest_risk
            FROM churches c
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            LEFT JOIN church_descriptions cd ON c.church_id = cd.church_id
            LEFT JOIN church_hazard_assessments cha ON c.church_id = cha.church_id
            GROUP BY
                c.church_id,
                c.church_name,
                c.municipality_id,
                c.barangay,
                c.address,
                c.latitude,
                c.longitude,
                c.date_built,
                c.monitoring_status,
                c.created_by,
                c.created_at,
                m.municipality_name,
                cd.historical_background,
                cd.historical_period,
                cd.cultural_significance,
                cd.religious_significance,
                cd.notable_artifacts
            ORDER BY c.church_name ASC
        """)
        churches = cur.fetchall()

        cur.execute("""
            SELECT m.municipality_name, COUNT(c.church_id) AS church_count
            FROM municipalities m
            LEFT JOIN churches c ON m.municipality_id = c.municipality_id
            GROUP BY m.municipality_id
            ORDER BY church_count DESC
        """)
        municipality_stats = cur.fetchall()

    else:
        municipality_id = session.get('municipality_id')

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM churches
            WHERE municipality_id = %s
        """, (municipality_id,))
        total_churches = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            WHERE c.municipality_id = %s
        """, (municipality_id,))
        total_reports = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(DISTINCT cha.church_id) AS total
            FROM church_hazard_assessments cha
            JOIN churches c ON cha.church_id = c.church_id
            WHERE c.municipality_id = %s
              AND cha.risk_level = 'High'
        """, (municipality_id,))
        high_risk = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM users
            WHERE municipality_id = %s
        """, (municipality_id,))
        total_users = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            WHERE c.municipality_id = %s
              AND dr.report_status IN ('Pending Validation', 'Reported - Validated', 'Under Assessment')
        """, (municipality_id,))
        pending_reports = cur.fetchone()['total']
        cur.execute("""
            SELECT dr.*, c.church_name, m.municipality_name, ht.hazard_name
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            JOIN hazard_types ht ON dr.hazard_type_id = ht.hazard_type_id
            WHERE m.municipality_id = %s
            ORDER BY dr.report_date DESC
            LIMIT 8
        """, (municipality_id,))
        recent_reports = cur.fetchall()

        cur.execute("""
            SELECT
                c.*,
                m.municipality_name,
                cd.historical_background,
                cd.historical_period,
                cd.cultural_significance,
                cd.religious_significance,
                cd.notable_artifacts,
                MAX(CASE
                    WHEN cha.risk_level = 'High' THEN 'High'
                    WHEN cha.risk_level = 'Medium' THEN 'Medium'
                    WHEN cha.risk_level = 'Low' THEN 'Low'
                    ELSE NULL
                END) AS highest_risk
            FROM churches c
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            LEFT JOIN church_descriptions cd ON c.church_id = cd.church_id
            LEFT JOIN church_hazard_assessments cha ON c.church_id = cha.church_id
            WHERE c.municipality_id = %s
            GROUP BY
                c.church_id,
                c.church_name,
                c.municipality_id,
                c.barangay,
                c.address,
                c.latitude,
                c.longitude,
                c.date_built,
                c.monitoring_status,
                c.created_by,
                c.created_at,
                m.municipality_name,
                cd.historical_background,
                cd.historical_period,
                cd.cultural_significance,
                cd.religious_significance,
                cd.notable_artifacts
            ORDER BY c.church_name ASC
        """, (municipality_id,))
        churches = cur.fetchall()

        cur.execute("""
            SELECT m.municipality_name, COUNT(c.church_id) AS church_count
            FROM municipalities m
            LEFT JOIN churches c ON m.municipality_id = c.municipality_id
            WHERE m.municipality_id = %s
            GROUP BY m.municipality_id
            ORDER BY church_count DESC
        """, (municipality_id,))
        municipality_stats = cur.fetchall()

    cur.execute("SELECT * FROM municipalities ORDER BY municipality_name ASC")
    municipalities = cur.fetchall()

    cur.execute("SELECT * FROM hazard_types ORDER BY hazard_name ASC")
    hazard_types = cur.fetchall()

    church_ids = [c['church_id'] for c in churches]
    dashboard_data = {}

    if church_ids:
        placeholders = ','.join(['%s'] * len(church_ids))

        cur.execute(f"""
            SELECT cha.*, ht.hazard_name
            FROM church_hazard_assessments cha
            JOIN hazard_types ht ON cha.hazard_type_id = ht.hazard_type_id
            WHERE cha.church_id IN ({placeholders})
            ORDER BY cha.assessment_date DESC, cha.assessment_id DESC
        """, tuple(church_ids))
        assessments = cur.fetchall()

        cur.execute(f"""
            SELECT *
            FROM heritage_recognitions
            WHERE church_id IN ({placeholders})
            ORDER BY year_recognized DESC, recognition_id DESC
        """, tuple(church_ids))
        recognitions = cur.fetchall()

        cur.execute(f"""
            SELECT ci.*, u.full_name AS uploaded_by_name
            FROM church_images ci
            LEFT JOIN users u ON ci.uploaded_by = u.user_id
            WHERE ci.church_id IN ({placeholders})
            ORDER BY ci.uploaded_at DESC, ci.image_id DESC
        """, tuple(church_ids))
        images = cur.fetchall()

        cur.execute(f"""
            SELECT dr.*, ht.hazard_name
            FROM disaster_reports dr
            JOIN hazard_types ht ON dr.hazard_type_id = ht.hazard_type_id
            WHERE dr.church_id IN ({placeholders})
            ORDER BY dr.report_date DESC, dr.report_id DESC
        """, tuple(church_ids))
        reports = cur.fetchall()

        report_ids = [r['report_id'] for r in reports]
        report_images = []
        if report_ids:
            report_placeholders = ','.join(['%s'] * len(report_ids))
            cur.execute(f"""
                SELECT report_image_id, report_id, image_path
                FROM report_images
                WHERE report_id IN ({report_placeholders})
                ORDER BY report_image_id ASC
            """, tuple(report_ids))
            report_images = cur.fetchall()

        assessments_map = defaultdict(list)
        for a in assessments:
            assessments_map[a['church_id']].append(a)

        recognitions_map = defaultdict(list)
        for r in recognitions:
            recognitions_map[r['church_id']].append(r)

        images_map = defaultdict(list)
        for img in images:
            images_map[img['church_id']].append(img)

        report_images_map = defaultdict(list)
        for img in report_images:
            report_images_map[img['report_id']].append(img)

        reports_map = defaultdict(list)
        for r in reports:
            r_copy = dict(r)
            r_copy['images'] = report_images_map.get(r['report_id'], [])
            reports_map[r['church_id']].append(r_copy)

        for c in churches:
            dashboard_data[str(c['church_id'])] = {
                'church_id': c['church_id'],
                'church_name': c['church_name'],
                'municipality_id': c['municipality_id'],
                'municipality_name': c['municipality_name'],
                'barangay': c['barangay'],
                'address': c['address'],
                'latitude': c['latitude'],
                'longitude': c['longitude'],
                'date_built': c['date_built'],
                'monitoring_status': c['monitoring_status'],
                'historical_background': c.get('historical_background'),
                'historical_period': c.get('historical_period'),
                'cultural_significance': c.get('cultural_significance'),
                'religious_significance': c.get('religious_significance'),
                'notable_artifacts': c.get('notable_artifacts'),
                'assessments': assessments_map.get(c['church_id'], []),
                'recognitions': recognitions_map.get(c['church_id'], []),
                'images': images_map.get(c['church_id'], []),
                'reports': reports_map.get(c['church_id'], []),
            }

    cur.close()

    return render_template(
        'dashboard.html',
        total_churches=total_churches,
        total_reports=total_reports,
        high_risk=high_risk,
        total_users=total_users,
        pending_reports=pending_reports,
        recent_reports=recent_reports,
        churches=churches,
        municipality_stats=municipality_stats,
        municipalities=municipalities,
        hazard_types=hazard_types,
        dashboard_data=dashboard_data
    )

# ─── Homepage ─────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT
            c.church_id,
            c.church_name,
            m.municipality_name,
            c.barangay,
            c.date_built,
            c.monitoring_status,
            (
                SELECT ci.image_path
                FROM church_images ci
                WHERE ci.church_id = c.church_id
                ORDER BY ci.image_id DESC
                LIMIT 1
            ) AS image_path,
            MAX(CASE
                WHEN cha.risk_level = 'High' THEN 'High'
                WHEN cha.risk_level = 'Medium' THEN 'Medium'
                WHEN cha.risk_level = 'Low' THEN 'Low'
                ELSE NULL
            END) AS highest_risk
        FROM churches c
        JOIN municipalities m ON c.municipality_id = m.municipality_id
        LEFT JOIN church_hazard_assessments cha ON c.church_id = cha.church_id
        GROUP BY
            c.church_id,
            c.church_name,
            m.municipality_name,
            c.barangay,
            c.date_built,
            c.monitoring_status
        ORDER BY c.church_name ASC
    """)
    churches = cur.fetchall()

    cur.execute("SELECT COUNT(*) AS total FROM churches")
    total_churches = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM church_hazard_assessments WHERE risk_level = 'High'")
    high_risk = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM disaster_reports")
    total_reports = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM municipalities")
    total_municipalities = cur.fetchone()['total']

    cur.close()

    return render_template(
        'index.html',
        churches=churches,
        total_churches=total_churches,
        high_risk=high_risk,
        total_reports=total_reports,
        total_municipalities=total_municipalities
    )

# ─── Hazard Map ───────────────────────────────────────────────────────────────
@app.route('/hazard-map')
def hazard_map():
    cur = mysql.connection.cursor()

    role_name = session.get('role_name')
    municipality_id = session.get('municipality_id')

    if role_name == 'Super Admin':
        cur.execute("""
            SELECT
                c.church_id,
                c.church_name,
                c.barangay,
                c.address,
                c.latitude,
                c.longitude,
                c.monitoring_status,
                m.municipality_name,
                MAX(CASE
                    WHEN cha.risk_level = 'High' THEN 'High'
                    WHEN cha.risk_level = 'Medium' THEN 'Medium'
                    WHEN cha.risk_level = 'Low' THEN 'Low'
                    ELSE NULL
                END) AS highest_risk
            FROM churches c
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            LEFT JOIN church_hazard_assessments cha ON c.church_id = cha.church_id
            WHERE c.latitude IS NOT NULL
              AND c.longitude IS NOT NULL
            GROUP BY
                c.church_id, c.church_name, c.barangay, c.address,
                c.latitude, c.longitude, c.monitoring_status, m.municipality_name
            ORDER BY c.church_name ASC
        """)
        churches = cur.fetchall()

        cur.execute("SELECT COUNT(*) AS total FROM churches")
        total_churches = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(DISTINCT church_id) AS mapped_count
            FROM churches
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        """)
        mapped_count = cur.fetchone()['mapped_count']

        cur.execute("""
            SELECT COUNT(DISTINCT church_id) AS high_risk_count
            FROM church_hazard_assessments
            WHERE risk_level = 'High'
        """)
        high_risk_count = cur.fetchone()['high_risk_count']

        scope_label = "Province of Bohol"
        is_admin_view = True

    elif role_name == 'Municipal Admin':
        cur.execute("""
            SELECT
                c.church_id,
                c.church_name,
                c.barangay,
                c.address,
                c.latitude,
                c.longitude,
                c.monitoring_status,
                m.municipality_name,
                MAX(CASE
                    WHEN cha.risk_level = 'High' THEN 'High'
                    WHEN cha.risk_level = 'Medium' THEN 'Medium'
                    WHEN cha.risk_level = 'Low' THEN 'Low'
                    ELSE NULL
                END) AS highest_risk
            FROM churches c
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            LEFT JOIN church_hazard_assessments cha ON c.church_id = cha.church_id
            WHERE c.latitude IS NOT NULL
              AND c.longitude IS NOT NULL
              AND c.municipality_id = %s
            GROUP BY
                c.church_id, c.church_name, c.barangay, c.address,
                c.latitude, c.longitude, c.monitoring_status, m.municipality_name
            ORDER BY c.church_name ASC
        """, (municipality_id,))
        churches = cur.fetchall()

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM churches
            WHERE municipality_id = %s
        """, (municipality_id,))
        total_churches = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(DISTINCT church_id) AS mapped_count
            FROM churches
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
              AND municipality_id = %s
        """, (municipality_id,))
        mapped_count = cur.fetchone()['mapped_count']

        cur.execute("""
            SELECT COUNT(DISTINCT cha.church_id) AS high_risk_count
            FROM church_hazard_assessments cha
            JOIN churches c ON cha.church_id = c.church_id
            WHERE cha.risk_level = 'High'
              AND c.municipality_id = %s
        """, (municipality_id,))
        high_risk_count = cur.fetchone()['high_risk_count']

        cur.execute("""
            SELECT municipality_name
            FROM municipalities
            WHERE municipality_id = %s
        """, (municipality_id,))
        muni = cur.fetchone()

        scope_label = muni['municipality_name'] if muni else 'Assigned Municipality'
        is_admin_view = True

    else:
        cur.execute("""
            SELECT
                c.church_id,
                c.church_name,
                c.barangay,
                c.address,
                c.latitude,
                c.longitude,
                c.monitoring_status,
                m.municipality_name,
                MAX(CASE
                    WHEN cha.risk_level = 'High' THEN 'High'
                    WHEN cha.risk_level = 'Medium' THEN 'Medium'
                    WHEN cha.risk_level = 'Low' THEN 'Low'
                    ELSE NULL
                END) AS highest_risk
            FROM churches c
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            LEFT JOIN church_hazard_assessments cha ON c.church_id = cha.church_id
            WHERE c.latitude IS NOT NULL
              AND c.longitude IS NOT NULL
            GROUP BY
                c.church_id, c.church_name, c.barangay, c.address,
                c.latitude, c.longitude, c.monitoring_status, m.municipality_name
            ORDER BY c.church_name ASC
        """)
        churches = cur.fetchall()

        cur.execute("SELECT COUNT(*) AS total FROM churches")
        total_churches = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(DISTINCT church_id) AS mapped_count
            FROM churches
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        """)
        mapped_count = cur.fetchone()['mapped_count']

        cur.execute("""
            SELECT COUNT(DISTINCT church_id) AS high_risk_count
            FROM church_hazard_assessments
            WHERE risk_level = 'High'
        """)
        high_risk_count = cur.fetchone()['high_risk_count']

        scope_label = "Province of Bohol"
        is_admin_view = False

    cur.close()

    return render_template(
        'hazard_map.html',
        churches=churches,
        total_churches=total_churches,
        mapped_count=mapped_count,
        high_risk_count=high_risk_count,
        scope_label=scope_label,
        is_admin_view=is_admin_view
    )


# ─── Public Reports Page ──────────────────────────────────────────────────────
@app.route('/reports')
def public_reports():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            dr.report_id,
            dr.church_id,
            dr.hazard_type_id,
            dr.incident_date,
            dr.report_date,
            dr.report_description,
            dr.damage_level,
            dr.report_status,
            c.church_name,
            c.barangay,
            m.municipality_name,
            ht.hazard_name
        FROM disaster_reports dr
        JOIN churches c ON dr.church_id = c.church_id
        JOIN municipalities m ON c.municipality_id = m.municipality_id
        JOIN hazard_types ht ON dr.hazard_type_id = ht.hazard_type_id
        ORDER BY dr.report_date DESC, dr.report_id DESC
    """)
    reports = cur.fetchall()

    report_images_map = defaultdict(list)

    if reports:
        report_ids = [r['report_id'] for r in reports]
        placeholders = ','.join(['%s'] * len(report_ids))

        cur.execute(f"""
            SELECT report_image_id, report_id, image_path
            FROM report_images
            WHERE report_id IN ({placeholders})
            ORDER BY report_image_id ASC
        """, tuple(report_ids))
        report_images = cur.fetchall()

        for img in report_images:
            report_images_map[img['report_id']].append(img)

    cur.execute("SELECT * FROM hazard_types ORDER BY hazard_name ASC")
    hazard_types = cur.fetchall()

    cur.execute("SELECT * FROM municipalities ORDER BY municipality_name ASC")
    municipalities = cur.fetchall()

    cur.execute("""
        SELECT c.church_id, c.church_name, m.municipality_name
        FROM churches c
        JOIN municipalities m ON c.municipality_id = m.municipality_id
        ORDER BY c.church_name ASC
    """)
    churches = cur.fetchall()
    pending_public_report = session.get('pending_public_report', {})
    cur.close()

   return render_template(
        'reports_public.html',
        reports=reports,
        hazard_types=hazard_types,
        municipalities=municipalities,
        churches=churches,
        pending_public_report=pending_public_report
)
    )

# ─── Public About Page ────────────────────────────────────────────────────────
@app.route('/about')
def about():
    cur = mysql.connection.cursor()

    cur.execute("SELECT COUNT(*) AS total FROM churches")
    total_churches = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM municipalities")
    total_municipalities = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM disaster_reports")
    total_reports = cur.fetchone()['total']

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM church_hazard_assessments
        WHERE risk_level = 'High'
    """)
    high_risk = cur.fetchone()['total']

    cur.close()

    return render_template(
        'about.html',
        total_churches=total_churches,
        total_municipalities=total_municipalities,
        total_reports=total_reports,
        high_risk=high_risk
    )


# ─── Church Detail ────────────────────────────────────────────────────────────
@app.route('/church/<int:church_id>')
def church_detail(church_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT c.*, m.municipality_name
        FROM churches c
        JOIN municipalities m ON c.municipality_id = m.municipality_id
        WHERE c.church_id = %s
    """, (church_id,))
    church = cur.fetchone()

    if not church:
        cur.close()
        return render_template("404.html"), 404

    cur.execute("SELECT * FROM church_descriptions WHERE church_id = %s", (church_id,))
    description = cur.fetchone()

    cur.execute("""
        SELECT *
        FROM heritage_recognitions
        WHERE church_id = %s
        ORDER BY year_recognized DESC, recognition_id DESC
    """, (church_id,))
    recognitions = cur.fetchall()

    cur.execute("""
        SELECT cha.*, ht.hazard_name
        FROM church_hazard_assessments cha
        JOIN hazard_types ht ON cha.hazard_type_id = ht.hazard_type_id
        WHERE cha.church_id = %s
        ORDER BY cha.assessment_date DESC
    """, (church_id,))
    assessments = cur.fetchall()

    cur.execute("""
        SELECT dr.*, ht.hazard_name
        FROM disaster_reports dr
        JOIN hazard_types ht ON dr.hazard_type_id = ht.hazard_type_id
        WHERE dr.church_id = %s
        ORDER BY dr.report_date DESC
    """, (church_id,))
    reports = cur.fetchall()

    report_images_map = defaultdict(list)

    if reports:
        report_ids = [r['report_id'] for r in reports]
        placeholders = ','.join(['%s'] * len(report_ids))
        cur.execute(f"""
            SELECT report_image_id, report_id, image_path
            FROM report_images
            WHERE report_id IN ({placeholders})
            ORDER BY report_image_id ASC
        """, tuple(report_ids))
        report_images = cur.fetchall()
        for img in report_images:
            report_images_map[img['report_id']].append(img)

    cur.execute("""
        SELECT ci.*, u.full_name AS uploaded_by_name
        FROM church_images ci
        LEFT JOIN users u ON ci.uploaded_by = u.user_id
        WHERE ci.church_id = %s
        ORDER BY ci.uploaded_at DESC, ci.image_id DESC
    """, (church_id,))
    images = cur.fetchall()

    cur.execute("SELECT * FROM hazard_types ORDER BY hazard_name ASC")
    hazard_types = cur.fetchall()

    cur.execute("SELECT * FROM municipalities ORDER BY municipality_name ASC")
    municipalities = cur.fetchall()

    cur.close()

    return render_template(
        'church_detail.html',
        church=church,
        description=description,
        recognitions=recognitions,
        assessments=assessments,
        reports=reports,
        report_images_map=report_images_map,
        images=images,
        hazard_types=hazard_types,
        municipalities=municipalities
    )


# ─── Add Church ───────────────────────────────────────────────────────────────
@app.route('/admin/add-church', methods=['POST'])
@admin_required
def add_church():
    church_name = request.form.get('church_name', '').strip()
    form_municipality_id = request.form.get('municipality_id')
    barangay = request.form.get('barangay', '').strip()
    address = request.form.get('address', '').strip()
    latitude = request.form.get('latitude') or None
    longitude = request.form.get('longitude') or None
    date_built = request.form.get('date_built') or None
    monitoring_status = request.form.get('monitoring_status', 'Active')

    if not church_name or not barangay or not monitoring_status:
        flash('Church name, barangay, and monitoring status are required.', 'danger')
        return redirect(url_for('dashboard'))

    if session.get('role_name') == 'Super Admin':
        municipality_id = form_municipality_id
        if not municipality_id:
            flash('Municipality is required.', 'danger')
            return redirect(url_for('dashboard'))
    else:
        municipality_id = session.get('municipality_id')
        if not municipality_id:
            flash('Your account has no assigned municipality.', 'danger')
            return redirect(url_for('dashboard'))

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO churches
                (church_name, municipality_id, barangay, address,
                 latitude, longitude, date_built, monitoring_status, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            church_name,
            municipality_id,
            barangay,
            address,
            latitude,
            longitude,
            date_built,
            monitoring_status,
            session.get('user_id')
        ))
        mysql.connection.commit()
        new_church_id = cur.lastrowid
        cur.close()

        log_audit(
            session.get('user_id'),
            'INSERT',
            'churches',
            new_church_id,
            f'Added church "{church_name}".'
        )

        flash(f'"{church_name}" has been added successfully!', 'success')

    except Exception as e:
        print("ADD CHURCH ERROR:", e)
        flash(f'Error adding church: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))


# ─── Edit Church ──────────────────────────────────────────────────────────────
@app.route('/admin/edit-church/<int:church_id>', methods=['POST'])
@admin_required
def edit_church(church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to edit this church.', 'danger')
        return redirect(url_for('dashboard'))

    church_name = request.form.get('church_name', '').strip()
    barangay = request.form.get('barangay', '').strip()
    address = request.form.get('address', '').strip()
    latitude = request.form.get('latitude') or None
    longitude = request.form.get('longitude') or None
    date_built = request.form.get('date_built') or None
    monitoring_status = request.form.get('monitoring_status', 'Active')

    came_from_church_detail = request.referrer and f'/church/{church_id}' in request.referrer
    redirect_to = request.form.get('redirect_to', '').strip()

    if session.get('role_name') == 'Super Admin':
        municipality_id = request.form.get('municipality_id')
    else:
        municipality_id = session.get('municipality_id')

    if not church_name or not barangay or not monitoring_status or not municipality_id:
        flash('Church name, municipality, barangay, and monitoring status are required.', 'danger')
        if redirect_to == 'church_detail' or came_from_church_detail:
            return redirect(url_for('church_detail', church_id=church_id))
        return redirect(url_for('dashboard'))

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE churches
            SET church_name = %s,
                municipality_id = %s,
                barangay = %s,
                address = %s,
                latitude = %s,
                longitude = %s,
                date_built = %s,
                monitoring_status = %s
            WHERE church_id = %s
        """, (
            church_name,
            municipality_id,
            barangay,
            address,
            latitude,
            longitude,
            date_built,
            monitoring_status,
            church_id
        ))
        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'UPDATE',
            'churches',
            church_id,
            f'Updated church "{church_name}" (ID {church_id}).'
        )

        flash('Church updated successfully!', 'success')

    except Exception as e:
        print("EDIT CHURCH ERROR:", e)
        flash(f'Error updating church: {str(e)}', 'danger')

    if redirect_to == 'church_detail' or came_from_church_detail:
        return redirect(url_for('church_detail', church_id=church_id))
    return redirect(url_for('dashboard'))


@app.route('/admin/update-church-profile/<int:church_id>', methods=['POST'])
@admin_required
def update_church_profile(church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to update this church.', 'danger')
        return redirect(url_for('dashboard'))

    church_name = request.form.get('church_name', '').strip()
    barangay = request.form.get('barangay', '').strip()
    address = request.form.get('address', '').strip()
    latitude = request.form.get('latitude') or None
    longitude = request.form.get('longitude') or None
    date_built = request.form.get('date_built') or None
    monitoring_status = request.form.get('monitoring_status', 'Active')

    historical_background = request.form.get('historical_background', '').strip() or None
    historical_period = request.form.get('historical_period', '').strip() or None
    cultural_significance = request.form.get('cultural_significance', '').strip() or None
    religious_significance = request.form.get('religious_significance', '').strip() or None
    notable_artifacts = request.form.get('notable_artifacts', '').strip() or None

    redirect_to = request.form.get('redirect_to', '').strip()

    if session.get('role_name') == 'Super Admin':
        municipality_id = request.form.get('municipality_id')
    else:
        municipality_id = session.get('municipality_id')

    if not church_name or not barangay or not monitoring_status or not municipality_id:
        flash('Church name, municipality, barangay, and monitoring status are required.', 'danger')
        return redirect_after_church_action(church_id, redirect_to)

    try:
        cur = mysql.connection.cursor()

        cur.execute("""
            UPDATE churches
            SET church_name = %s,
                municipality_id = %s,
                barangay = %s,
                address = %s,
                latitude = %s,
                longitude = %s,
                date_built = %s,
                monitoring_status = %s
            WHERE church_id = %s
        """, (
            church_name,
            municipality_id,
            barangay,
            address,
            latitude,
            longitude,
            date_built,
            monitoring_status,
            church_id
        ))

        cur.execute("SELECT description_id FROM church_descriptions WHERE church_id = %s", (church_id,))
        existing_description = cur.fetchone()

        if existing_description:
            cur.execute("""
                UPDATE church_descriptions
                SET historical_background = %s,
                    historical_period = %s,
                    cultural_significance = %s,
                    religious_significance = %s,
                    notable_artifacts = %s
                WHERE church_id = %s
            """, (
                historical_background,
                historical_period,
                cultural_significance,
                religious_significance,
                notable_artifacts,
                church_id
            ))
            description_record_id = existing_description['description_id']
            description_action = 'UPDATE'
        else:
            cur.execute("""
                INSERT INTO church_descriptions
                    (church_id, historical_background, historical_period,
                     cultural_significance, religious_significance, notable_artifacts)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                church_id,
                historical_background,
                historical_period,
                cultural_significance,
                religious_significance,
                notable_artifacts
            ))
            description_record_id = cur.lastrowid
            description_action = 'INSERT'

        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'UPDATE',
            'churches',
            church_id,
            f'Updated church profile for "{church_name}" (ID {church_id}).'
        )

        log_audit(
            session.get('user_id'),
            description_action,
            'church_descriptions',
            description_record_id,
            f'Updated description profile for church ID {church_id}.'
        )

        flash('Church information and description updated successfully!', 'success')

    except Exception as e:
        print("UPDATE CHURCH PROFILE ERROR:", e)
        flash(f'Error updating church profile: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Delete Church ────────────────────────────────────────────────────────────
@app.route('/admin/delete-church/<int:church_id>', methods=['POST'])
@admin_required
def delete_church(church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to delete this church.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        cur = mysql.connection.cursor()

        cur.execute("""
            SELECT church_name
            FROM churches
            WHERE church_id = %s
        """, (church_id,))
        church = cur.fetchone()

        if not church:
            cur.close()
            flash('Church not found.', 'warning')
            return redirect(url_for('dashboard'))

        church_name = church['church_name']

        cur.execute("""
            SELECT ri.image_path
            FROM report_images ri
            JOIN disaster_reports dr ON ri.report_id = dr.report_id
            WHERE dr.church_id = %s
        """, (church_id,))
        report_images = cur.fetchall()

        cur.execute("""
            SELECT image_path
            FROM church_images
            WHERE church_id = %s
        """, (church_id,))
        church_images = cur.fetchall()

        cur.execute("DELETE FROM report_images WHERE report_id IN (SELECT report_id FROM disaster_reports WHERE church_id = %s)", (church_id,))
        cur.execute("DELETE FROM disaster_reports WHERE church_id = %s", (church_id,))
        cur.execute("DELETE FROM church_hazard_assessments WHERE church_id = %s", (church_id,))
        cur.execute("DELETE FROM church_descriptions WHERE church_id = %s", (church_id,))
        cur.execute("DELETE FROM heritage_recognitions WHERE church_id = %s", (church_id,))
        cur.execute("DELETE FROM church_images WHERE church_id = %s", (church_id,))
        cur.execute("DELETE FROM churches WHERE church_id = %s", (church_id,))

        mysql.connection.commit()
        cur.close()

        for img in report_images:
            if img.get('image_path'):
                absolute_path = os.path.join(app.static_folder, img['image_path'].replace('/', os.sep))
                if os.path.exists(absolute_path):
                    try:
                        os.remove(absolute_path)
                    except Exception as file_err:
                        print("DELETE REPORT IMAGE FILE ERROR:", file_err)

        for img in church_images:
            if img.get('image_path'):
                absolute_path = os.path.join(app.static_folder, img['image_path'].replace('/', os.sep))
                if os.path.exists(absolute_path):
                    try:
                        os.remove(absolute_path)
                    except Exception as file_err:
                        print("DELETE CHURCH IMAGE FILE ERROR:", file_err)

        log_audit(
            session.get('user_id'),
            'DELETE',
            'churches',
            church_id,
            f'Deleted church "{church_name}" and all related records.'
        )

        flash(f'Church "{church_name}" deleted successfully.', 'info')

    except Exception as e:
        print("DELETE CHURCH ERROR:", e)
        flash(f'Error deleting church: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))


# ─── Submit Disaster Report ───────────────────────────────────────────────────
@app.route('/admin/submit-report', methods=['POST'])
@admin_required
def submit_report():
    church_id = request.form.get('church_id')
    hazard_type_id = request.form.get('hazard_type_id')
    incident_date = request.form.get('incident_date') or None
    report_description = request.form.get('report_description', '').strip()
    damage_level = request.form.get('damage_level') or None
    uploaded_files = request.files.getlist('report_images')

    if not church_id or not hazard_type_id or not report_description:
        flash('Please fill in Church, Hazard Type, and Report Description.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        cur = mysql.connection.cursor()
        role_name = session.get('role_name')

        if role_name == 'Municipal Admin':
            cur.execute("""
                SELECT municipality_id
                FROM churches
                WHERE church_id = %s
            """, (church_id,))
            church = cur.fetchone()

            if not church or church['municipality_id'] != session.get('municipality_id'):
                cur.close()
                flash('You do not have permission to submit a report for this church.', 'danger')
                return redirect(url_for('dashboard'))

        cur.execute("""
            INSERT INTO disaster_reports
                (church_id, hazard_type_id, incident_date,
                 report_description, damage_level,
                 report_status, reported_by)
            VALUES (%s, %s, %s, %s, %s, 'Reported - Validated', %s)
        """, (
            church_id,
            hazard_type_id,
            incident_date,
            report_description,
            damage_level,
            session.get('user_id')
        ))
        mysql.connection.commit()

        new_report_id = cur.lastrowid
        saved_paths = save_report_images(uploaded_files)

        for image in saved_paths:
            cur.execute("""
                INSERT INTO report_images (report_id, image_path)
                VALUES (%s, %s)
            """, (new_report_id, image["url"]))

        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'INSERT',
            'disaster_reports',
            new_report_id,
            f'Submitted a disaster report for church ID {church_id} with {len(saved_paths)} image(s).'
        )

        flash('Disaster report submitted successfully!', 'success')

    except Exception as e:
        print("DATABASE ERROR:", e)
        flash(f'Error submitting report: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))


# ─── Update Church Description ────────────────────────────────────────────────
@app.route('/admin/update-church-description/<int:church_id>', methods=['POST'])
@admin_required
def update_church_description(church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to manage this church description.', 'danger')
        return redirect(url_for('church_detail', church_id=church_id))

    historical_background = request.form.get('historical_background', '').strip() or None
    historical_period = request.form.get('historical_period', '').strip() or None
    cultural_significance = request.form.get('cultural_significance', '').strip() or None
    religious_significance = request.form.get('religious_significance', '').strip() or None
    notable_artifacts = request.form.get('notable_artifacts', '').strip() or None

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT description_id FROM church_descriptions WHERE church_id = %s", (church_id,))
        existing = cur.fetchone()

        if existing:
            cur.execute("""
                UPDATE church_descriptions
                SET historical_background = %s,
                    historical_period = %s,
                    cultural_significance = %s,
                    religious_significance = %s,
                    notable_artifacts = %s
                WHERE church_id = %s
            """, (
                historical_background,
                historical_period,
                cultural_significance,
                religious_significance,
                notable_artifacts,
                church_id
            ))
            record_id = existing['description_id']
            action_type = 'UPDATE'
        else:
            cur.execute("""
                INSERT INTO church_descriptions
                    (church_id, historical_background, historical_period,
                     cultural_significance, religious_significance, notable_artifacts)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                church_id,
                historical_background,
                historical_period,
                cultural_significance,
                religious_significance,
                notable_artifacts
            ))
            record_id = cur.lastrowid
            action_type = 'INSERT'

        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            action_type,
            'church_descriptions',
            record_id,
            f'Updated description content for church ID {church_id}.'
        )

        flash('Church description updated successfully!', 'success')

    except Exception as e:
        print("DESCRIPTION UPDATE ERROR:", e)
        flash(f'Error updating church description: {str(e)}', 'danger')

    return redirect(url_for('church_detail', church_id=church_id))


# ─── Add Heritage Recognition ─────────────────────────────────────────────────
@app.route('/admin/add-recognition/<int:church_id>', methods=['POST'])
@admin_required
def add_recognition(church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to manage this church recognition.', 'danger')
        return redirect(url_for('dashboard'))

    recognition_title = request.form.get('recognition_title', '').strip()
    issuing_body = request.form.get('issuing_body', '').strip() or None
    year_recognized = request.form.get('year_recognized') or None
    redirect_to = request.form.get('redirect_to', '').strip()

    if not recognition_title:
        flash('Recognition title is required.', 'danger')
        return redirect_after_church_action(church_id, redirect_to)

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO heritage_recognitions
                (church_id, recognition_title, issuing_body, year_recognized)
            VALUES (%s, %s, %s, %s)
        """, (church_id, recognition_title, issuing_body, year_recognized))
        mysql.connection.commit()
        new_recognition_id = cur.lastrowid
        cur.close()

        log_audit(
            session.get('user_id'),
            'INSERT',
            'heritage_recognitions',
            new_recognition_id,
            f'Added heritage recognition for church ID {church_id}.'
        )

        flash('Heritage recognition added successfully!', 'success')

    except Exception as e:
        print("ADD RECOGNITION ERROR:", e)
        flash(f'Error adding recognition: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Update Heritage Recognition ──────────────────────────────────────────────
@app.route('/admin/update-recognition/<int:recognition_id>/<int:church_id>', methods=['POST'])
@admin_required
def update_recognition(recognition_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to edit this recognition.', 'danger')
        return redirect(url_for('dashboard'))

    recognition_title = request.form.get('recognition_title', '').strip()
    issuing_body = request.form.get('issuing_body', '').strip() or None
    year_recognized = request.form.get('year_recognized') or None
    redirect_to = request.form.get('redirect_to', '').strip()

    if not recognition_title:
        flash('Recognition title is required.', 'danger')
        return redirect_after_church_action(church_id, redirect_to)

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE heritage_recognitions
            SET recognition_title = %s,
                issuing_body = %s,
                year_recognized = %s
            WHERE recognition_id = %s AND church_id = %s
        """, (
            recognition_title,
            issuing_body,
            year_recognized,
            recognition_id,
            church_id
        ))
        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'UPDATE',
            'heritage_recognitions',
            recognition_id,
            f'Updated heritage recognition for church ID {church_id}.'
        )

        flash('Recognition updated successfully!', 'success')

    except Exception as e:
        print("UPDATE RECOGNITION ERROR:", e)
        flash(f'Error updating recognition: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Delete Heritage Recognition ──────────────────────────────────────────────
@app.route('/admin/delete-recognition/<int:recognition_id>/<int:church_id>', methods=['POST'])
@admin_required
def delete_recognition(recognition_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to delete this recognition.', 'danger')
        return redirect(url_for('dashboard'))

    redirect_to = request.form.get('redirect_to', '').strip()

    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM heritage_recognitions WHERE recognition_id = %s", (recognition_id,))
        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'DELETE',
            'heritage_recognitions',
            recognition_id,
            f'Deleted heritage recognition for church ID {church_id}.'
        )

        flash('Recognition deleted successfully!', 'info')

    except Exception as e:
        print("DELETE RECOGNITION ERROR:", e)
        flash(f'Error deleting recognition: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Upload Church Gallery Image ──────────────────────────────────────────────
@app.route('/admin/upload-church-image/<int:church_id>', methods=['POST'])
@admin_required
def upload_church_image(church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to upload images for this church.', 'danger')
        return redirect(url_for('dashboard'))

    uploaded_files = request.files.getlist('church_images')
    image_caption = request.form.get('image_caption', '').strip()
    redirect_to = request.form.get('redirect_to', '').strip()

    try:
        saved_paths = save_church_images(uploaded_files)

        if not saved_paths:
            flash('No valid image file was uploaded.', 'warning')
            return redirect_after_church_action(church_id, redirect_to)

        cur = mysql.connection.cursor()
        first_image_id = None

        for image in saved_paths:
            cur.execute("""
                INSERT INTO church_images (church_id, image_path, image_caption, uploaded_by)
                VALUES (%s, %s, %s, %s)
            """, (
                church_id,
                image["url"],
                image_caption if image_caption else None,
                session.get('user_id')
            ))
            if first_image_id is None:
                first_image_id = cur.lastrowid

        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'INSERT',
            'church_images',
            first_image_id,
            f'Uploaded {len(saved_paths)} church image(s) for church ID {church_id}.'
        )

        flash('Church gallery image uploaded successfully!', 'success')

    except Exception as e:
        print("CHURCH IMAGE UPLOAD ERROR:", e)
        flash(f'Error uploading church image: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Update Church Gallery Caption ────────────────────────────────────────────
@app.route('/admin/update-church-image-caption/<int:image_id>/<int:church_id>', methods=['POST'])
@admin_required
def update_church_image_caption(image_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to edit this church image.', 'danger')
        return redirect(url_for('dashboard'))

    image_caption = request.form.get('image_caption', '').strip() or None
    redirect_to = request.form.get('redirect_to', '').strip()

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE church_images
            SET image_caption = %s
            WHERE image_id = %s AND church_id = %s
        """, (image_caption, image_id, church_id))
        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'UPDATE',
            'church_images',
            image_id,
            f'Updated church gallery caption for church ID {church_id}.'
        )

        flash('Church gallery caption updated successfully!', 'success')

    except Exception as e:
        print("UPDATE CHURCH IMAGE CAPTION ERROR:", e)
        flash(f'Error updating image caption: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Delete Church Gallery Image ──────────────────────────────────────────────
@app.route('/admin/delete-church-image/<int:image_id>/<int:church_id>', methods=['POST'])
@admin_required
def delete_church_image(image_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to delete this church image.', 'danger')
        return redirect(url_for('dashboard'))

    redirect_to = request.form.get('redirect_to', '').strip()

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT image_path
            FROM church_images
            WHERE image_id = %s AND church_id = %s
        """, (image_id, church_id))
        image = cur.fetchone()

        if not image:
            cur.close()
            flash('Church image not found.', 'warning')
            return redirect_after_church_action(church_id, redirect_to)

        image_path = image['image_path']
        cur.execute("DELETE FROM church_images WHERE image_id = %s", (image_id,))
        mysql.connection.commit()
        cur.close()

        if image_path:
            absolute_path = os.path.join(app.static_folder, image_path.replace('/', os.sep))
            if os.path.exists(absolute_path):
                try:
                    os.remove(absolute_path)
                except Exception as file_err:
                    print("FILE DELETE ERROR:", file_err)

        log_audit(
            session.get('user_id'),
            'DELETE',
            'church_images',
            image_id,
            f'Deleted church gallery image for church ID {church_id}.'
        )

        flash('Church gallery image deleted successfully!', 'info')

    except Exception as e:
        print("DELETE CHURCH IMAGE ERROR:", e)
        flash(f'Error deleting church image: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

#_______Submit Public Report________
@app.route('/submit-public-report', methods=['POST'])
def submit_public_report():
    if 'user_id' not in session or session.get('role_name') != 'Public User':
        session['pending_public_report'] = {
            'church_id': request.form.get('church_id', ''),
            'hazard_type_id': request.form.get('hazard_type_id', ''),
            'incident_date': request.form.get('incident_date', ''),
            'damage_level': request.form.get('damage_level', ''),
            'report_description': request.form.get('report_description', '').strip()
        }

        flash('Please log in or sign up first. Your report details were saved, but you will need to re-attach any photo uploads.', 'warning')
        return redirect(url_for('public_login'))

    church_id = request.form.get('church_id')
    hazard_type_id = request.form.get('hazard_type_id')
    incident_date = request.form.get('incident_date') or None
    report_description = request.form.get('report_description', '').strip()
    damage_level = request.form.get('damage_level') or None
    uploaded_files = request.files.getlist('report_images')

    if not church_id or not hazard_type_id or not report_description:
        flash('Please fill in Church, Hazard Type, and Report Description.', 'danger')
        return redirect(url_for('public_reports'))

    try:
        cur = mysql.connection.cursor()

        cur.execute("""
            INSERT INTO disaster_reports
                (church_id, hazard_type_id, incident_date,
                 report_description, damage_level,
                 report_status, reported_by)
            VALUES (%s, %s, %s, %s, %s, 'Pending Validation', %s)
        """, (
            church_id,
            hazard_type_id,
            incident_date,
            report_description,
            damage_level,
            session.get('user_id')
        ))
        mysql.connection.commit()

        new_report_id = cur.lastrowid
        saved_paths = save_report_images(uploaded_files)

        for image in saved_paths:
            cur.execute("""
                INSERT INTO report_images (report_id, image_path)
                VALUES (%s, %s)
            """, (new_report_id, image["url"]))

        mysql.connection.commit()
        cur.close()

        session.pop('pending_public_report', None)

        flash('Your report has been submitted successfully and is now pending review.', 'success')

    except Exception as e:
        print("PUBLIC REPORT SUBMIT ERROR:", e)
        flash(f'Error submitting report: {str(e)}', 'danger')

    return redirect(url_for('public_reports'))

# ─── Delete Individual Report Image ───────────────────────────────────────────
@app.route('/admin/delete-report-image/<int:report_image_id>/<int:report_id>/<int:church_id>', methods=['POST'])
@admin_required
def delete_report_image(report_image_id, report_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to delete this report image.', 'danger')
        return redirect(url_for('dashboard'))

    redirect_to = request.form.get('redirect_to', '').strip()

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT ri.image_path
            FROM report_images ri
            JOIN disaster_reports dr ON ri.report_id = dr.report_id
            WHERE ri.report_image_id = %s
              AND ri.report_id = %s
              AND dr.church_id = %s
        """, (report_image_id, report_id, church_id))
        image = cur.fetchone()

        if not image:
            cur.close()
            flash('Report image not found.', 'warning')
            return redirect_after_church_action(church_id, redirect_to)

        image_path = image['image_path']

        cur.execute("""
            DELETE FROM report_images
            WHERE report_image_id = %s AND report_id = %s
        """, (report_image_id, report_id))
        mysql.connection.commit()
        cur.close()

        if image_path:
            absolute_path = os.path.join(app.static_folder, image_path.replace('/', os.sep))
            if os.path.exists(absolute_path):
                try:
                    os.remove(absolute_path)
                except Exception as file_err:
                    print("DELETE REPORT IMAGE FILE ERROR:", file_err)

        log_audit(
            session.get('user_id'),
            'DELETE',
            'report_images',
            report_image_id,
            f'Deleted individual report image from report ID {report_id} for church ID {church_id}.'
        )

        flash('Report image deleted successfully!', 'info')

    except Exception as e:
        print("DELETE REPORT IMAGE ERROR:", e)
        flash(f'Error deleting report image: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Update Disaster Report ───────────────────────────────────────────────────
@app.route('/admin/update-disaster-report/<int:report_id>/<int:church_id>', methods=['POST'])
@admin_required
def update_disaster_report(report_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to edit this disaster report.', 'danger')
        return redirect(url_for('dashboard'))

    hazard_type_id = request.form.get('hazard_type_id')
    incident_date = request.form.get('incident_date') or None
    damage_level = request.form.get('damage_level') or None
    report_description = request.form.get('report_description', '').strip()
    report_status = request.form.get('report_status', '').strip()
    redirect_to = request.form.get('redirect_to', '').strip()

    if not hazard_type_id or not report_description or not report_status:
        flash('Hazard type, description, and report status are required.', 'danger')
        return redirect_after_church_action(church_id, redirect_to)

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE disaster_reports
            SET hazard_type_id = %s,
                incident_date = %s,
                damage_level = %s,
                report_description = %s,
                report_status = %s
            WHERE report_id = %s AND church_id = %s
        """, (
            hazard_type_id,
            incident_date,
            damage_level,
            report_description,
            report_status,
            report_id,
            church_id
        ))
        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'UPDATE',
            'disaster_reports',
            report_id,
            f'Updated disaster report for church ID {church_id}.'
        )

        flash('Disaster report updated successfully!', 'success')

    except Exception as e:
        print("UPDATE DISASTER REPORT ERROR:", e)
        flash(f'Error updating disaster report: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Delete Disaster Report ───────────────────────────────────────────────────
@app.route('/admin/delete-disaster-report/<int:report_id>/<int:church_id>', methods=['POST'])
@admin_required
def delete_disaster_report(report_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to delete this disaster report.', 'danger')
        return redirect(url_for('church_detail', church_id=church_id))

    try:
        cur = mysql.connection.cursor()

        cur.execute("""
            SELECT image_path
            FROM report_images
            WHERE report_id = %s
        """, (report_id,))
        report_images = cur.fetchall()

        cur.execute("DELETE FROM report_images WHERE report_id = %s", (report_id,))
        cur.execute("DELETE FROM disaster_reports WHERE report_id = %s AND church_id = %s", (report_id, church_id))

        mysql.connection.commit()
        cur.close()

        for img in report_images:
            if img.get('image_path'):
                absolute_path = os.path.join(app.static_folder, img['image_path'].replace('/', os.sep))
                if os.path.exists(absolute_path):
                    try:
                        os.remove(absolute_path)
                    except Exception as file_err:
                        print("REPORT IMAGE DELETE ERROR:", file_err)

        log_audit(
            session.get('user_id'),
            'DELETE',
            'disaster_reports',
            report_id,
            f'Deleted disaster report for church ID {church_id}.'
        )

        flash('Disaster report deleted successfully!', 'info')

    except Exception as e:
        print("DELETE DISASTER REPORT ERROR:", e)
        flash(f'Error deleting disaster report: {str(e)}', 'danger')

    return redirect(url_for('church_detail', church_id=church_id))


# ─── Add Hazard Assessment ────────────────────────────────────────────────────
@app.route('/admin/add-assessment', methods=['POST'])
@admin_required
def add_assessment():
    church_id = request.form.get('church_id')
    hazard_type_id = request.form.get('hazard_type_id')
    risk_level = request.form.get('risk_level')
    assessment_date = request.form.get('assessment_date') or None
    assessment_remarks = request.form.get('assessment_remarks', '').strip()
    redirect_to = request.form.get('redirect_to', '').strip()

    if not church_id or not hazard_type_id or not risk_level:
        flash('Church, hazard type, and risk level are required.', 'danger')
        return redirect(url_for('dashboard'))

    cur = mysql.connection.cursor()

    if session.get('role_name') != 'Super Admin':
        cur.execute("SELECT municipality_id FROM churches WHERE church_id = %s", (church_id,))
        church = cur.fetchone()
        if not church or church['municipality_id'] != session.get('municipality_id'):
            flash('You do not have permission to assess this church.', 'danger')
            cur.close()
            if church_id:
                return redirect(url_for('church_detail', church_id=church_id))
            return redirect(url_for('dashboard'))

    cur.execute("""
        INSERT INTO church_hazard_assessments
            (church_id, hazard_type_id, risk_level,
             assessment_date, assessment_remarks, assessed_by)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        church_id, hazard_type_id, risk_level,
        assessment_date, assessment_remarks,
        session.get('user_id')
    ))
    mysql.connection.commit()
    new_assessment_id = cur.lastrowid
    cur.close()

    log_audit(
        session.get('user_id'),
        'INSERT',
        'church_hazard_assessments',
        new_assessment_id,
        f'Added hazard assessment for church ID {church_id}.'
    )

    flash('Hazard assessment added successfully!', 'success')

    if redirect_to == 'church_detail' and church_id:
        return redirect(url_for('church_detail', church_id=church_id))

    return redirect(url_for('dashboard'))


# ─── Update Hazard Assessment ─────────────────────────────────────────────────
@app.route('/admin/update-assessment/<int:assessment_id>/<int:church_id>', methods=['POST'])
@admin_required
def update_assessment(assessment_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to edit this hazard assessment.', 'danger')
        return redirect(url_for('dashboard'))

    hazard_type_id = request.form.get('hazard_type_id')
    risk_level = request.form.get('risk_level')
    assessment_date = request.form.get('assessment_date') or None
    assessment_remarks = request.form.get('assessment_remarks', '').strip() or None
    redirect_to = request.form.get('redirect_to', '').strip()

    if not hazard_type_id or not risk_level:
        flash('Hazard type and risk level are required.', 'danger')
        return redirect_after_church_action(church_id, redirect_to)

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE church_hazard_assessments
            SET hazard_type_id = %s,
                risk_level = %s,
                assessment_date = %s,
                assessment_remarks = %s
            WHERE assessment_id = %s AND church_id = %s
        """, (
            hazard_type_id,
            risk_level,
            assessment_date,
            assessment_remarks,
            assessment_id,
            church_id
        ))
        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'UPDATE',
            'church_hazard_assessments',
            assessment_id,
            f'Updated hazard assessment for church ID {church_id}.'
        )

        flash('Hazard assessment updated successfully!', 'success')

    except Exception as e:
        print("UPDATE ASSESSMENT ERROR:", e)
        flash(f'Error updating hazard assessment: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── Delete Hazard Assessment ─────────────────────────────────────────────────
@app.route('/admin/delete-assessment/<int:assessment_id>/<int:church_id>', methods=['POST'])
@admin_required
def delete_assessment(assessment_id, church_id):
    if not can_manage_church(church_id):
        flash('You do not have permission to delete this hazard assessment.', 'danger')
        return redirect(url_for('dashboard'))

    redirect_to = request.form.get('redirect_to', '').strip()

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            DELETE FROM church_hazard_assessments
            WHERE assessment_id = %s AND church_id = %s
        """, (assessment_id, church_id))
        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'DELETE',
            'church_hazard_assessments',
            assessment_id,
            f'Deleted hazard assessment for church ID {church_id}.'
        )

        flash('Hazard assessment deleted successfully!', 'info')

    except Exception as e:
        print("DELETE ASSESSMENT ERROR:", e)
        flash(f'Error deleting hazard assessment: {str(e)}', 'danger')

    return redirect_after_church_action(church_id, redirect_to)

# ─── User Management ──────────────────────────────────────────────────────────
@app.route('/admin/users')
@login_required
@super_admin_required
def admin_users():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT u.*, r.role_name, m.municipality_name
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        LEFT JOIN municipalities m ON u.municipality_id = m.municipality_id
        ORDER BY u.created_at DESC
    """)
    users = cur.fetchall()

    cur.execute("SELECT * FROM roles ORDER BY role_id ASC")
    roles = cur.fetchall()

    cur.execute("SELECT * FROM municipalities ORDER BY municipality_name ASC")
    municipalities = cur.fetchall()

    cur.close()

    return render_template(
        'users.html',
        users=users,
        roles=roles,
        municipalities=municipalities
    )


# ─── Add User ─────────────────────────────────────────────────────────────────
@app.route('/admin/users/add', methods=['POST'])
@login_required
@super_admin_required
def add_user():
    full_name = request.form.get('full_name', '').strip()
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    role_id = request.form.get('role_id')
    municipality_id = request.form.get('municipality_id') or None

    if not full_name or not username or not email or not password or not role_id:
        flash('Full name, username, email, password, and role are required.', 'danger')
        return redirect(url_for('admin_users'))

    try:
        cur = mysql.connection.cursor()

        cur.execute("""
            SELECT user_id
            FROM users
            WHERE username = %s OR email = %s
        """, (username, email))
        existing_user = cur.fetchone()

        if existing_user:
            cur.close()
            flash('Username or email already exists. Please use a different one.', 'danger')
            return redirect(url_for('admin_users'))

        hashed_password = generate_password_hash(password)

        cur.execute("""
    INSERT INTO users
        (full_name, username, email, password_hash,
         role_id, municipality_id, account_status)
    VALUES (%s, %s, %s, %s, %s, %s, 'active')
""", (full_name, username, email, hashed_password, role_id, municipality_id))
        mysql.connection.commit()
        new_user_id = cur.lastrowid
        cur.close()

        log_audit(
            session.get('user_id'),
            'INSERT',
            'users',
            new_user_id,
            f'Created user "{username}".'
        )

        flash(f'User "{username}" has been created successfully!', 'success')

    except Exception as e:
        print("ADD USER ERROR:", e)
        flash(f'Error creating user: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))


# ─── Update User ──────────────────────────────────────────────────────────────
@app.route('/admin/users/update/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def update_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot edit your own account from this page.', 'danger')
        return redirect(url_for('admin_users'))

    full_name = request.form.get('full_name', '').strip()
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    role_id = request.form.get('role_id')
    municipality_id = request.form.get('municipality_id') or None
    account_status = request.form.get('account_status', 'active').strip()

    if not full_name or not username or not email or not role_id:
        flash('Full name, username, email, and role are required.', 'danger')
        return redirect(url_for('admin_users'))

    try:
        cur = mysql.connection.cursor()

        cur.execute("SELECT username FROM users WHERE user_id = %s", (user_id,))
        existing_user = cur.fetchone()

        if not existing_user:
            cur.close()
            flash('User not found.', 'danger')
            return redirect(url_for('admin_users'))

        cur.execute("""
            SELECT user_id
            FROM users
            WHERE (username = %s OR email = %s)
              AND user_id != %s
        """, (username, email, user_id))
        duplicate_user = cur.fetchone()

        if duplicate_user:
            cur.close()
            flash('Username or email already exists for another user.', 'danger')
            return redirect(url_for('admin_users'))

        if password:
            hashed_password = generate_password_hash(password)

            cur.execute("""
                UPDATE users
                SET full_name = %s,
                    username = %s,
                    email = %s,
                    password_hash = %s,
                    role_id = %s,
                    municipality_id = %s,
                    account_status = %s
                WHERE user_id = %s
            """, (
                full_name,
                username,
                email,
                hashed_password,
                role_id,
                municipality_id,
                account_status,
                user_id
            ))
        else:
            cur.execute("""
                UPDATE users
                SET full_name = %s,
                    username = %s,
                    email = %s,
                    role_id = %s,
                    municipality_id = %s,
                    account_status = %s
                WHERE user_id = %s
            """, (
                full_name,
                username,
                email,
                role_id,
                municipality_id,
                account_status,
                user_id
            ))

        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'UPDATE',
            'users',
            user_id,
            f'Updated user "{username}".'
        )

        flash(f'User "{username}" updated successfully!', 'success')

    except Exception as e:
        print("UPDATE USER ERROR:", e)
        flash(f'Error updating user: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))


# ─── Toggle User Status ───────────────────────────────────────────────────────
@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def toggle_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('admin_users'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT username, account_status FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()

    if not user:
        cur.close()
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    new_status = 'inactive' if user['account_status'] == 'active' else 'active'

    cur.execute("UPDATE users SET account_status = %s WHERE user_id = %s", (new_status, user_id))
    mysql.connection.commit()
    cur.close()

    log_audit(
        session.get('user_id'),
        'UPDATE',
        'users',
        user_id,
        f'Changed status of user "{user["username"]}" to {new_status}.'
    )

    flash(f'User account has been {"activated" if new_status == "active" else "deactivated"}.', 'success')
    return redirect(url_for('admin_users'))


# ─── Delete User ──────────────────────────────────────────────────────────────
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))

    try:
        cur = mysql.connection.cursor()

        cur.execute("SELECT username FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()

        if not user:
            cur.close()
            flash('User not found.', 'danger')
            return redirect(url_for('admin_users'))

        username = user['username']

        # Delete dependent audit logs first to avoid foreign key constraint errors
        cur.execute("DELETE FROM audit_logs WHERE user_id = %s", (user_id,))

        # Now delete the user
        cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        mysql.connection.commit()
        cur.close()

        log_audit(
            session.get('user_id'),
            'DELETE',
            'users',
            user_id,
            f'Deleted user \"{username}\".'
        )

        flash(f'User \"{username}\" has been deleted.', 'info')

    except Exception as e:
        print("DELETE USER ERROR:", e)
        flash(f'Error deleting user: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))


# ─── View All Reports ─────────────────────────────────────────────────────────
@app.route('/admin/reports')
@admin_required
def view_reports():
    cur = mysql.connection.cursor()

    if session.get('role_name') == 'Super Admin':
        cur.execute("""
            SELECT dr.*, c.church_name, m.municipality_name, ht.hazard_name,
                   u.full_name AS reported_by_name
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            JOIN hazard_types ht ON dr.hazard_type_id = ht.hazard_type_id
            LEFT JOIN users u ON dr.reported_by = u.user_id
            ORDER BY dr.report_date DESC
        """)
    else:
        cur.execute("""
            SELECT dr.*, c.church_name, m.municipality_name, ht.hazard_name,
                   u.full_name AS reported_by_name
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            JOIN municipalities m ON c.municipality_id = m.municipality_id
            JOIN hazard_types ht ON dr.hazard_type_id = ht.hazard_type_id
            LEFT JOIN users u ON dr.reported_by = u.user_id
            WHERE m.municipality_id = %s
            ORDER BY dr.report_date DESC
        """, (session.get('municipality_id'),))
    reports = cur.fetchall()

    cur.execute("SELECT * FROM hazard_types ORDER BY hazard_name ASC")
    hazard_types = cur.fetchall()

    cur.close()

    return render_template(
        'reports.html',
        reports=reports,
        hazard_types=hazard_types
    )

# ─── Update Report Status ─────────────────────────────────────────────────────
@app.route('/admin/update-report/<int:report_id>', methods=['POST'])
@admin_required
def update_report(report_id):
    new_status = request.form.get('report_status')
    validated_by = session.get('user_id')

    if not new_status:
        flash('Report status is required.', 'danger')
        return redirect(url_for('dashboard'))

    cur = mysql.connection.cursor()

    if session.get('role_name') != 'Super Admin':
        cur.execute("""
            SELECT c.municipality_id
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            WHERE dr.report_id = %s
        """, (report_id,))
        report = cur.fetchone()

        if not report or report['municipality_id'] != session.get('municipality_id'):
            flash('You do not have permission to update this report.', 'danger')
            cur.close()
            return redirect(url_for('dashboard'))

    if new_status == 'Resolved':
        cur.execute("""
            UPDATE disaster_reports
            SET report_status = %s,
                validated_by = %s,
                validated_date = NOW()
            WHERE report_id = %s
        """, (new_status, validated_by, report_id))
    else:
        cur.execute("""
            UPDATE disaster_reports
            SET report_status = %s
            WHERE report_id = %s
        """, (new_status, report_id))

    mysql.connection.commit()
    cur.close()

    log_audit(
        session.get('user_id'),
        'UPDATE',
        'disaster_reports',
        report_id,
        f'Updated disaster report status to "{new_status}".'
    )

    flash(f'Report status updated to "{new_status}" successfully!', 'success')
    return redirect(url_for('dashboard'))

# ─── Analytics ────────────────────────────────────────────────────────────────
@app.route('/admin/analytics')
@admin_required
def analytics():
    cur = mysql.connection.cursor()

    if is_super_admin():
        cur.execute("""
            SELECT report_status, COUNT(*) AS total
            FROM disaster_reports
            GROUP BY report_status
        """)
        reports_by_status = cur.fetchall()

        cur.execute("""
            SELECT ht.hazard_name, COUNT(dr.report_id) AS total
            FROM hazard_types ht
            LEFT JOIN disaster_reports dr ON ht.hazard_type_id = dr.hazard_type_id
            GROUP BY ht.hazard_type_id, ht.hazard_name
            ORDER BY total DESC, ht.hazard_name ASC
        """)
        reports_by_hazard = cur.fetchall()

        cur.execute("""
            SELECT
                SUM(CASE WHEN highest_risk = 'High' THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN highest_risk = 'Medium' THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN highest_risk = 'Low' THEN 1 ELSE 0 END) AS low,
                SUM(CASE WHEN highest_risk IS NULL THEN 1 ELSE 0 END) AS unassessed
            FROM (
                SELECT c.church_id,
                    MAX(CASE WHEN cha.risk_level = 'High' THEN 'High'
                             WHEN cha.risk_level = 'Medium' THEN 'Medium'
                             WHEN cha.risk_level = 'Low' THEN 'Low'
                             ELSE NULL END) AS highest_risk
                FROM churches c
                LEFT JOIN church_hazard_assessments cha ON c.church_id = cha.church_id
                GROUP BY c.church_id
            ) AS risk_summary
        """)
        risk_summary = cur.fetchone()

        cur.execute("""
            SELECT m.municipality_name, COUNT(dr.report_id) AS total
            FROM municipalities m
            JOIN churches c ON m.municipality_id = c.municipality_id
            JOIN disaster_reports dr ON c.church_id = dr.church_id
            GROUP BY m.municipality_id, m.municipality_name
            HAVING COUNT(dr.report_id) > 0
            ORDER BY total DESC, m.municipality_name ASC
            LIMIT 10
        """)
        reports_by_municipality = cur.fetchall()

        cur.execute("SELECT COUNT(*) AS total FROM churches")
        total_churches = cur.fetchone()['total']

        cur.execute("SELECT COUNT(*) AS total FROM disaster_reports")
        total_reports = cur.fetchone()['total']

        cur.execute("SELECT COUNT(*) AS total FROM disaster_reports WHERE report_status = 'Resolved'")
        resolved_reports = cur.fetchone()['total']

        cur.execute("SELECT COUNT(*) AS total FROM church_hazard_assessments")
        total_assessments = cur.fetchone()['total']

        scope_label = 'System-wide'

    else:
        municipality_id = session.get('municipality_id')

        cur.execute("""
            SELECT dr.report_status, COUNT(*) AS total
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            WHERE c.municipality_id = %s
            GROUP BY dr.report_status
        """, (municipality_id,))
        reports_by_status = cur.fetchall()

        cur.execute("""
            SELECT ht.hazard_name, COUNT(dr.report_id) AS total
            FROM hazard_types ht
            LEFT JOIN disaster_reports dr
                ON ht.hazard_type_id = dr.hazard_type_id
               AND dr.church_id IN (
                    SELECT church_id
                    FROM churches
                    WHERE municipality_id = %s
               )
            GROUP BY ht.hazard_type_id, ht.hazard_name
            ORDER BY total DESC, ht.hazard_name ASC
        """, (municipality_id,))
        reports_by_hazard = cur.fetchall()

        cur.execute("""
            SELECT
                SUM(CASE WHEN highest_risk = 'High' THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN highest_risk = 'Medium' THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN highest_risk = 'Low' THEN 1 ELSE 0 END) AS low,
                SUM(CASE WHEN highest_risk IS NULL THEN 1 ELSE 0 END) AS unassessed
            FROM (
                SELECT c.church_id,
                    MAX(CASE WHEN cha.risk_level = 'High' THEN 'High'
                             WHEN cha.risk_level = 'Medium' THEN 'Medium'
                             WHEN cha.risk_level = 'Low' THEN 'Low'
                             ELSE NULL END) AS highest_risk
                FROM churches c
                LEFT JOIN church_hazard_assessments cha ON c.church_id = cha.church_id
                WHERE c.municipality_id = %s
                GROUP BY c.church_id
            ) AS risk_summary
        """, (municipality_id,))
        risk_summary = cur.fetchone()

        cur.execute("""
            SELECT m.municipality_name, COUNT(dr.report_id) AS total
            FROM municipalities m
            JOIN churches c ON m.municipality_id = c.municipality_id
            JOIN disaster_reports dr ON c.church_id = dr.church_id
            WHERE m.municipality_id = %s
            GROUP BY m.municipality_id, m.municipality_name
            HAVING COUNT(dr.report_id) > 0
            ORDER BY total DESC, m.municipality_name ASC
            LIMIT 10
        """, (municipality_id,))
        reports_by_municipality = cur.fetchall()

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM churches
            WHERE municipality_id = %s
        """, (municipality_id,))
        total_churches = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            WHERE c.municipality_id = %s
        """, (municipality_id,))
        total_reports = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM disaster_reports dr
            JOIN churches c ON dr.church_id = c.church_id
            WHERE c.municipality_id = %s
              AND dr.report_status = 'Resolved'
        """, (municipality_id,))
        resolved_reports = cur.fetchone()['total']

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM church_hazard_assessments cha
            JOIN churches c ON cha.church_id = c.church_id
            WHERE c.municipality_id = %s
        """, (municipality_id,))
        total_assessments = cur.fetchone()['total']

        cur.execute("""
            SELECT municipality_name
            FROM municipalities
            WHERE municipality_id = %s
        """, (municipality_id,))
        muni = cur.fetchone()
        scope_label = muni['municipality_name'] if muni else 'Assigned Municipality'

    cur.close()

    return render_template(
        'analytics.html',
        reports_by_status=reports_by_status,
        reports_by_hazard=reports_by_hazard,
        risk_summary=risk_summary,
        reports_by_municipality=reports_by_municipality,
        total_churches=total_churches,
        total_reports=total_reports,
        resolved_reports=resolved_reports,
        total_assessments=total_assessments,
        scope_label=scope_label
    )


# ─── Audit Logs ───────────────────────────────────────────────────────────────
@app.route('/admin/logs')
@admin_required
def audit_logs():
    if session.get('role_name') != 'Super Admin':
        flash('Only Super Admins can view audit logs.', 'danger')
        return redirect(url_for('dashboard'))

    logs = []
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT al.*, u.full_name, u.username
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.user_id
            ORDER BY al.action_timestamp DESC
            LIMIT 200
        """)
        logs = cur.fetchall()
        cur.close()
    except Exception as e:
        flash(f'Error loading audit logs: {str(e)}', 'danger')

    return render_template('audit_logs.html', logs=logs)


# ─── Favicon ──────────────────────────────────────────────────────────────────
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.png',
        mimetype='image/png'
    )


# ─── Error Handlers ───────────────────────────────────────────────────────────
@app.errorhandler(413)
def request_entity_too_large(error):
    flash('Uploaded file is too large. Maximum allowed size is 5 MB.', 'danger')
    return redirect(request.referrer or url_for('dashboard'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500


if __name__ == '__main__':
    app.run(debug=False)
