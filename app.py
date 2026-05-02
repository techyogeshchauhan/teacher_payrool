from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from flask_mail import Mail, Message
from datetime import date, datetime, timezone, timedelta
from werkzeug.utils import secure_filename
import random
import pandas as pd
import io
import hashlib
import calendar
from bson.objectid import ObjectId
import os
from pymongo import MongoClient

app = Flask(__name__)
app.secret_key = 'gayatri_vidyapith_secret_2024'

# MongoDB Connection
mongo_uri = os.environ.get('MONGO_URI', 'mongodb+srv://GVP:QeMjUCPTfgZJVHVO@gvp.sbsdal5.mongodb.net/?appName=GVP')
client = MongoClient(mongo_uri)
db = client['gayatri_school']

teachers_col = db['teachers']
attendance_col = db['attendance']
admins_col = db['admins']
principals_col = db['principals']
increment_col = db['increments']
holidays_col = db['govt_holidays']
logs_col = db['activity_logs']
assets_col = db['assets']
# Flask-Mail Configuration (Use environment variables or hardcode for now)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'yc993205@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'kgahkdejlanmoiam')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

# ─── Upload Config ──────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# ─── Helpers ────────────────────────────────────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_activity(teacher_id, teacher_name, action, details=''):
    """Log teacher activity to MongoDB"""
    try:
        ist_now = datetime.now(timezone(timedelta(hours=5, minutes=30)))
        logs_col.insert_one({
            'teacher_id': teacher_id,
            'teacher_name': teacher_name,
            'action': action,
            'details': details,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': ist_now,
            'date': ist_now.strftime('%Y-%m-%d'),
            'time': ist_now.strftime('%I:%M:%S %p')
        })
    except Exception:
        pass  # never let logging crash the app

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_admin():
    # Update existing admin name if it's currently 'Yogesh' or set it to 'Ravindra kumar'
    admins_col.update_one(
        {'username': 'GVP022026'},
        {'$set': {'name': 'Ravindra kumar'}}
    )
    # Original logic to create if not exists
    if not admins_col.find_one({'username': 'GVP022026'}):
        admins_col.insert_one({
            'username': 'GVP022026',
            'password': hash_password('Yogi@#2025'),
            'name': 'Ravindra kumar'
        })
    else:
        # Update existing admin password as requested
        admins_col.update_one(
            {'username': 'GVP022026'},
            {'$set': {'password': hash_password('Yogi@#7983124911')}}
        )

    # Initialize Principal if not exists
    principals_col.update_one(
        {'username': 'principal'},
        {'$set': {'name': 'Ravindra kumar'}}
    )
    if not principals_col.find_one({'username': 'principal'}):
        principals_col.insert_one({
            'username': 'principal',
            'password': hash_password('Principal@2026'),
            'name': 'Ravindra kumar'
        })

from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            flash('कृपया लॉगिन करें!')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def principal_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('principal') and not session.get('admin'):
            flash('कृपया लॉगिन करें!')
            return redirect(url_for('principal_login'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('teacher_id'):
            flash('कृपया लॉगिन करें!')
            return redirect(url_for('teacher_login'))
        return f(*args, **kwargs)
    return decorated_function

def get_month_summary(year, month):
    """Returns complete month summary: total days, sundays, govt holidays, working days."""
    days_in_month = calendar.monthrange(year, month)[1]
    month_str = f"{year}-{month:02d}"

    # Count Sundays
    sundays = 0
    sunday_days = set()
    for d in range(1, days_in_month + 1):
        if calendar.weekday(year, month, d) == 6:
            sundays += 1
            sunday_days.add(d)

    # Get govt holidays from DB
    govt_holidays = list(holidays_col.find({'date': {'$regex': f'^{month_str}'}}).sort('date', 1))
    holiday_days = set()
    for h in govt_holidays:
        d = int(h['date'].split('-')[2])
        if d not in sunday_days:  # don't double count Sunday holidays
            holiday_days.add(d)

    # Actual working days = Total - Sundays - Govt Holidays (on Mon-Sat)
    actual_working_days = days_in_month - sundays - len(holiday_days)

    return {
        'days_in_month': days_in_month,
        'sundays': sundays,
        'sunday_days': sunday_days,
        'holidays': len(holiday_days),
        'holiday_days': holiday_days,
        'holidays_list': govt_holidays,
        'working_days': actual_working_days
    }

# Keep old function for backward compatibility
def get_working_days(year, month):
    return get_month_summary(year, month)['working_days']


def calculate_paid_days(tid, year, month, summary):
    """
    Attendance-based salary calculation.

    Formula:
      paid_days = Present(P) + Medical(M) + Half(H)×0.5
                  + Sundays within work period
                  + Govt Holidays within work period

    Work period = first paid-attendance day → last paid-attendance day of month.
    (Sundays/Holidays ONLY count if they fall within the days teacher was working.)

    Example: Basic=4500, April(30 days), Present=12, last present=Apr 16
      → Sundays in Apr 1–16 = Apr 5, 12 = 2
      → paid_days = 12 + 2 = 14  →  net = 4500/30 × 14 = ₹2100
    """
    month_str = f"{year}-{month:02d}"

    present  = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': {'$in': ['present', 'P']}})
    half     = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': {'$in': ['half_day', 'H']}})
    medical  = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': 'M'})
    absent   = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': {'$in': ['absent', 'A']}})

    # Find work period: first → last PAID attendance day (P/M/H only, not A)
    paid_records = list(attendance_col.find(
        {'teacher_id': tid,
         'date': {'$regex': f'^{month_str}'},
         'status': {'$in': ['present', 'P', 'M', 'half_day', 'H']}},
        {'date': 1}
    ).sort('date', 1))

    if paid_records:
        first_d = date.fromisoformat(paid_records[0]['date'])
        last_d  = date.fromisoformat(paid_records[-1]['date'])

        # Sundays falling within work period
        sundays_paid = sum(
            1 for i in range((last_d - first_d).days + 1)
            if (first_d + timedelta(days=i)).weekday() == 6   # 6 = Sunday
        )

        # Govt holidays (non-Sunday) falling within work period
        holidays_paid = sum(
            1 for h in summary.get('holidays_list', [])
            if first_d <= date.fromisoformat(h['date']) <= last_d
            and date.fromisoformat(h['date']).weekday() != 6
        )
    else:
        sundays_paid   = 0
        holidays_paid  = 0

    paid_days = present + medical + (half * 0.5) + sundays_paid + holidays_paid

    return {
        'present':       present,
        'half':          half,
        'medical':       medical,
        'absent':        absent,
        'sundays_paid':  sundays_paid,
        'holidays_paid': holidays_paid,
        'paid_days':     round(paid_days, 1),
        'leave_taken':   absent,
    }


@app.after_request
def add_header(response):
    """Prevent back button from showing cached pages after logout"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        admin = admins_col.find_one({'username': username, 'password': password})
        if admin:
            session['admin'] = True
            session['admin_name'] = admin['name']
            return redirect(url_for('admin_dashboard'))
        flash('गलत username या password!')
    return render_template('admin_login.html')

@app.route('/principal/login', methods=['GET', 'POST'])
def principal_login():
    if session.get('principal'):
        return redirect(url_for('principal_dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        principal = principals_col.find_one({'username': username, 'password': password})
        if principal:
            session['principal'] = True
            session['principal_name'] = principal['name']
            return redirect(url_for('principal_dashboard'))
        flash('गलत username या password!')
    return render_template('principal_login.html')

@app.route('/teacher/login', methods=['GET', 'POST'])
def teacher_login():
    if session.get('teacher_id'):
        return redirect(url_for('teacher_dashboard'))
    if request.method == 'POST':
        teacher_id = request.form['teacher_id']
        password = hash_password(request.form['password'])
        teacher = teachers_col.find_one({'teacher_id': teacher_id, 'password': password})
        if teacher:
            session['teacher_id'] = teacher_id
            session['teacher_name'] = teacher['name']
            log_activity(teacher_id, teacher['name'], 'LOGIN', 'Teacher logged in')
            if teacher.get('must_change_password'):
                flash('सुरक्षा के लिए कृपया अपना पासवर्ड बदलें।')
                return redirect(url_for('teacher_change_password'))
            return redirect(url_for('teacher_dashboard'))
        flash('गलत ID या password!')
    return render_template('teacher_login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ─── Admin Routes ────────────────────────────────────────────────────────────

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    total_teachers = teachers_col.count_documents({'active': True})
    today_str = date.today().strftime('%Y-%m-%d')
    today_attendance = attendance_col.count_documents({'date': today_str, 'status': {'$in': ['present', 'P']}})
    teachers = list(teachers_col.find({'active': True}))
    return render_template('admin_dashboard.html', 
                         total=total_teachers,
                         present_today=today_attendance,
                         teachers=teachers,
                         today=today_str,
                         admin_name=session.get('admin_name'))

@app.route('/principal/dashboard')
@principal_required
def principal_dashboard():
    total_teachers = teachers_col.count_documents({'active': True})
    today_str = date.today().strftime('%Y-%m-%d')
    today_attendance = attendance_col.count_documents({'date': today_str, 'status': {'$in': ['present', 'P']}})
    return render_template('principal_dashboard.html', 
                         total=total_teachers,
                         present_today=today_attendance,
                         today=today_str,
                         principal_name=session.get('principal_name'))

@app.route('/admin/teachers')
@admin_required
def manage_teachers():
    teachers = list(teachers_col.find({'active': True}))
    return render_template('manage_teachers.html', teachers=teachers)

@app.route('/admin/teacher/add', methods=['GET', 'POST'])
@admin_required
def add_teacher():
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone'].strip()
        
        # Format: TCH + Mobile Number ke last 4 digits
        if len(phone) >= 4:
            base_id = f"TCH{phone[-4:]}"
        else:
            base_id = f"TCH{phone.zfill(4)}"
            
        teacher_id = base_id
        if teachers_col.find_one({'teacher_id': teacher_id}):
            # Collision handle: Add suffix if needed (though unlikely with last 4 digits)
            count = 1
            while teachers_col.find_one({'teacher_id': f"{base_id}-{count}"}):
                count += 1
            teacher_id = f"{base_id}-{count}"
            
        # Default Password: GVP@2026 (Updated as per request)
        default_password = "GVP@2026"
        
        teacher = {
            'teacher_id': teacher_id,
            'name': name,
            'subject': request.form['subject'],
            'phone': phone,
            'email': request.form.get('email', ''),
            'basic_salary': float(request.form['basic_salary']),
            'password': hash_password(default_password),
            'joining_date': request.form['joining_date'],
            'active': True,
            'created_at': datetime.now(),
            'must_change_password': True,
            # Bank Details
            'bank_name': request.form.get('bank_name', ''),
            'bank_account': request.form.get('bank_account', ''),
            'ifsc': request.form.get('ifsc', '').upper(),
            'holder_name': request.form.get('holder_name', ''),
            'pan_no': request.form.get('pan_no', '').upper()
        }
        teachers_col.insert_one(teacher)
        flash(f'Teacher {teacher["name"]} सफलतापूर्वक जोड़े गए! ID: {teacher_id}')
        return redirect(url_for('manage_teachers'))

    return render_template('add_teacher.html')

# Migration completed. New logic is in add_teacher.

@app.route('/admin/teacher/delete/<teacher_id>')
@admin_required
def delete_teacher(teacher_id):
    teachers_col.update_one({'teacher_id': teacher_id}, {'$set': {'active': False}})
    flash('Teacher हटा दिए गए!')
    return redirect(url_for('manage_teachers'))

@app.route('/admin/teacher/edit/<teacher_id>', methods=['GET', 'POST'])
@admin_required
def edit_teacher(teacher_id):
    teacher = teachers_col.find_one({'teacher_id': teacher_id})
    if not teacher:
        flash('Teacher नहीं मिले!')
        return redirect(url_for('manage_teachers'))

    if request.method == 'POST':
        updates = {
            'name': request.form['name'],
            'subject': request.form['subject'],
            'phone': request.form['phone'].strip(),
            'email': request.form.get('email', ''),
            'basic_salary': float(request.form['basic_salary']),
            'joining_date': request.form['joining_date'],
            # Bank Details
            'bank_name': request.form.get('bank_name', ''),
            'bank_account': request.form.get('bank_account', ''),
            'ifsc': request.form.get('ifsc', '').upper(),
            'holder_name': request.form.get('holder_name', ''),
            'pan_no': request.form.get('pan_no', '').upper()
        }
        teachers_col.update_one({'teacher_id': teacher_id}, {'$set': updates})
        flash(f'✅ {updates["name"]} की जानकारी सफलतापूर्वक अपडेट हो गई!')
        return redirect(url_for('manage_teachers'))

    return render_template('edit_teacher.html', teacher=teacher)

@app.route('/admin/teacher/reset_password/<teacher_id>')
@admin_required
def admin_reset_teacher_password(teacher_id):
    teacher = teachers_col.find_one({'teacher_id': teacher_id})
    if not teacher:
        flash('Teacher नहीं मिले!')
        return redirect(url_for('manage_teachers'))

    default_password = "GVP@2026"
    teachers_col.update_one(
        {'teacher_id': teacher_id},
        {'$set': {
            'password': hash_password(default_password),
            'must_change_password': True
        }}
    )
    flash(f'🔑 {teacher["name"]} का Password Reset हो गया! Default Password: {default_password}')
    return redirect(url_for('manage_teachers'))

@app.route('/admin/attendance', methods=['GET', 'POST'])
@principal_required
def mark_attendance():
    
    selected_date = request.args.get('date', date.today().strftime('%Y-%m-%d'))
    teachers = list(teachers_col.find({'active': True}))
    
    # Get existing attendance for the date
    existing = {}
    for rec in attendance_col.find({'date': selected_date}):
        existing[rec['teacher_id']] = rec['status']
    
    if request.method == 'POST':
        att_date = request.form['att_date']
        for teacher in teachers:
            tid = teacher['teacher_id']
            status = request.form.get(f'status_{tid}', 'absent')
            attendance_col.update_one(
                {'teacher_id': tid, 'date': att_date},
                {'$set': {
                    'teacher_id': tid,
                    'teacher_name': teacher['name'],
                    'date': att_date,
                    'status': status,
                    'marked_by': session.get('admin_name') or session.get('principal_name'),
                    'marked_at': datetime.now()
                }},
                upsert=True
            )
        flash(f'{att_date} की attendance सफलतापूर्वक save हो गई!')
        return redirect(url_for('mark_attendance', date=att_date))

    return render_template('mark_attendance.html',
                         teachers=teachers,
                         selected_date=selected_date,
                         existing=existing)

@app.route('/admin/payroll')
@admin_required
def payroll():
    month = int(request.args.get('month', date.today().month))
    year  = int(request.args.get('year',  date.today().year))

    teachers     = list(teachers_col.find({'active': True}))
    summary      = get_month_summary(year, month)
    working_days = summary['working_days']

    payroll_data  = []
    total_payable = 0

    for teacher in teachers:
        tid = teacher['teacher_id']

        att = calculate_paid_days(tid, year, month, summary)

        days_in_month  = summary['days_in_month']
        per_day_salary = teacher['basic_salary'] / days_in_month if days_in_month > 0 else 0
        net_salary     = round(per_day_salary * att['paid_days'], 2)
        deduction      = round(per_day_salary * (att['absent'] + att['half'] * 0.5), 2)

        total_payable += net_salary

        payroll_data.append({
            'teacher_id':     tid,
            'name':           teacher['name'],
            'subject':        teacher['subject'],
            'basic_salary':   teacher['basic_salary'],
            'days_in_month':  days_in_month,
            'sundays':        att['sundays_paid'],
            'holidays':       att['holidays_paid'],
            'working_days':   working_days,
            'present_days':   att['present'],
            'half_days':      att['half'],
            'medical_leaves': att['medical'],
            'absent_days':    att['absent'],
            'paid_days':      att['paid_days'],
            'per_day':        round(per_day_salary, 2),
            'deduction':      deduction,
            'net_salary':     net_salary,
            'calculation_days': days_in_month
        })

    return render_template('payroll.html',
                         payroll=payroll_data,
                         month=month, year=year,
                         month_name=calendar.month_name[month],
                         working_days=working_days,
                         total_payable=round(total_payable, 2),
                         summary=summary)



@app.route('/admin/attendance/report')
@principal_required
def attendance_report():
    month = int(request.args.get('month', date.today().month))
    year = int(request.args.get('year', date.today().year))
    month_str = f"{year}-{month:02d}"
    
    teachers = list(teachers_col.find({'active': True}))
    days_in_month = calendar.monthrange(year, month)[1]
    
    # Find all Sundays in the month
    sundays = set()
    for d in range(1, days_in_month + 1):
        if calendar.weekday(year, month, d) == 6:  # 6 = Sunday
            sundays.add(d)
    
    report = []
    for teacher in teachers:
        tid = teacher['teacher_id']
        att_map = {}
        for rec in attendance_col.find({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}}):
            day = int(rec['date'].split('-')[2])
            att_map[day] = rec['status']
        report.append({
            'name': teacher['name'],
            'teacher_id': tid,
            'att_map': att_map
        })

    # Submissions info
    submission_logs = list(attendance_col.find({'date': {'$regex': f'^{month_str}'}}).sort('marked_at', -1).limit(30))
    
    return render_template('attendance_report.html',
                         report=report,
                         month=month, year=year,
                         month_name=calendar.month_name[month],
                         days=days_in_month,
                         sundays=sundays,
                         submission_logs=submission_logs)

@app.route('/admin/holidays', methods=['GET', 'POST'])
@admin_required
def manage_holidays():
    if request.method == 'POST':
        hdate = request.form['date']
        hname = request.form['name'].strip()
        if not holidays_col.find_one({'date': hdate}):
            holidays_col.insert_one({
                'date': hdate,
                'name': hname,
                'added_by': session.get('admin_name'),
                'added_at': datetime.now()
            })
            flash(f'✅ {hdate} — "{hname}" छुट्टी add हो गई!')
        else:
            flash('⚠️ यह date पहले से registered है!')
        return redirect(url_for('manage_holidays'))

    year = int(request.args.get('year', date.today().year))
    all_holidays = list(holidays_col.find({'date': {'$regex': f'^{year}'}}).sort('date', 1))
    return render_template('manage_holidays.html', holidays=all_holidays, year=year)

@app.route('/admin/holidays/delete/<holiday_id>')
@admin_required
def delete_holiday(holiday_id):
    holidays_col.delete_one({'_id': ObjectId(holiday_id)})
    flash('छुट्टी हटा दी गई!')
    return redirect(url_for('manage_holidays'))

# ─── Admin Salary Increment ─────────────────────────────────────────────────

@app.route('/admin/salary/increment', methods=['GET', 'POST'])
@admin_required
def salary_increment():
    teachers = list(teachers_col.find({'active': True}))

    if request.method == 'POST':
        teacher_id = request.form['teacher_id']
        increment_type = request.form['increment_type']  # 'fixed' or 'percent'
        increment_value = float(request.form['increment_value'])
        remarks = request.form.get('remarks', '')

        teacher = teachers_col.find_one({'teacher_id': teacher_id})
        if not teacher:
            flash('Teacher नहीं मिले!')
            return redirect(url_for('salary_increment'))

        old_salary = teacher['basic_salary']
        if increment_type == 'percent':
            new_salary = round(old_salary * (1 + increment_value / 100), 2)
        else:
            new_salary = round(old_salary + increment_value, 2)

        teachers_col.update_one({'teacher_id': teacher_id}, {'$set': {'basic_salary': new_salary}})
        increment_col.insert_one({
            'teacher_id': teacher_id,
            'teacher_name': teacher['name'],
            'old_salary': old_salary,
            'new_salary': new_salary,
            'increment_type': increment_type,
            'increment_value': increment_value,
            'remarks': remarks,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'done_by': session.get('admin_name'),
            'year': datetime.now().year
        })
        diff = new_salary - old_salary
        flash(f'✅ {teacher["name"]} की Salary ₹{old_salary:,.0f} → ₹{new_salary:,.0f} (+₹{diff:,.0f})')
        return redirect(url_for('salary_increment'))

    history = list(increment_col.find().sort('date', -1).limit(30))
    return render_template('salary_increment.html', teachers=teachers, history=history)

# ─── Admin Assets / Stationaries Route ───────────────────────────────────────

@app.route('/admin/assets', methods=['GET', 'POST'])
@principal_required
def manage_assets():
    teachers = list(teachers_col.find({'active': True}))
    
    if request.method == 'POST':
        teacher_id = request.form['teacher_id']
        item_name = request.form['item_name'].strip()
        quantity = int(request.form.get('quantity', 1))
        remarks = request.form.get('remarks', '').strip()
        
        teacher = teachers_col.find_one({'teacher_id': teacher_id})
        if teacher:
            ist_now = datetime.now(timezone(timedelta(hours=5, minutes=30)))
            assets_col.insert_one({
                'teacher_id': teacher_id,
                'teacher_name': teacher['name'],
                'item_name': item_name,
                'quantity': quantity,
                'remarks': remarks,
                'assigned_by': session.get('admin_name') or session.get('principal_name'),
                'date': ist_now.strftime('%Y-%m-%d'),
                'timestamp': ist_now
            })
            flash(f'✅ {teacher["name"]} को {quantity}x {item_name} असाइन किया गया!')
        else:
            flash('⚠️ Teacher नहीं मिला!')
        return redirect(url_for('manage_assets'))
        
    all_assets = list(assets_col.find().sort('timestamp', -1))
    return render_template('manage_assets.html', teachers=teachers, assets=all_assets)

@app.route('/admin/assets/delete/<asset_id>')
@principal_required
def delete_asset(asset_id):
    assets_col.delete_one({'_id': ObjectId(asset_id)})
    flash('असाइनमेंट सफलतापूर्वक हटा दिया गया!')
    return redirect(url_for('manage_assets'))

# ─── Teacher Routes ────────────────────────────────────────────────────────────

@app.route('/teacher/dashboard')
@teacher_required
def teacher_dashboard():
    tid = session['teacher_id']
    teacher = teachers_col.find_one({'teacher_id': tid})

    month = date.today().month
    year = date.today().year
    month_str = f"{year}-{month:02d}"

    # Previous Month calculation
    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    prev_summary = get_month_summary(prev_year, prev_month)
    prev_att = calculate_paid_days(tid, prev_year, prev_month, prev_summary)
    prev_days_in_month = prev_summary['days_in_month']
    prev_paid_days = prev_att['paid_days']
    prev_per_day = teacher['basic_salary'] / prev_days_in_month if prev_days_in_month > 0 else 0
    prev_estimated_salary = round(prev_per_day * prev_paid_days, 2)

    summary = get_month_summary(year, month)
    working_days = summary['working_days']

    att = calculate_paid_days(tid, year, month, summary)

    present = att['present']
    half = att['half']
    absent = att['absent']
    medical = att['medical']

    days_in_month = summary['days_in_month']
    paid_days = att['paid_days']
    
    per_day = teacher['basic_salary'] / days_in_month if days_in_month > 0 else 0
    estimated_salary = round(per_day * paid_days, 2)

    recent = list(attendance_col.find({'teacher_id': tid}).sort('date', -1).limit(10))
    assigned_assets = list(assets_col.find({'teacher_id': tid}).sort('timestamp', -1))
    
    log_activity(tid, teacher['name'], 'VISIT_DASHBOARD', 'Visited teacher dashboard')

    return render_template('teacher_dashboard.html',
                         teacher=teacher,
                         present=present, half=half, absent=absent,
                         total_days=summary['days_in_month'],
                         calculation_days=days_in_month,
                         paid_days=paid_days,
                         per_day=per_day,
                         estimated_salary=estimated_salary,
                         month_name=calendar.month_name[month],
                         year=year,
                         prev_month=prev_month,
                         prev_month_name=calendar.month_name[prev_month],
                         prev_year=prev_year,
                         prev_estimated_salary=prev_estimated_salary,
                         prev_paid_days=prev_paid_days,
                         prev_per_day=prev_per_day,
                         recent=recent,
                         assets=assigned_assets)


@app.route('/teacher/salary')
@teacher_required
def teacher_salary():
    tid = session['teacher_id']
    teacher = teachers_col.find_one({'teacher_id': tid})

    month = int(request.args.get('month', date.today().month))
    year = int(request.args.get('year', date.today().year))
    month_str = f"{year}-{month:02d}"

    summary = get_month_summary(year, month)

    # Auto-redirect to previous month if current month has no attendance
    today = date.today()
    month_str = f"{year}-{month:02d}"
    total_any = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}})
    no_att_data = total_any == 0
    is_current_month = (year == today.year and month == today.month)
    if no_att_data and is_current_month and not request.args.get('force'):
        prev_month = month - 1 if month > 1 else 12
        prev_year  = year if month > 1 else year - 1
        return redirect(url_for('teacher_salary', month=prev_month, year=prev_year))

    att  = calculate_paid_days(tid, year, month, summary)
    days_in_month = summary['days_in_month']
    per_day       = teacher['basic_salary'] / days_in_month if days_in_month > 0 else 0
    net_salary    = round(per_day * att['paid_days'], 2)
    deduction     = round(per_day * (att['absent'] + att['half'] * 0.5), 2)

    all_teachers = list(teachers_col.find({'active': True}, {'teacher_id': 1}).sort('_id', 1))
    bill_no = next((i + 1 for i, t in enumerate(all_teachers) if t['teacher_id'] == tid), 1)

    slip_date = today.strftime('%d/%m/%Y')
    log_activity(tid, teacher['name'], 'VISIT_SALARY', f'Viewed salary slip for {calendar.month_name[month]} {year}')

    return render_template('salary_slip.html',
                         teacher=teacher,
                         month=month, year=year,
                         month_name=calendar.month_name[month],
                         summary=summary,
                         total_working_days=att['paid_days'],
                         calculation_days=days_in_month,
                         present=att['present'], half=att['half'],
                         medical=att['medical'], absent=att['absent'],
                         sundays_paid=att['sundays_paid'],
                         holidays_paid=att['holidays_paid'],
                         paid_days=att['paid_days'],
                         leave_taken=att['leave_taken'],
                         per_day=round(per_day, 2),
                         deduction=deduction,
                         net_salary=net_salary,
                         bill_no=f"{bill_no:02d}",
                         slip_date=slip_date,
                         no_att_data=no_att_data,
                         is_admin=False)


@app.route('/admin/salary/slip/<teacher_id>')
@admin_required
def admin_salary_slip(teacher_id):
    teacher = teachers_col.find_one({'teacher_id': teacher_id})
    if not teacher:
        flash('Teacher नहीं मिले!')
        return redirect(url_for('payroll'))

    month = int(request.args.get('month', date.today().month))
    year  = int(request.args.get('year',  date.today().year))
    month_str = f"{year}-{month:02d}"

    summary = get_month_summary(year, month)

    # Auto-redirect to previous month if current month has no attendance
    today = date.today()
    total_any = attendance_col.count_documents({'teacher_id': teacher_id, 'date': {'$regex': f'^{month_str}'}})
    no_att_data = total_any == 0
    is_current_month = (year == today.year and month == today.month)
    if no_att_data and is_current_month and not request.args.get('force'):
        prev_month = month - 1 if month > 1 else 12
        prev_year  = year if month > 1 else year - 1
        return redirect(url_for('admin_salary_slip', teacher_id=teacher_id, month=prev_month, year=prev_year))

    att  = calculate_paid_days(teacher_id, year, month, summary)
    days_in_month = summary['days_in_month']
    per_day       = teacher['basic_salary'] / days_in_month if days_in_month > 0 else 0
    net_salary    = round(per_day * att['paid_days'], 2)
    deduction     = round(per_day * (att['absent'] + att['half'] * 0.5), 2)

    all_teachers = list(teachers_col.find({'active': True}, {'teacher_id': 1}).sort('_id', 1))
    bill_no = next((i + 1 for i, t in enumerate(all_teachers) if t['teacher_id'] == teacher_id), 1)
    slip_date = today.strftime('%d/%m/%Y')

    return render_template('salary_slip.html',
                         teacher=teacher,
                         month=month, year=year,
                         month_name=calendar.month_name[month],
                         summary=summary,
                         total_working_days=att['paid_days'],
                         calculation_days=days_in_month,
                         present=att['present'], half=att['half'],
                         medical=att['medical'], absent=att['absent'],
                         sundays_paid=att['sundays_paid'],
                         holidays_paid=att['holidays_paid'],
                         paid_days=att['paid_days'],
                         leave_taken=att['leave_taken'],
                         per_day=round(per_day, 2),
                         deduction=deduction,
                         net_salary=net_salary,
                         bill_no=f"{bill_no:02d}",
                         slip_date=slip_date,
                         no_att_data=no_att_data,
                         is_admin=True)


@app.route('/teacher/attendance/report')
@teacher_required
def teacher_attendance_report():
    tid = session['teacher_id']
    teacher = teachers_col.find_one({'teacher_id': tid})
    month = int(request.args.get('month', date.today().month))
    year = int(request.args.get('year', date.today().year))
    month_str = f"{year}-{month:02d}"
    days_in_month = calendar.monthrange(year, month)[1]

    att_map = {}
    for rec in attendance_col.find({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}}):
        day = int(rec['date'].split('-')[2])
        att_map[day] = rec['status']

    sundays = set()
    for d in range(1, days_in_month + 1):
        if calendar.weekday(year, month, d) == 6:
            sundays.add(d)

    p = sum(1 for v in att_map.values() if v in ['present', 'P'])
    h = sum(1 for v in att_map.values() if v in ['half_day', 'H'])
    m = sum(1 for v in att_map.values() if v == 'M')
    a = sum(1 for v in att_map.values() if v in ['absent', 'A'])
    log_activity(tid, teacher['name'], 'VISIT_ATTENDANCE', f'Viewed attendance for {calendar.month_name[month]} {year}')

    return render_template('teacher_attendance_report.html',
                         teacher=teacher,
                         att_map=att_map,
                         month=month, year=year,
                         month_name=calendar.month_name[month],
                         days=days_in_month,
                         sundays=sundays,
                         p_count=p, h_count=h, m_count=m, a_count=a)

@app.route('/teacher/profile', methods=['GET', 'POST'])
@teacher_required
def teacher_profile():
    tid = session['teacher_id']
    teacher = teachers_col.find_one({'teacher_id': tid})

    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('कोई फ़ाइल नहीं चुनी!')
            return redirect(url_for('teacher_profile'))
        file = request.files['photo']
        if file.filename == '':
            flash('कोई फ़ाइल नहीं चुनी!')
            return redirect(url_for('teacher_profile'))
        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"teacher_{tid}.{ext}")
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            teachers_col.update_one({'teacher_id': tid}, {'$set': {'photo': filename}})
            log_activity(tid, teacher['name'], 'PHOTO_UPLOAD', 'Uploaded/updated profile photo')
            flash('✅ Profile photo सफलतापूर्वक update हो गई!')
        else:
            flash('❌ सिर्फ JPG, PNG, WEBP files allowed हैं (max 2MB)!')
        return redirect(url_for('teacher_profile'))

    log_activity(tid, teacher['name'], 'VISIT_PROFILE', 'Visited profile page')
    return render_template('teacher_profile.html', teacher=teacher)

@app.route('/teacher/forgot_password', methods=['GET', 'POST'])
def teacher_forgot_password():
    if request.method == 'POST':
        teacher_id = request.form['teacher_id'].upper()
        phone = request.form['phone']
        teacher = teachers_col.find_one({'teacher_id': teacher_id, 'phone': phone})
        
        if teacher:
            if not teacher.get('email'):
                flash('आपका Email रजिस्टर्ड नहीं है! कृपया एडमिन से ईमेल अपडेट करवाएं।')
                return redirect(url_for('teacher_forgot_password'))
                
            # Generate 6-digit OTP
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['reset_teacher_id'] = teacher_id
            
            # Send Email
            try:
                msg = Message("Password Reset OTP - Gayatri Vidyapith",
                            recipients=[teacher['email']])
                msg.body = f"Hello {teacher['name']},\n\nYour OTP for password reset is: {otp}\n\nDo not share this with anyone."
                mail.send(msg)
                flash(f'एक OTP आपकी ईमेल ({teacher["email"]}) पर भेज दिया गया है।')
                return redirect(url_for('teacher_verify_otp'))
            except Exception as e:
                print(f"Mail Error: {e}")
                flash('ईमेल भेजने में गड़बड़ हुई! कृपया बाद में प्रयास करें।')
        else:
            flash('गलत ID या Phone Number!')
    return render_template('teacher_forgot_password.html')

@app.route('/teacher/verify_otp', methods=['GET', 'POST'])
def teacher_verify_otp():
    if not session.get('reset_teacher_id') or not session.get('otp'):
        return redirect(url_for('teacher_forgot_password'))
        
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['otp']:
            flash('OTP सत्यापित (Verified) हुआ! अब अपना नया पासवर्ड सेट करें।')
            return redirect(url_for('teacher_reset_password'))
        flash('गलत OTP! कृपया फिर से चेक करें।')
        
    return render_template('teacher_verify_otp.html')

@app.route('/teacher/reset_password', methods=['GET', 'POST'])
def teacher_reset_password():
    if not session.get('reset_teacher_id'):
        return redirect(url_for('teacher_forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password == confirm_password:
            hashed_pw = hash_password(new_password)
            teachers_col.update_one(
                {'teacher_id': session['reset_teacher_id']},
                {'$set': {'password': hashed_pw}}
            )
            session.pop('reset_teacher_id', None)
            flash('पासवर्ड सफलतापूर्वक बदल दिया गया है! अब आप लॉगिन कर सकते हैं।')
            return redirect(url_for('teacher_login'))
        flash('पासवर्ड मेल नहीं खाते!')
    
    return render_template('teacher_reset_password.html')

@app.route('/admin/teacher/logs')
@admin_required
def teacher_logs():
    filter_id = request.args.get('teacher_id', '')
    filter_action = request.args.get('action', '')
    filter_date = request.args.get('date', '')

    query = {}
    if filter_id:
        query['teacher_id'] = filter_id
    if filter_action:
        query['action'] = filter_action
    if filter_date:
        query['date'] = filter_date

    logs = list(logs_col.find(query).sort('timestamp', -1).limit(200))
    all_teachers = list(teachers_col.find({'active': True}, {'teacher_id': 1, 'name': 1}))

    # Summary stats
    ist_now = datetime.now(timezone(timedelta(hours=5, minutes=30)))
    today_ist = ist_now.strftime('%Y-%m-%d')
    today_logins = logs_col.count_documents({'action': 'LOGIN', 'date': today_ist})
    total_logins = logs_col.count_documents({'action': 'LOGIN'})
    total_visits = logs_col.count_documents({})

    return render_template('teacher_logs.html',
                         logs=logs,
                         all_teachers=all_teachers,
                         filter_id=filter_id,
                         filter_action=filter_action,
                         filter_date=filter_date,
                         today_logins=today_logins,
                         total_logins=total_logins,
                         total_visits=total_visits,
                         today=today_ist)

@app.route('/admin/teacher/logs/clear', methods=['POST'])
@admin_required
def clear_logs():
    ist_now = datetime.now(timezone(timedelta(hours=5, minutes=30)))
    before_date = (ist_now - timedelta(days=2)).strftime('%Y-%m-%d')
    deleted_info = logs_col.delete_many({'date': {'$lt': before_date}})
    if deleted_info.deleted_count > 0:
        flash(f'✅ {before_date} से पहले के {deleted_info.deleted_count} logs सफलतापूर्वक delete हो गए!')
    else:
        flash(f'ℹ️ {before_date} से पहले के कोई logs मौजूद नहीं हैं।')
    return redirect(url_for('teacher_logs'))

@app.route('/admin/attendance/export')
@principal_required
def export_attendance():
    month = int(request.args.get('month', date.today().month))
    year = int(request.args.get('year', date.today().year))
    month_str = f"{year}-{month:02d}"
    
    teachers = list(teachers_col.find({'active': True}))
    days_in_month = calendar.monthrange(year, month)[1]
    
    # Create the report structure
    data = []
    for teacher in teachers:
        tid = teacher['teacher_id']
        att_map = {}
        for rec in attendance_col.find({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}}):
            day = int(rec['date'].split('-')[2])
            att_map[day] = rec['status']
            
        row = {
            "Teacher Name": teacher['name'],
            "ID": tid
        }
        
        counts = {'P': 0, 'H': 0, 'M': 0, 'A': 0}
        for d in range(1, days_in_month + 1):
            s = att_map.get(d, "-")
            if s in ['present', 'P']:
                status = 'P'
                counts['P'] += 1
            elif s in ['half_day', 'H']:
                status = 'H'
                counts['H'] += 1
            elif s in ['absent', 'A']:
                status = 'A'
                counts['A'] += 1
            elif s == 'M':
                status = 'M'
                counts['M'] += 1
            else:
                status = "-"
            row[str(d)] = status
            
        row.update({
            "P (Present)": counts['P'],
            "H (Half Day)": counts['H'],
            "M (Medical)": counts['M'],
            "A (Absent)": counts['A']
        })
        data.append(row)
        
    df = pd.DataFrame(data)
    
    # Send as Excel file
    output = io.BytesIO()
    month_name = calendar.month_name[month]
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # Write metadata headers manually
        df.to_excel(writer, index=False, sheet_name=f'Attendance_{month_str}', startrow=4)
        
        # Access openpyxl objects for styling
        workbook  = writer.book
        worksheet = writer.sheets[f'Attendance_{month_str}']
        
        # Add Custom Headings
        from openpyxl.styles import Font, Alignment, PatternFill
        
        header_font = Font(bold=True, size=16, color="FFFFFF")
        sub_header_font = Font(bold=True, size=12)
        center_align = Alignment(horizontal='center', vertical='center')
        header_fill = PatternFill(start_color="FF8C00", end_color="FF8C00", fill_type="solid") # Saffron
        
        # A1: School Name
        worksheet.merge_cells(f'A1:{chr(ord("A") + days_in_month + 5)}1')
        worksheet['A1'] = "गायत्री विद्यापीठ, दाउदनगर"
        worksheet['A1'].font = header_font
        worksheet['A1'].alignment = center_align
        worksheet['A1'].fill = header_fill
        
        # A2: Report Title
        worksheet.merge_cells(f'A2:{chr(ord("A") + days_in_month + 5)}2')
        worksheet['A2'] = f"Attendance Report — {month_name} {year}"
        worksheet['A2'].font = sub_header_font
        worksheet['A2'].alignment = center_align
        
        # A3: Export Date
        worksheet.merge_cells(f'A3:{chr(ord("A") + days_in_month + 5)}3')
        worksheet['A3'] = f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        worksheet['A3'].alignment = center_align
        
        # Auto-adjust column widths
        for col in worksheet.columns:
            max_length = 0
            column = col[4].column_letter # Get the column letter (headers are in row 5, index 4)
            for cell in col:
                if cell.value:
                    max_length = max(max_length, len(str(cell.value)))
            worksheet.column_dimensions[column].width = max_length + 2

    output.seek(0)
    filename = f"Attendance_Report_{month_name}_{year}.xlsx"
    
    return send_file(output, 
                     download_name=filename, 
                     as_attachment=True, 
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/teacher/change_password', methods=['GET', 'POST'])
@teacher_required
def teacher_change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        teacher = teachers_col.find_one({'teacher_id': session['teacher_id'], 'password': hash_password(old_password)})
        
        if not teacher:
            flash('पुराना पासवर्ड गलत है!')
        elif new_password != confirm_password:
            flash('नया पासवर्ड मेल नहीं खाता!')
        else:
            teachers_col.update_one(
                {'teacher_id': session['teacher_id']},
                {'$set': {'password': hash_password(new_password), 'must_change_password': False}}
            )
            flash('पासवर्ड सफलतापूर्वक बदल दिया गया है!')
            return redirect(url_for('teacher_dashboard'))
            
    return render_template('teacher_change_password.html')

if __name__ == '__main__':
    init_admin()
    app.run(debug=True, port=5000)
