from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from pymongo import MongoClient
from datetime import datetime, date
import hashlib
import calendar
from bson.objectid import ObjectId
import os

app = Flask(__name__)
app.secret_key = 'gayatri_vidyapith_secret_2024'

# MongoDB Connection
mongo_uri = os.environ.get('MONGO_URI', 'mongodb+srv://GVP:QeMjUCPTfgZJVHVO@gvp.sbsdal5.mongodb.net/?appName=GVP')
client = MongoClient(mongo_uri)
db = client['gayatri_school']

teachers_col = db['teachers']
attendance_col = db['attendance']
admins_col = db['admins']

# ─── Helpers ────────────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_admin():
    if not admins_col.find_one({'username': 'admin'}):
        admins_col.insert_one({
            'username': 'admin',
            'password': hash_password('admin123'),
            'name': 'Yogesh'
        })

def get_working_days(year, month):
    """Count working days (Mon-Sat) in a month"""
    cal = calendar.monthcalendar(year, month)
    working = 0
    for week in cal:
        for i, day in enumerate(week):
            if day != 0 and i != 6:  # exclude Sunday
                working += 1
    return working

# ─── Auth Routes ────────────────────────────────────────────────────────────

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

@app.route('/teacher/login', methods=['GET', 'POST'])
def teacher_login():
    if request.method == 'POST':
        teacher_id = request.form['teacher_id']
        password = hash_password(request.form['password'])
        teacher = teachers_col.find_one({'teacher_id': teacher_id, 'password': password})
        if teacher:
            session['teacher_id'] = teacher_id
            session['teacher_name'] = teacher['name']
            return redirect(url_for('teacher_dashboard'))
        flash('गलत ID या password!')
    return render_template('teacher_login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ─── Admin Routes ────────────────────────────────────────────────────────────

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    total_teachers = teachers_col.count_documents({'active': True})
    today_str = date.today().strftime('%Y-%m-%d')
    today_attendance = attendance_col.count_documents({'date': today_str, 'status': 'present'})
    teachers = list(teachers_col.find({'active': True}))
    return render_template('admin_dashboard.html', 
                         total=total_teachers,
                         present_today=today_attendance,
                         teachers=teachers,
                         today=today_str,
                         admin_name=session.get('admin_name'))

@app.route('/admin/teachers')
def manage_teachers():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    teachers = list(teachers_col.find({'active': True}))
    return render_template('manage_teachers.html', teachers=teachers)

@app.route('/admin/teacher/add', methods=['GET', 'POST'])
def add_teacher():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    if request.method == 'POST':
        teacher_id = request.form['teacher_id'].upper()
        if teachers_col.find_one({'teacher_id': teacher_id}):
            flash('यह Teacher ID पहले से मौजूद है!')
            return redirect(url_for('add_teacher'))
        teacher = {
            'teacher_id': teacher_id,
            'name': request.form['name'],
            'subject': request.form['subject'],
            'phone': request.form['phone'],
            'email': request.form.get('email', ''),
            'basic_salary': float(request.form['basic_salary']),
            'password': hash_password(request.form['password']),
            'joining_date': request.form['joining_date'],
            'active': True,
            'created_at': datetime.now()
        }
        teachers_col.insert_one(teacher)
        flash(f'Teacher {teacher["name"]} सफलतापूर्वक जोड़े गए!')
        return redirect(url_for('manage_teachers'))
    # Auto-generate next teacher ID
    last_teacher = teachers_col.find_one({}, sort=[('teacher_id', -1)])
    if last_teacher and last_teacher.get('teacher_id', '').startswith('TCH'):
        try:
            last_num = int(last_teacher['teacher_id'][3:])
            next_teacher_id = f"TCH{(last_num + 1):03d}"
        except ValueError:
            next_teacher_id = f"TCH{(teachers_col.count_documents({}) + 1):03d}"
    else:
        next_teacher_id = f"TCH{(teachers_col.count_documents({}) + 1):03d}"

    return render_template('add_teacher.html', next_teacher_id=next_teacher_id)

@app.route('/admin/teacher/delete/<teacher_id>')
def delete_teacher(teacher_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    teachers_col.update_one({'teacher_id': teacher_id}, {'$set': {'active': False}})
    flash('Teacher हटा दिए गए!')
    return redirect(url_for('manage_teachers'))

@app.route('/admin/attendance', methods=['GET', 'POST'])
def mark_attendance():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
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
                    'marked_by': session.get('admin_name'),
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
def payroll():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    month = int(request.args.get('month', date.today().month))
    year = int(request.args.get('year', date.today().year))
    
    teachers = list(teachers_col.find({'active': True}))
    working_days = get_working_days(year, month)
    
    payroll_data = []
    total_payable = 0
    
    for teacher in teachers:
        tid = teacher['teacher_id']
        month_str = f"{year}-{month:02d}"
        
        present_count = attendance_col.count_documents({
            'teacher_id': tid,
            'date': {'$regex': f'^{month_str}'},
            'status': 'present'
        })
        half_day_count = attendance_col.count_documents({
            'teacher_id': tid,
            'date': {'$regex': f'^{month_str}'},
            'status': 'half_day'
        })
        
        effective_days = present_count + (half_day_count * 0.5)
        per_day_salary = teacher['basic_salary'] / working_days if working_days > 0 else 0
        net_salary = round(per_day_salary * effective_days, 2)
        deduction = round(teacher['basic_salary'] - net_salary, 2)
        
        total_payable += net_salary
        
        payroll_data.append({
            'teacher_id': tid,
            'name': teacher['name'],
            'subject': teacher['subject'],
            'basic_salary': teacher['basic_salary'],
            'working_days': working_days,
            'present_days': present_count,
            'half_days': half_day_count,
            'effective_days': effective_days,
            'per_day': round(per_day_salary, 2),
            'deduction': deduction,
            'net_salary': net_salary
        })
    
    month_name = calendar.month_name[month]
    return render_template('payroll.html', 
                         payroll=payroll_data,
                         month=month, year=year,
                         month_name=month_name,
                         working_days=working_days,
                         total_payable=round(total_payable, 2))

@app.route('/admin/attendance/report')
def attendance_report():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    month = int(request.args.get('month', date.today().month))
    year = int(request.args.get('year', date.today().year))
    month_str = f"{year}-{month:02d}"
    
    teachers = list(teachers_col.find({'active': True}))
    days_in_month = calendar.monthrange(year, month)[1]
    
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
    
    return render_template('attendance_report.html',
                         report=report,
                         month=month, year=year,
                         month_name=calendar.month_name[month],
                         days=days_in_month)

# ─── Teacher Routes ────────────────────────────────────────────────────────────

@app.route('/teacher/dashboard')
def teacher_dashboard():
    if not session.get('teacher_id'):
        return redirect(url_for('teacher_login'))
    
    tid = session['teacher_id']
    teacher = teachers_col.find_one({'teacher_id': tid})
    
    month = date.today().month
    year = date.today().year
    month_str = f"{year}-{month:02d}"
    
    present = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': 'present'})
    half = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': 'half_day'})
    absent = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': 'absent'})
    
    working_days = get_working_days(year, month)
    effective = present + (half * 0.5)
    per_day = teacher['basic_salary'] / working_days if working_days > 0 else 0
    estimated_salary = round(per_day * effective, 2)
    
    # Recent attendance
    recent = list(attendance_col.find({'teacher_id': tid}).sort('date', -1).limit(10))
    
    return render_template('teacher_dashboard.html',
                         teacher=teacher,
                         present=present, half=half, absent=absent,
                         working_days=working_days,
                         estimated_salary=estimated_salary,
                         month_name=calendar.month_name[month],
                         year=year,
                         recent=recent)

@app.route('/teacher/salary')
def teacher_salary():
    if not session.get('teacher_id'):
        return redirect(url_for('teacher_login'))
    tid = session['teacher_id']
    teacher = teachers_col.find_one({'teacher_id': tid})
    
    month = int(request.args.get('month', date.today().month))
    year = int(request.args.get('year', date.today().year))
    month_str = f"{year}-{month:02d}"
    working_days = get_working_days(year, month)
    
    present = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': 'present'})
    half = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': 'half_day'})
    effective = present + (half * 0.5)
    per_day = teacher['basic_salary'] / working_days if working_days > 0 else 0
    net_salary = round(per_day * effective, 2)
    deduction = round(teacher['basic_salary'] - net_salary, 2)
    
    return render_template('teacher_salary.html',
                         teacher=teacher,
                         month=month, year=year,
                         month_name=calendar.month_name[month],
                         working_days=working_days,
                         present=present, half=half,
                         effective=effective,
                         per_day=round(per_day, 2),
                         deduction=deduction,
                         net_salary=net_salary)

@app.route('/teacher/forgot_password', methods=['GET', 'POST'])
def teacher_forgot_password():
    if request.method == 'POST':
        teacher_id = request.form['teacher_id'].upper()
        phone = request.form['phone']
        teacher = teachers_col.find_one({'teacher_id': teacher_id, 'phone': phone})
        if teacher:
            session['reset_teacher_id'] = teacher_id
            flash('विवरण सही है। कृपया अपना नया पासवर्ड दर्ज करें।')
            return redirect(url_for('teacher_reset_password'))
        flash('गलत ID या Phone Number!')
    return render_template('teacher_forgot_password.html')

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

@app.route('/teacher/change_password', methods=['GET', 'POST'])
def teacher_change_password():
    if not session.get('teacher_id'):
        return redirect(url_for('teacher_login'))
    
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
                {'$set': {'password': hash_password(new_password)}}
            )
            flash('पासवर्ड सफलतापूर्वक बदल दिया गया है!')
            return redirect(url_for('teacher_dashboard'))
            
    return render_template('teacher_change_password.html')

if __name__ == '__main__':
    init_admin()
    app.run(debug=True, port=5000)
