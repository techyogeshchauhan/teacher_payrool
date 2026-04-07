from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from flask_mail import Mail, Message
from datetime import date, datetime
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
# Flask-Mail Configuration (Use environment variables or hardcode for now)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'yc993205@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'kgahkdejlanmoiam')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

# ─── Helpers ────────────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_admin():
    if not admins_col.find_one({'username': 'GVP022026'}):
        admins_col.insert_one({
            'username': 'GVP022026',
            'password': hash_password('Yogi@#2025'),
            'name': 'Yogesh'
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

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('teacher_id'):
            flash('कृपया लॉगिन करें!')
            return redirect(url_for('teacher_login'))
        return f(*args, **kwargs)
    return decorated_function

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
            'must_change_password': True
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

@app.route('/admin/attendance', methods=['GET', 'POST'])
@admin_required
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
@admin_required
def payroll():
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
            'status': {'$in': ['present', 'P']}
        })
        half_day_count = attendance_col.count_documents({
            'teacher_id': tid,
            'date': {'$regex': f'^{month_str}'},
            'status': {'$in': ['half_day', 'H']}
        })
        medical_leave_count = attendance_col.count_documents({
            'teacher_id': tid,
            'date': {'$regex': f'^{month_str}'},
            'status': 'M'
        })
        
        # Logic: Medical Leave is counted as Present for salary (usually) or as per school rules.
        # Let's count P and M as full days.
        effective_days = (present_count + medical_leave_count) + (half_day_count * 0.5)
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
            'medical_leaves': medical_leave_count,
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
@admin_required
def attendance_report():
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
@teacher_required
def teacher_dashboard():
    tid = session['teacher_id']
    teacher = teachers_col.find_one({'teacher_id': tid})
    
    month = date.today().month
    year = date.today().year
    month_str = f"{year}-{month:02d}"
    
    present = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': {'$in': ['present', 'P']}})
    half = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': {'$in': ['half_day', 'H']}})
    absent = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': {'$in': ['absent', 'A']}})
    medical = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': 'M'})
    
    working_days = get_working_days(year, month)
    effective = (present + medical) + (half * 0.5)
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
@teacher_required
def teacher_salary():
    tid = session['teacher_id']
    teacher = teachers_col.find_one({'teacher_id': tid})
    
    month = int(request.args.get('month', date.today().month))
    year = int(request.args.get('year', date.today().year))
    month_str = f"{year}-{month:02d}"
    working_days = get_working_days(year, month)
    
    present = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': {'$in': ['present', 'P']}})
    half = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': {'$in': ['half_day', 'H']}})
    medical = attendance_col.count_documents({'teacher_id': tid, 'date': {'$regex': f'^{month_str}'}, 'status': 'M'})
    effective = (present + medical) + (half * 0.5)
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

@app.route('/admin/attendance/export')
@admin_required
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
