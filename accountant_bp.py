"""
Accountant Module — Student Fee Management (SECURED)
Blueprint-based architecture for clean separation from existing payroll/attendance modules.
All inputs are validated and sanitized. Passwords use bcrypt. Deletes use POST.
"""

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, flash, jsonify, current_app
)
from functools import wraps
from datetime import datetime, timezone, timedelta
from bson.objectid import ObjectId
import re

from security import (
    PasswordManager, SecurityValidator, safe_str, sanitize_mongo_query
)

# ─── Blueprint Setup ────────────────────────────────────────────────────────
accountant_bp = Blueprint('accountant', __name__, template_folder='templates')

# ─── Database reference (set by init_accountant) ────────────────────────────
_db = None
accountants_col = None
students_col = None
fee_history_col = None


def init_accountant(db):
    """
    Initialize accountant module with shared database connection.
    Called from app.py after MongoDB is connected.
    """
    global _db, accountants_col, students_col, fee_history_col
    _db = db
    accountants_col = db['accountants']
    students_col = db['students']
    fee_history_col = db['fee_history']

    # Create default accountant if not exists
    _create_default_accountant()


def _create_default_accountant():
    """Create default accountant with bcrypt-hashed password if not exists."""
    if accountants_col is None:
        return
    try:
        import os
        username = os.environ.get('ACCOUNTANT_USERNAME', 'accountant')
        password = os.environ.get('ACCOUNTANT_DEFAULT_PASSWORD', 'Accountant@2026')

        if not accountants_col.find_one({'username': username}):
            accountants_col.insert_one({
                'username': username,
                'password': PasswordManager.hash_password(password),
                'name': 'Accountant',
                'created_at': datetime.now(timezone.utc),
                'must_change_password': True
            })
    except Exception:
        pass


def accountant_required(f):
    """Decorator: only accountant session can access these routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('accountant'):
            flash('कृपया Accountant Login करें!')
            return redirect(url_for('accountant.accountant_login'))
        return f(*args, **kwargs)
    return decorated_function


def get_ist_now():
    """Get current IST datetime."""
    return datetime.now(timezone(timedelta(hours=5, minutes=30)))


# ─── Auth Routes ────────────────────────────────────────────────────────────

@accountant_bp.route('/accountant/login', methods=['GET', 'POST'])
def accountant_login():
    if session.get('accountant'):
        return redirect(url_for('accountant.accountant_dashboard'))

    if request.method == 'POST':
        username = safe_str(request.form.get('username', ''), 50).strip()
        password = safe_str(request.form.get('password', ''), 128)

        if not username or not password:
            flash('कृपया username और password दोनों दर्ज करें!')
            return render_template('accountant/accountant_login.html')

        # Prevent NoSQL injection: ensure username is a plain string
        acct = accountants_col.find_one({'username': username})

        if acct and PasswordManager.verify_password(password, acct.get('password', '')):
            # Migrate to bcrypt if still on SHA-256
            if PasswordManager.needs_rehash(acct.get('password', '')):
                accountants_col.update_one(
                    {'_id': acct['_id']},
                    {'$set': {'password': PasswordManager.hash_password(password)}}
                )

            # Regenerate session to prevent fixation
            session.clear()
            session['accountant'] = True
            session['accountant_name'] = acct.get('name', 'Accountant')
            session.permanent = True
            return redirect(url_for('accountant.accountant_dashboard'))

        # Generic error — don't reveal which field was wrong
        flash('गलत username या password!')

    return render_template('accountant/accountant_login.html')


@accountant_bp.route('/accountant/logout')
def accountant_logout():
    session.clear()
    return redirect(url_for('index'))


# ─── Dashboard ──────────────────────────────────────────────────────────────

@accountant_bp.route('/accountant/dashboard')
@accountant_required
def accountant_dashboard():
    # Aggregate stats
    pipeline_totals = list(students_col.aggregate([
        {'$group': {
            '_id': None,
            'total_students': {'$sum': 1},
            'total_fee': {'$sum': '$total_fee'},
            'total_paid': {'$sum': '$paid_fee'},
            'total_balance': {'$sum': '$balance_fee'}
        }}
    ]))

    stats = pipeline_totals[0] if pipeline_totals else {
        'total_students': 0, 'total_fee': 0, 'total_paid': 0, 'total_balance': 0
    }

    # Active vs Inactive count
    active_count = students_col.count_documents({'status': {'$ne': 'Inactive'}})
    inactive_count = students_col.count_documents({'status': 'Inactive'})

    # Class-wise summary
    class_summary = list(students_col.aggregate([
        {'$group': {
            '_id': '$class',
            'count': {'$sum': 1},
            'total_fee': {'$sum': '$total_fee'},
            'total_paid': {'$sum': '$paid_fee'},
            'total_balance': {'$sum': '$balance_fee'}
        }},
        {'$sort': {'_id': 1}}
    ]))

    # Recent payments (last 10)
    recent_payments = list(fee_history_col.find().sort('date', -1).limit(10))

    return render_template('accountant/accountant_dashboard.html',
                         stats=stats,
                         active_count=active_count,
                         inactive_count=inactive_count,
                         class_summary=class_summary,
                         recent_payments=recent_payments,
                         accountant_name=session.get('accountant_name'))


# ─── Student Management ────────────────────────────────────────────────────

@accountant_bp.route('/accountant/students')
@accountant_required
def accountant_manage_students():
    filter_class = safe_str(request.args.get('class', '')).strip()
    filter_section = safe_str(request.args.get('section', '')).strip()
    filter_search = safe_str(request.args.get('search', '')).strip()
    filter_fee_status = safe_str(request.args.get('fee_status', '')).strip()

    query = {}

    if filter_class:
        query['class'] = filter_class
    if filter_section:
        query['section'] = filter_section
    if filter_search:
        # Escape regex to prevent NoSQL injection / ReDoS
        escaped = SecurityValidator.sanitize_search(filter_search)
        query['$or'] = [
            {'name': {'$regex': escaped, '$options': 'i'}},
            {'roll_no': {'$regex': escaped, '$options': 'i'}},
            {'admission_no': {'$regex': escaped, '$options': 'i'}}
        ]

    students = list(students_col.find(query).sort(
        [('class', 1), ('section', 1), ('roll_no', 1)]
    ))

    # Apply fee status filter in-memory
    if filter_fee_status == 'fully_paid':
        students = [s for s in students if s.get('balance_fee', 0) <= 0]
    elif filter_fee_status == 'pending':
        students = [s for s in students
                    if s.get('paid_fee', 0) == 0 and s.get('total_fee', 0) > 0]
    elif filter_fee_status == 'partial':
        students = [s for s in students
                    if s.get('paid_fee', 0) > 0 and s.get('balance_fee', 0) > 0]

    all_classes = sorted([c for c in students_col.distinct('class') if c])
    all_sections = sorted([s for s in students_col.distinct('section') if s])

    return render_template('accountant/accountant_manage_students.html',
                         students=students,
                         all_classes=all_classes,
                         all_sections=all_sections,
                         filter_class=filter_class,
                         filter_section=filter_section,
                         filter_search=filter_search,
                         filter_fee_status=filter_fee_status)


@accountant_bp.route('/accountant/student/add', methods=['GET', 'POST'])
@accountant_required
def accountant_add_student():
    if request.method == 'POST':
        # Validate and sanitize all inputs
        name = SecurityValidator.sanitize_string(request.form.get('name', ''), 100)
        admission_no = SecurityValidator.sanitize_string(
            request.form.get('admission_no', ''), 20
        )
        roll_no = SecurityValidator.sanitize_string(request.form.get('roll_no', ''), 20)
        student_class = SecurityValidator.sanitize_string(
            request.form.get('class', ''), 20
        )
        section = SecurityValidator.sanitize_string(
            request.form.get('section', ''), 10
        )
        father_name = SecurityValidator.sanitize_string(
            request.form.get('father_name', ''), 100
        )
        mother_name = SecurityValidator.sanitize_string(
            request.form.get('mother_name', ''), 100
        )
        mobile = SecurityValidator.sanitize_string(
            request.form.get('mobile', ''), 15
        )
        address = SecurityValidator.sanitize_string(
            request.form.get('address', ''), 500
        )
        status = request.form.get('status', 'Active')

        # Validate required fields
        if not name or not roll_no or not student_class:
            flash('⚠️ नाम, रोल नंबर और कक्षा अनिवार्य हैं!')
            return redirect(url_for('accountant.accountant_add_student'))

        # Validate fee amount
        valid, result = SecurityValidator.validate_amount(
            request.form.get('total_fee', 0)
        )
        if not valid:
            flash(f'⚠️ {result}')
            return redirect(url_for('accountant.accountant_add_student'))
        total_fee = result

        # Validate status
        if status not in ('Active', 'Inactive'):
            status = 'Active'

        student = {
            'name': name,
            'admission_no': admission_no,
            'roll_no': roll_no,
            'class': student_class,
            'section': section,
            'father_name': father_name,
            'mother_name': mother_name,
            'mobile': mobile,
            'address': address,
            'total_fee': total_fee,
            'paid_fee': 0,
            'balance_fee': total_fee,
            'status': status,
            'added_at': get_ist_now(),
            'added_by': session.get('accountant_name', 'Accountant')
        }
        students_col.insert_one(student)
        flash(f'✅ Student {name} सफलतापूर्वक जोड़ा गया!')
        return redirect(url_for('accountant.accountant_manage_students'))

    return render_template('accountant/accountant_add_student.html')


@accountant_bp.route('/accountant/student/edit/<student_id>', methods=['GET', 'POST'])
@accountant_required
def accountant_edit_student(student_id):
    # Validate ObjectId
    valid, err = SecurityValidator.validate_object_id(student_id)
    if not valid:
        flash('Invalid student ID!')
        return redirect(url_for('accountant.accountant_manage_students'))

    student = students_col.find_one({'_id': ObjectId(student_id)})
    if not student:
        flash('Student नहीं मिला!')
        return redirect(url_for('accountant.accountant_manage_students'))

    if request.method == 'POST':
        # Validate fee
        valid, result = SecurityValidator.validate_amount(
            request.form.get('total_fee', 0)
        )
        if not valid:
            flash(f'⚠️ {result}')
            return redirect(url_for(
                'accountant.accountant_edit_student', student_id=student_id
            ))
        total_fee = result
        paid_fee = student.get('paid_fee', 0)
        balance_fee = total_fee - paid_fee

        status = request.form.get('status', 'Active')
        if status not in ('Active', 'Inactive'):
            status = 'Active'

        updates = {
            'name': SecurityValidator.sanitize_string(
                request.form.get('name', ''), 100
            ),
            'admission_no': SecurityValidator.sanitize_string(
                request.form.get('admission_no', ''), 20
            ),
            'roll_no': SecurityValidator.sanitize_string(
                request.form.get('roll_no', ''), 20
            ),
            'class': SecurityValidator.sanitize_string(
                request.form.get('class', ''), 20
            ),
            'section': SecurityValidator.sanitize_string(
                request.form.get('section', ''), 10
            ),
            'father_name': SecurityValidator.sanitize_string(
                request.form.get('father_name', ''), 100
            ),
            'mother_name': SecurityValidator.sanitize_string(
                request.form.get('mother_name', ''), 100
            ),
            'mobile': SecurityValidator.sanitize_string(
                request.form.get('mobile', ''), 15
            ),
            'address': SecurityValidator.sanitize_string(
                request.form.get('address', ''), 500
            ),
            'total_fee': total_fee,
            'balance_fee': balance_fee,
            'status': status
        }
        students_col.update_one({'_id': ObjectId(student_id)}, {'$set': updates})
        flash(f'✅ {updates["name"]} की जानकारी अपडेट हो गई!')
        return redirect(url_for('accountant.accountant_manage_students'))

    return render_template('accountant/accountant_edit_student.html', student=student)


@accountant_bp.route('/accountant/student/delete/<student_id>', methods=['POST'])
@accountant_required
def accountant_delete_student(student_id):
    """Delete student — POST only (CSRF-protected)."""
    valid, err = SecurityValidator.validate_object_id(student_id)
    if not valid:
        flash('Invalid student ID!')
        return redirect(url_for('accountant.accountant_manage_students'))

    student = students_col.find_one({'_id': ObjectId(student_id)})
    if student:
        students_col.delete_one({'_id': ObjectId(student_id)})
        fee_history_col.delete_many({'student_id': str(student_id)})
        flash(f'🗑️ {student["name"]} और उनकी फीस हिस्ट्री हटा दी गई!')
    else:
        flash('Student नहीं मिला!')
    return redirect(url_for('accountant.accountant_manage_students'))


# ─── Fee Payment ────────────────────────────────────────────────────────────

@accountant_bp.route('/accountant/student/pay/<student_id>', methods=['GET', 'POST'])
@accountant_required
def accountant_pay_fee(student_id):
    valid, err = SecurityValidator.validate_object_id(student_id)
    if not valid:
        flash('Invalid student ID!')
        return redirect(url_for('accountant.accountant_manage_students'))

    student = students_col.find_one({'_id': ObjectId(student_id)})
    if not student:
        flash('Student नहीं मिला!')
        return redirect(url_for('accountant.accountant_manage_students'))

    if request.method == 'POST':
        # Validate all fee breakdown fields
        fee_fields = [
            ('reg_fee', 'Registration Fee'),
            ('form_charge', 'Form Charge'),
            ('prev_dues', 'Previous Dues'),
            ('tuition_fee', 'Tuition Fee'),
            ('computer_fee', 'Computer Fee'),
            ('admission_fee', 'Admission'),
            ('term_fee', 'Term Fee'),
            ('library_fee', 'Library Fee'),
            ('electric_charge', 'Electric Charge'),
            ('development_charge', 'Development Charge'),
            ('security_money', 'Security Money'),
            ('transport_fee', 'Conveyance/Transportation Fee'),
            ('exam_fee', 'Exam. Fee'),
            ('hostel_charge', 'Hostel Charge'),
            ('late_fine', 'Late Fine'),
            ('others_fee', 'Others'),
        ]

        breakdown = {}
        for field_name, label in fee_fields:
            raw = request.form.get(field_name, 0) or 0
            try:
                val = float(raw)
                if val < 0:
                    flash(f'⚠️ {label} ऋणात्मक नहीं हो सकती!')
                    return redirect(url_for(
                        'accountant.accountant_pay_fee', student_id=student_id
                    ))
                breakdown[label] = val
            except (ValueError, TypeError):
                breakdown[label] = 0.0

        amount = sum(breakdown.values())
        month = SecurityValidator.sanitize_string(
            request.form.get('month', ''), 50
        )
        payment_mode = SecurityValidator.sanitize_string(
            request.form.get('payment_mode', 'Cash'), 20
        )
        remarks = SecurityValidator.sanitize_string(
            request.form.get('remarks', ''), 500
        )

        # Validate amount
        if amount <= 0:
            flash('⚠️ कुल राशि 0 से अधिक होनी चाहिए!')
            return redirect(url_for(
                'accountant.accountant_pay_fee', student_id=student_id
            ))

        new_paid = student.get('paid_fee', 0) + amount
        new_balance = student.get('total_fee', 0) - new_paid

        # Update student record
        students_col.update_one(
            {'_id': ObjectId(student_id)},
            {'$set': {'paid_fee': new_paid, 'balance_fee': new_balance}}
        )

        # Generate unique receipt number
        ist_now = get_ist_now()
        receipt_no = f"GVP-FEE-{ist_now.strftime('%Y%m%d%H%M%S')}-{str(student_id)[-4:]}"

        # Save fee history
        fee_history_col.insert_one({
            'student_id': str(student_id),
            'student_name': student['name'],
            'class': student.get('class', ''),
            'section': student.get('section', ''),
            'roll_no': student.get('roll_no', ''),
            'admission_no': student.get('admission_no', ''),
            'amount': amount,
            'breakdown': breakdown,
            'month': month,
            'payment_mode': payment_mode,
            'remarks': remarks,
            'receipt_no': receipt_no,
            'date': ist_now.strftime('%Y-%m-%d %H:%M:%S'),
            'collected_by': session.get('accountant_name', 'Accountant'),
            'total_fee': student.get('total_fee', 0),
            'total_paid_after': new_paid,
            'balance_after': new_balance
        })

        flash(f'✅ ₹{amount:,.0f} की फीस {student["name"]} के लिए जमा कर दी गई!')
        return redirect(url_for(
            'accountant.accountant_fee_receipt', receipt_no=receipt_no
        ))

    return render_template('accountant/accountant_pay_fee.html', student=student)


# ─── Fee Receipt ────────────────────────────────────────────────────────────

@accountant_bp.route('/accountant/student/receipt/<receipt_no>')
@accountant_required
def accountant_fee_receipt(receipt_no):
    # Sanitize receipt number
    receipt_no = SecurityValidator.sanitize_string(receipt_no, 50)
    receipt = fee_history_col.find_one({'receipt_no': receipt_no})
    if not receipt:
        flash('Receipt नहीं मिली!')
        return redirect(url_for('accountant.accountant_manage_students'))

    # Validate student_id before query
    valid, _ = SecurityValidator.validate_object_id(receipt.get('student_id', ''))
    student = None
    if valid:
        student = students_col.find_one({'_id': ObjectId(receipt['student_id'])})

    return render_template(
        'accountant/accountant_fee_receipt.html',
        receipt=receipt, student=student
    )


# ─── Fee History ────────────────────────────────────────────────────────────

@accountant_bp.route('/accountant/student/fee-history/<student_id>')
@accountant_required
def accountant_fee_history(student_id):
    valid, err = SecurityValidator.validate_object_id(student_id)
    if not valid:
        flash('Invalid student ID!')
        return redirect(url_for('accountant.accountant_manage_students'))

    student = students_col.find_one({'_id': ObjectId(student_id)})
    if not student:
        flash('Student नहीं मिला!')
        return redirect(url_for('accountant.accountant_manage_students'))

    history = list(
        fee_history_col.find({'student_id': str(student_id)}).sort('date', -1)
    )
    return render_template(
        'accountant/accountant_fee_history.html',
        student=student, history=history
    )
