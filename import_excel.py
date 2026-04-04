import pandas as pd
import hashlib
from pymongo import MongoClient
from datetime import datetime

client = MongoClient('mongodb://localhost:27017/')
db = client['gayatri_school']
teachers_col = db['teachers']

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

file_path = "Teacher Bank Details and Verification Form (Responses).xlsx"
df = pd.read_excel(file_path)

# Fill na values
df = df.fillna('')

for index, row in df.iterrows():
    name = str(row['Full Name of Teacher']).strip()
    if not name:
        continue
        
    salary_str = str(row.get('total sallray ', '0')).replace(',', '')
    try:
        basic_salary = float(salary_str)
    except:
        basic_salary = 0.0

    mobile = str(row.get('Mobile Number', '')).split('.')[0] # removing floating point .0
    email = str(row.get('Email Address', '')).strip()

    # Generate teacher_id
    last_teacher = teachers_col.find_one({}, sort=[('teacher_id', -1)])
    if last_teacher and last_teacher.get('teacher_id', '').startswith('TCH'):
        try:
            last_num = int(last_teacher['teacher_id'][3:])
            next_teacher_id = f"TCH{(last_num + 1):03d}"
        except ValueError:
            next_teacher_id = f"TCH{(teachers_col.count_documents({}) + 1):03d}"
    else:
        next_teacher_id = f"TCH{(teachers_col.count_documents({}) + 1):03d}"
        
    password = "123"
    
    pan = str(row.get('Personal PAN (Permanent Account Number)', '')).strip()
    bank_acc = str(row.get('Bank Account Number', '')).replace('.0', '').strip()
    acc_type = str(row.get('Which type of account is this?', '')).strip()
    ifsc = str(row.get('IFSC (Indian Financial System Code)', '')).strip()
    bank_name = str(row.get('Name of the Bank (e.g., State Bank of India, HDFC Bank)', '')).strip()

    teacher_doc = {
        'teacher_id': next_teacher_id,
        'name': name,
        'subject': 'General',
        'phone': mobile,
        'email': email,
        'basic_salary': basic_salary,
        'password': hash_password(password),
        'joining_date': '2026-04-01',
        'active': True,
        'created_at': datetime.now(),
        # Bank Details
        'pan_number': pan,
        'bank_account': bank_acc,
        'account_type': acc_type,
        'ifsc': ifsc,
        'bank_name': bank_name
    }
    
    # insert
    teachers_col.insert_one(teacher_doc)

print("Insertion completed.")
