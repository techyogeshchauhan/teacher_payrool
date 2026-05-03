import os
import hashlib
from datetime import datetime, date
from pymongo import MongoClient
import calendar

mongo_uri = os.environ.get('MONGO_URI', 'mongodb+srv://GVP:QeMjUCPTfgZJVHVO@gvp.sbsdal5.mongodb.net/?appName=GVP')
client = MongoClient(mongo_uri)
db = client['gayatri_school']
teachers_col = db['teachers']
attendance_col = db['attendance']

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_base_id(phone):
    if len(phone) >= 4:
        return f"TCH{phone[-4:]}"
    return f"TCH{phone.zfill(4)}"

def get_unique_teacher_id(phone):
    base_id = get_base_id(phone)
    teacher_id = base_id
    count = 1
    while teachers_col.find_one({'teacher_id': teacher_id}):
        count += 1
        teacher_id = f"{base_id}-{count}"
    return teacher_id

# 1. Chandra Prakash
cp_phone = '9304531866'
cp_id = get_unique_teacher_id(cp_phone)
if not teachers_col.find_one({'phone': cp_phone}):
    teachers_col.insert_one({
        'teacher_id': cp_id,
        'name': 'Chandra Prakash',
        'subject': 'General',
        'phone': cp_phone,
        'email': 'Chandra669praksh@gmail.com',
        'basic_salary': 80000.0,
        'password': hash_password('GVP@2026'),
        'joining_date': '2026-04-01',
        'active': True,
        'created_at': datetime.now(),
        'must_change_password': True,
        'bank_name': 'State bank of india',
        'bank_account': '33537035495',
        'ifsc': 'SBIN0005609',
        'holder_name': 'Chandra Prakash',
        'pan_no': 'GAEPP5392C'
    })
else:
    cp_id = teachers_col.find_one({'phone': cp_phone})['teacher_id']

# 2. Khushi kumari
kk_phone = '9125088979'
kk_id = get_unique_teacher_id(kk_phone)
if not teachers_col.find_one({'phone': kk_phone}):
    teachers_col.insert_one({
        'teacher_id': kk_id,
        'name': 'Khushi kumari',
        'subject': 'General',
        'phone': kk_phone,
        'email': 'k65253183@gmail.com',
        'basic_salary': 4000.0,
        'password': hash_password('GVP@2026'),
        'joining_date': '2026-04-10',
        'active': True,
        'created_at': datetime.now(),
        'must_change_password': True,
        'bank_name': 'PUNJAB NATIONAL BANK',
        'bank_account': '3861001700280200',
        'ifsc': 'PUNB0386100',
        'holder_name': 'Khushi kumari',
        'pan_no': 'NA'
    })
else:
    kk_id = teachers_col.find_one({'phone': kk_phone})['teacher_id']

# 3. Varsha kumari
vk_phone = '920463842'
vk_id = get_unique_teacher_id(vk_phone)
if not teachers_col.find_one({'phone': vk_phone}):
    teachers_col.insert_one({
        'teacher_id': vk_id,
        'name': 'Varsha kumari',
        'subject': 'General',
        'phone': vk_phone,
        'email': 'varshakumariv2007@gmail.com',
        'basic_salary': 3500.0,
        'password': hash_password('GVP@2026'),
        'joining_date': '2026-04-01',
        'active': True,
        'created_at': datetime.now(),
        'must_change_password': True,
        'bank_name': 'NA',
        'bank_account': '0010800017765',
        'ifsc': 'BARBODAUDNA',
        'holder_name': 'Varsha kumari',
        'pan_no': 'NA'
    })
else:
    vk_id = teachers_col.find_one({'phone': vk_phone})['teacher_id']

# 4. Shivani Singh (already exists, TCH1455)
ss_id = 'TCH1455'
teachers_col.update_one({'teacher_id': ss_id}, {'$set': {'joining_date': '2026-04-27'}})

print("Teachers added/updated.")

# Handle Attendance for April 2026
# Clear existing attendance for these 4 teachers in April 2026
attendance_col.delete_many({
    'teacher_id': {'$in': [cp_id, kk_id, vk_id, ss_id]},
    'date': {'$regex': '^2026-04'}
})

def add_att(tid, tname, d, status):
    date_str = f"2026-04-{d:02d}"
    attendance_col.insert_one({
        'teacher_id': tid,
        'teacher_name': tname,
        'date': date_str,
        'status': status,
        'marked_by': 'Admin Script',
        'marked_at': datetime.now()
    })

# April 2026 Sundays: 5, 12, 19, 26

# 1. Chandra Prakash: 3 absent, rest present (paid days 27)
# Absent on 1, 2, 3
for d in [1, 2, 3]:
    add_att(cp_id, 'Chandra Prakash', d, 'absent')
# Present on 4 to 30 (except Sundays)
for d in range(4, 31):
    if d not in [5, 12, 19, 26]:
        add_att(cp_id, 'Chandra Prakash', d, 'present')

# 2. Khushi kumari: paid days 15 (including sunday)
# Work period 10 to 24 (15 days). Sundays: 12, 19
# Present on 10 to 24 (except Sundays)
for d in range(10, 25):
    if d not in [12, 19]:
        add_att(kk_id, 'Khushi kumari', d, 'present')
# Absent 25 to 30
for d in range(25, 31):
    if d not in [26]:
        add_att(kk_id, 'Khushi kumari', d, 'absent')

# 3. Varsha kumari: paid days 8 (including sunday)
# Work period 1 to 8 (8 days). Sunday: 5
# Present 1 to 8 (except Sunday 5)
for d in range(1, 9):
    if d != 5:
        add_att(vk_id, 'Varsha kumari', d, 'present')
# Absent 9 to 30
for d in range(9, 31):
    if d not in [12, 19, 26]:
        add_att(vk_id, 'Varsha kumari', d, 'absent')

# 4. Shivani Singh: 27, 28, 29, 30 present
for d in [27, 28, 29, 30]:
    add_att(ss_id, 'Shivani Singh', d, 'present')

print("Attendance records inserted.")
