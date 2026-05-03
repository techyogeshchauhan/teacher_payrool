import os
from datetime import datetime
from pymongo import MongoClient

mongo_uri = 'mongodb+srv://GVP:QeMjUCPTfgZJVHVO@gvp.sbsdal5.mongodb.net/?appName=GVP'
client = MongoClient(mongo_uri)
db = client['gayatri_school']
teachers_col = db['teachers']
attendance_col = db['attendance']

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

# 1. Update Chandra Prakash
cp = teachers_col.find_one({'phone': '9304531866'})
if cp:
    teachers_col.update_one({'_id': cp['_id']}, {'$set': {'basic_salary': 8000.0}})
    print(f"Updated Chandra Prakash salary to 8000.0")

# 2. Update Priya
priya = teachers_col.find_one({'name': {'$regex': 'Priya', '$options': 'i'}})
if priya:
    p_id = priya['teacher_id']
    p_name = priya['name']
    
    # Clear Priya's April attendance
    attendance_col.delete_many({'teacher_id': p_id, 'date': {'$regex': '^2026-04'}})
    
    # Priya present 1st to 15th (except Sundays 5, 12)
    for d in range(1, 16):
        if d not in [5, 12]:
            add_att(p_id, p_name, d, 'present')
    
    # Absent from 16 to 30
    for d in range(16, 31):
        if d not in [19, 26]:
            add_att(p_id, p_name, d, 'absent')
    print(f"Updated Priya's attendance (1-15 present).")

# 3. Update Varsha Kumari
vk = teachers_col.find_one({'phone': '920463842'})
if vk:
    vk_id = vk['teacher_id']
    vk_name = vk['name']
    
    # Clear Varsha's April attendance
    attendance_col.delete_many({'teacher_id': vk_id, 'date': {'$regex': '^2026-04'}})
    
    # Varsha 8 paid days: present on 1, 2, 3, 4, 6, 7, 8 (7 days) + 1 sunday (5) = 8
    # Last present day is 8th. So work period is 1 to 8.
    for d in range(1, 9):
        if d != 5:
            add_att(vk_id, vk_name, d, 'present')
    
    # Absent for the rest
    for d in range(9, 31):
        if d not in [12, 19, 26]:
            add_att(vk_id, vk_name, d, 'absent')
    print(f"Updated Varsha's attendance (8 paid days total).")

print("All corrections applied successfully.")
