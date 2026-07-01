import os
from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['gayatri_school']

teacher_id = 'TCH9866'
date_str = '2026-06-21'

teacher = db.teachers.find_one({'teacher_id': teacher_id})
if teacher:
    result = db.attendance.update_one(
        {'date': date_str, 'teacher_id': teacher_id},
        {'$set': {
            'status': 'A',
            'marked_at': datetime.now(),
            'marked_by': 'Admin (Deduction for Sunday)',
            'teacher_name': teacher['name']
        }},
        upsert=True
    )
    print(f"Updated attendance for {teacher['name']} on {date_str} to 'A' (Absent).")
else:
    print("Teacher not found.")
