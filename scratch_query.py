import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)

db = client['gayatri_school']
print("Collections:")
for coll in db.list_collection_names():
    print(f"\n--- {coll} ---")
    sample = db[coll].find_one()
    print("Sample:", sample)

# Query specifically for teacher TCH9866
print("\n--- Teacher TCH9866 ---")
print(db.teachers.find_one({'teacher_id': 'TCH9866'}))

print("\n--- Attendance for TCH9866 on 2026-06-21 ---")
# June 21, 2026
print(db.attendance.find_one({'date': '2026-06-21', 'teacher_id': 'TCH9866'}))
# check if it uses string dates or datetime
print("\n--- Any Attendance for TCH9866 ---")
print(db.attendance.find_one({'teacher_id': 'TCH9866'}))
