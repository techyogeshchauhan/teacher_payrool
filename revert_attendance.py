import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['gayatri_school']

teacher_id = 'TCH1455'
date_str = '2026-06-21'

# Delete the 'A' record so Sunday defaults back to Paid
result = db.attendance.delete_one({'date': date_str, 'teacher_id': teacher_id})
if result.deleted_count > 0:
    print(f"Successfully reverted 21 June 2026 for {teacher_id} back to normal (Paid Sunday).")
else:
    # If not deleted, maybe it wasn't there? Let's just set it to 'P' just in case.
    db.attendance.update_one({'date': date_str, 'teacher_id': teacher_id}, {'$set': {'status': 'P'}}, upsert=True)
    print(f"Set {teacher_id} to 'P' for {date_str}.")
