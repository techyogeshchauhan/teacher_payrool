from pymongo import MongoClient, ASCENDING, DESCENDING
import os
from dotenv import load_dotenv

load_dotenv()
mongo_uri = os.environ.get('MONGO_URI')

if not mongo_uri:
    print("MONGO_URI not found in environment.")
    exit(1)

client = MongoClient(mongo_uri)
db = client['gayatri_school']

def create_indexes():
    print("Creating indexes on 'gayatri_school'...")
    
    # Teachers
    db.teachers.create_index([("teacher_id", ASCENDING)], unique=True)
    db.teachers.create_index([("phone", ASCENDING)])
    db.teachers.create_index([("active", ASCENDING)])
    
    # Attendance
    db.attendance.create_index([("date", ASCENDING), ("status", ASCENDING)])
    db.attendance.create_index([("date", ASCENDING), ("teacher_id", ASCENDING)])
    db.attendance.create_index([("teacher_id", ASCENDING), ("date", DESCENDING)])
    db.attendance.create_index([("marked_at", DESCENDING)])
    
    # Admins/Principals
    db.admins.create_index([("username", ASCENDING)], unique=True)
    db.principals.create_index([("username", ASCENDING)], unique=True)
    
    # Assets
    db.assets.create_index([("teacher_id", ASCENDING), ("timestamp", DESCENDING)])
    
    # Holidays
    db.holidays.create_index([("date", ASCENDING)], unique=True)

    # Leave Requests
    db.leave_requests.create_index([("teacher_id", ASCENDING), ("applied_on", DESCENDING)])
    db.leave_requests.create_index([("status", ASCENDING), ("start_date", ASCENDING), ("end_date", ASCENDING)])

    # Generated Slips
    db.generated_slips.create_index([("generated_at", DESCENDING)])
    db.generated_slips.create_index([("teacher_id", ASCENDING), ("year", ASCENDING), ("month", ASCENDING)])

    # Logs
    db.logs.create_index([("teacher_id", ASCENDING), ("timestamp", DESCENDING)])
    db.logs.create_index([("action", ASCENDING), ("date", ASCENDING)])
    db.logs.create_index([("timestamp", DESCENDING)])

    # Salary Adjustments
    db.salary_adjustments.create_index([("year", ASCENDING), ("month", ASCENDING), ("teacher_id", ASCENDING)])

    print("All production indexes for gayatri_school created successfully.")

if __name__ == "__main__":
    create_indexes()
