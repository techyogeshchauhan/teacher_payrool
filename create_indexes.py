from pymongo import MongoClient, ASCENDING, DESCENDING
import os
from dotenv import load_dotenv

load_dotenv()
mongo_uri = os.environ.get('MONGO_URI')

if not mongo_uri:
    print("MONGO_URI not found in environment.")
    exit(1)

client = MongoClient(mongo_uri)
db = client['teacher_payroll']

def create_indexes():
    # Teachers
    print("Creating indexes for teachers...")
    db.teachers.create_index([("teacher_id", ASCENDING)], unique=True)
    db.teachers.create_index([("mobile", ASCENDING)], unique=True)
    
    # Students
    print("Creating indexes for students...")
    db.students.create_index([("mobile", ASCENDING)]) # Not unique, siblings can share
    db.students.create_index([("class", ASCENDING), ("section", ASCENDING)])
    db.students.create_index([("status", ASCENDING)])
    
    # Attendance
    print("Creating indexes for attendance...")
    db.attendance.create_index([("teacher_id", ASCENDING), ("date", DESCENDING)])
    db.attendance.create_index([("month", DESCENDING)])
    
    # Admins/Principals/Accountants
    print("Creating indexes for admins & principals & accountants...")
    db.admins.create_index([("username", ASCENDING)], unique=True)
    db.principals.create_index([("username", ASCENDING)], unique=True)
    # If accountants col exists:
    if "accountants" in db.list_collection_names():
        db.accountants.create_index([("username", ASCENDING)], unique=True)
        
    # Activity logs
    print("Creating indexes for activity logs...")
    db.activity_logs.create_index([("timestamp", DESCENDING)])
    db.activity_logs.create_index([("teacher_id", ASCENDING)])
    db.activity_logs.create_index([("action", ASCENDING)])

    # Fee history
    print("Creating indexes for fee history...")
    db.fee_history.create_index([("student_id", ASCENDING), ("date", DESCENDING)])
    
    # Assets
    print("Creating indexes for assets...")
    db.assets.create_index([("assigned_to", ASCENDING)])
    
    # Govt holidays
    print("Creating indexes for govt_holidays...")
    db.govt_holidays.create_index([("date", ASCENDING)])

    print("All indexes created successfully.")

if __name__ == "__main__":
    create_indexes()
