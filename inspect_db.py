import os
from pymongo import MongoClient

mongo_uri = 'mongodb+srv://GVP:QeMjUCPTfgZJVHVO@gvp.sbsdal5.mongodb.net/?appName=GVP'
client = MongoClient(mongo_uri)
db = client['gayatri_school']

print("Teachers:")
for t in db.teachers.find():
    print(t.get('name'), t.get('teacher_id'), t.get('basic_salary'))

print("\nHolidays in April 2026:")
for h in db.govt_holidays.find({'date': {'$regex': '^2026-04'}}):
    print(h)
