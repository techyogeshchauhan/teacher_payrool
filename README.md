# गायत्री विद्यापीठ — Attendance & Payroll System
## दाउदनगर

---

## 🚀 Setup Instructions

### Step 1: MongoDB Install करें
```bash
# Ubuntu/Linux
sudo apt-get install -y mongodb
sudo systemctl start mongodb
sudo systemctl enable mongodb

# Windows: https://www.mongodb.com/try/download/community
```

### Step 2: Python Libraries Install करें
```bash
cd gayatri_school
pip install -r requirements.txt
```

### Step 3: App चलाएं
```bash
python app.py
```

### Step 4: Browser में खोलें
```
http://localhost:5000
```

---

## 🔑 Default Login

### Admin (Principal)
- Username: `admin`
- Password: `admin123`

### Teacher
- Teacher ID: (admin जब teacher add करे तब set होगा)
- Password: (admin जब teacher add करे तब set होगा)

---

## 📋 Features

### Admin Panel:
- ✅ Teacher add / remove करना
- ✅ हर teacher को unique ID & password देना
- ✅ Daily attendance mark करना (Present / Half Day / Absent)
- ✅ किसी भी date की attendance देख सकते हैं
- ✅ Monthly attendance report (calendar view)
- ✅ Auto salary calculate — working days के हिसाब से
- ✅ Payroll sheet print कर सकते हैं

### Teacher Panel:
- ✅ Apni attendance check kar sakte hain
- ✅ Monthly salary slip dekh sakte hain
- ✅ Print salary slip

---

## 💰 Salary Formula

```
Working Days = सोमवार से शनिवार (रविवार छोड़कर)
Per Day = Basic Salary ÷ Working Days
Net Salary = (Present Days + Half Days × 0.5) × Per Day Rate
Deduction = Basic Salary - Net Salary
```

---

## 📁 Project Structure

```
gayatri_school/
├── app.py              # Main Flask Application
├── requirements.txt    # Python dependencies
├── templates/
│   ├── base.html           # Common navbar/layout
│   ├── admin_login.html    # Admin login page
│   ├── teacher_login.html  # Teacher login page
│   ├── admin_dashboard.html
│   ├── manage_teachers.html
│   ├── add_teacher.html
│   ├── mark_attendance.html
│   ├── payroll.html
│   ├── attendance_report.html
│   ├── teacher_dashboard.html
│   └── teacher_salary.html
└── static/             # CSS/JS files (optional)
```

---

## 🔧 Tech Stack
- **Backend:** Python Flask
- **Database:** MongoDB (pymongo)
- **Frontend:** HTML + Tailwind CSS + Font Awesome
- **Language:** Hindi + English
