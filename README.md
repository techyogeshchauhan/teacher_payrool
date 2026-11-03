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
cd teacher_payrool
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
teacher_payrool/
├── app.py              # Main Flask application (all routes)
├── config.py           # App settings, loaded from .env
├── security.py         # Password hashing, input validation helpers
├── middleware.py       # Security headers / request middleware
├── requirements.txt    # Python dependencies
├── Procfile            # Production start command (gunicorn)
├── .env                # Secrets — never commit
├── scripts/
│   └── create_indexes.py   # One-time MongoDB index setup
├── templates/          # Jinja2 HTML pages (base.html = common layout)
├── static/             # Logo, school photos
│   └── uploads/            # Teacher photos uploaded via the app
├── logs/               # App log files (auto-created, not committed)
└── records/            # Private payroll documents (not committed)
    ├── payroll/            # Monthly payroll sheets
    └── salary_slips/       # Generated salary slips, one folder per month (YYYY-MM)
```

---

## 🔧 Tech Stack
- **Backend:** Python Flask
- **Database:** MongoDB (pymongo)
- **Frontend:** HTML + Tailwind CSS + Font Awesome
- **Language:** Hindi + English
