# AJ KLASSES — UNIFIED EDUCATIONAL WEB PLATFORM & MANAGEMENT SYSTEM
**Premier Coaching Institute • Orai, Jalaun District, Uttar Pradesh — 285001**  
**Faculty Leadership:** Dr. Ajay Rathour (Founder & Director) & Abhishek Rathour  
**Support:** +91 63940 43659 • +91 73982 17481 • pariharrishi777@gmail.com

---

## 1. Executive Platform Overview

The **AJ Klasses Unified Platform** is a full-stack educational web application and administration management suite built specifically for **AJ Klasses Coaching Institute** in Orai, Uttar Pradesh. It unifies public student portals, online admissions, verified faculty profiles, a 5 GB media gallery, and a role-based staff console into a single, high-performance, dark glassmorphism system powered by **Node.js 22**, **Express**, and **native SQLite** (`node:sqlite`).

### Core Platform Pillars
1. **Academic Excellence & Results**: Students (Classes 6–12, CBSE & UP Board, JEE/NEET Foundation) verify and print official board-preparation marksheets using **only** their **Roll Number** and **Student Name**.
2. **Online Admissions & Tracking**: Prospective students apply online, receive a unique reference ID (`AJ-ADM-YYYY-XXXX`), and track review status without exposing personal contact details.
3. **Attendance Verification**: Parents and students monitor lecture attendance percentages and date-wise presence registers.
4. **Cumulative Progression History**: Multi-term performance analytics showing progression across multiple examinations and subjects.
5. **Faculty & Staff Directory**: Complete academic profiles of 7 verified mentors detailing degrees (Ph.D., M.Sc, M.A., B.Ed, BCA), teaching experience (up to 15+ years), and contact links.
6. **Events Gallery & 5 GB Cloud Media Vault**: High-resolution institute events showcase (Toppers Felicitation, Science Exhibitions, Annual Celebrations) with automatic 5 GB storage quota management.
7. **Role-Based Admin Console**: Authenticated dashboard for staff to manage admissions, students, exams, marksheets, attendance, faculty, and media assets.

---

## 2. Platform Architecture & Portals Directory

```
new website/
├── index.html                # Institute Homepage (Hero, Highlights, Toppers, Quick Actions)
├── courses.html              # Academic Curriculum (Classes 6-12, CBSE & UP Board, Foundation)
├── about.html                # Institutional Pedagogy, Mission & Leadership Message
├── about-staff.html          # Faculty & Staff Directory (7 Verified Mentors, Filter Tabs)
├── gallery.html              # Events Media Gallery (Dynamic Feed, Lightbox, 5 GB Telemetry)
├── admission.html            # Online Admission Portal (Application Form & Status Tracker)
├── results.html              # Student Result Verification Portal (Two-Field Marksheet Card)
├── attendance.html           # Daily Attendance Verification (Percentage & Lecture Register)
├── student-history.html      # Cumulative Academic Progression (Multi-Term Progression)
├── contact.html              # Contact Information, Location & Inquiry Form
├── style.css                 # Unified Vanilla CSS Design System (Gold/Blue Glassmorphism)
├── script.js                 # Global Interactive Script (Nav Drawer, Theme, Dropdowns)
├── server.js                 # Node.js 22 + SQLite Backend REST API Engine
├── test_suite.js             # Automated 63-Test Regression & Security Verification Suite
├── package.json              # Project Manifest & NPM Scripts
├── database_schema.sql       # PostgreSQL / Supabase Migration DDL with RLS Policies
├── data/
│   └── aj_klasses.db         # Persistent SQLite Database (WAL Mode, Foreign Keys ON)
└── uploads/
    └── gallery/              # Physical Disk Storage for Uploaded Event Photographs
```

### Complete Page Breakdown

| Portal File | Route / Access | Purpose & Features |
|---|---|---|
| [`index.html`](./index.html) | `http://localhost:3000/` | Main institute portal with hero classroom showcase, course highlights, top rankers, and 3-dot dropdown menu. |
| [`about-staff.html`](./about-staff.html) | `/about-staff.html` | Faculty directory with filter tabs (All, Mathematics, Science, English, Counseling), qualifications, experience, and direct inquiry buttons. |
| [`courses.html`](./courses.html) | `/courses.html` | Comprehensive academic programs, batch timings, and lead faculty mentorship. |
| [`gallery.html`](./gallery.html) | `/gallery.html` | High-definition media wall, category filtering (Toppers Felicitation, Science Exhibition, Annual Functions), full-screen lightbox modal, and live 5 GB storage indicator. |
| [`admission.html`](./admission.html) | `/admission.html` | Online admission registration form with real-time phone validation and dual-mode reference number status tracker. |
| [`results.html`](./results.html) | `/results.html` | Official term and board-prep result verification with print-to-PDF layout and dual faculty signature blocks. |
| [`attendance.html`](./attendance.html) | `/attendance.html` | Student attendance tracker displaying overall attendance percentage, days present, absent, late, and approved leaves. |
| [`student-history.html`](./student-history.html) | `/student-history.html` | Comprehensive academic progression timeline showing continuous performance trends across multiple terms. |
| [`admin/login.html`](./admin/login.html) | `/admin/login.html` | Authenticated staff entrance with rate limiting and secure PBKDF2 hash verification. |
| [`admin/dashboard.html`](./admin/dashboard.html) | `/admin/dashboard.html` | Comprehensive administrative console with 8 dedicated tabs and real-time operational telemetry. |

---

## 3. REST API Reference

All API routes run on the unified Express server (`server.js`):

### Public Endpoints
* `POST /api/results/lookup` — Verify published student marksheet (Payload: `rollNumber`, `studentName`).
* `POST /api/admissions/apply` — Submit new admission application. Returns unique `appRefNumber`.
* `GET /api/admissions/status?ref=AJ-ADM-YYYY-XXXX` — Track application review status.
* `POST /api/attendance/lookup` — Retrieve attendance percentage and lecture logs.
* `POST /api/history/lookup` — Retrieve cumulative academic progression and term history.
* `GET /api/teachers` — Fetch directory of active faculty mentors and qualifications.
* `GET /api/gallery?category=...` — Fetch gallery events and real-time 5 GB storage telemetry.

### Authenticated Admin Endpoints (Header: `Authorization: Bearer <token>`)
* `POST /api/admin/login` — Authenticate staff credentials (`admin` / `AJadmin@2025`).
* `GET /api/admin/dashboard` — Platform overview metrics (students, admissions, exams, results, faculty, 5 GB storage).
* `GET / POST / PUT / DELETE /api/admin/students` — Student directory CRUD and duplicate roll check.
* `GET / POST / PUT / DELETE /api/admin/exams` — Exam sessions management and publication toggle.
* `POST /api/admin/results` — Record student marksheet with validation (`marks <= max_marks`).
* `PATCH /api/admin/results/:id/publish` — Toggle result publication (Draft $\leftrightarrow$ Published).
* `POST /api/admin/bulk-import-csv` — Multer CSV/Excel parser with instant validation and dry-run preview.
* `GET /api/admin/sample-csv` — Download standardized Excel/CSV template.
* `GET /api/admin/admissions` — Review pending admission applications with status filter.
* `POST /api/admin/admissions/:id/approve` — Approve application and link to student record.
* `GET /api/admin/attendance/eligible-students` — Query class roster to mark attendance.
* `POST /api/admin/attendance/record` — Save date-wise attendance register for a session.
* `POST / PUT / DELETE /api/admin/teachers` — Faculty directory management (credentials, bio, order).
* `POST /api/admin/gallery/upload` — Upload event photo with strict 5 GB quota verification.
* `DELETE /api/admin/gallery/:id` — Delete gallery item and immediately reclaim disk storage space.

---

## 4. Security Architecture & 5 GB Quota Engine

1. **Two-Field Identification Standard**:
   * Students access results, attendance, and progression using **only** Roll Number and Student Name.
   * No passwords, OTPs, or sensitive dates of birth are required from students or parents.
2. **Generic Error Safeguard**:
   * Failed queries return a uniform generic message:  
     *"We couldn't verify these details or the information is not currently available. Please check the information or contact the institute."*
   * The platform never confirms or leaks whether a roll number exists, whether a name matched, or whether an unpublished draft is pending.
3. **Draft vs Published Isolation**:
   * All marksheets start in Draft mode (`is_published = 0`).
   * Draft results are strictly filtered out by SQL queries and are **never** accessible to the public until explicitly published by an administrator.
4. **Privacy-Preserving SHA-256 Rate Limiter**:
   * Client IP addresses are hashed using SHA-256 with a salt before logging. Raw IP addresses are never retained.
   * Automatically restricts public spam (50 lookups / 15 min; 20 admin logins / 15 min) and purges old logs periodically.
5. **5 GB Events Gallery Storage Engine**:
   * Allocation: Exactly `5,368,709,120` bytes (5.00 GB).
   * Before writing uploaded media to `uploads/gallery/`, `server.js` calculates `current_used + file_size`. If the sum exceeds 5 GB, the upload is rejected with a 400 error and the temporary buffer is instantly deleted.
   * When an event photo is deleted in the Admin Console, `fs.unlinkSync` permanently removes the file from disk, freeing capacity in real time.

---

## 5. How to Run Locally

### Prerequisites
* **Node.js**: v18+ (verified on Node.js v22.23.3)
* **npm**: v9+

### Quick Start
```bash
# 1. Install dependencies
npm install

# 2. Launch the local server
npm start
```

The server will automatically initialize SQLite with WAL mode (`data/aj_klasses.db`), seed default faculty, demo exams, students, and events, and listen on port **3000**:
* **Main Website**: `http://localhost:3000/index.html`
* **Faculty Directory**: `http://localhost:3000/about-staff.html`
* **Events Gallery**: `http://localhost:3000/gallery.html`
* **Admissions Portal**: `http://localhost:3000/admission.html`
* **Student Results Portal**: `http://localhost:3000/results.html`
* **Attendance Portal**: `http://localhost:3000/attendance.html`
* **Student Academic History**: `http://localhost:3000/student-history.html`
* **Admin Staff Login**: `http://localhost:3000/admin/login.html`

### Default Staff Credentials
* **Username**: `admin`
* **Password**: `AJadmin@2025` *(or set via `ADMIN_INITIAL_PASSWORD` environment variable)*

---

## 6. Automated Verification & Testing

The platform features an automated end-to-end regression and security test suite (`test_suite.js`) executing across 7 test groups.

To run the verification suite:
```bash
npm test
```

### Test Coverage (63 / 63 Tests Passed — 100%)
* **Group 1: Public Result Lookup & Privacy (14 assertions)**: Exact two-field matching, case-insensitivity, whitespace trimming, invalid roll rejection, mismatched name rejection, empty fields validation, buffer overflow string rejection, draft isolation, and private ID masking.
* **Group 2: Admin Authentication & Access Control (5 assertions)**: Unauthenticated 401 blocking, invalid password rejection, PBKDF2 hash verification, token issuance, and authenticated dashboard metrics.
* **Group 3: Student & Result Data Management (8 assertions)**: Student creation, duplicate roll prevention within class/year, validation rejecting `marks > max_marks`, draft marksheet isolation, admin publishing, and aggregation accuracy (180/200).
* **Group 4: Admissions Portal & Public Tracking (8 assertions)**: Application submission, `AJ-ADM-YYYY-XXXX` reference generation, public status tracking, 404 on nonexistent reference, and missing field validation.
* **Group 5: Attendance & Progression History (8 assertions)**: Attendance lookup, percentage calculation, lecture logs, student academic history profile, exams list, and mismatched name rejection.
* **Group 6: Faculty & Staff Directory Module (9 assertions)**: Public faculty feed (`GET /api/teachers`), verification of seeded leaders (Dr. Ajay, Komal Ma'am), unauthorized creation blocking (401), validation (400), and full admin CRUD cycle (Create, Update, Delete).
* **Group 7: Events Gallery & 5 GB Storage Quota (11 assertions)**: Gallery feed (`GET /api/gallery`), 5 GB quota verification (`5,368,709,120` bytes), formatted storage telemetry, category filtering, and unauthorized deletion blocking (401).

---

## 7. Cloud Migration Guide (PostgreSQL & Supabase)

If deploying to **Supabase** or a cloud PostgreSQL instance:

1. Open your Supabase Dashboard $\to$ **SQL Editor**.
2. Open [`database_schema.sql`](./database_schema.sql) and paste the complete script into the editor.
3. Click **Run**.
4. This provisions:
   * Tables with primary keys and constraints: `students`, `exams`, `results`, `result_subjects`, `admission_applications`, `attendance_sessions`, `attendance_records`, `teachers`, `gallery_events`, `admin_users`, `rate_limit_logs`.
   * Row Level Security (RLS) enabled on all tables.
   * `SECURITY DEFINER` stored functions (`lookup_student_result`, `track_admission_status`, etc.) for zero-leak public execution.

---

## 8. Verified Faculty Mentors (Orai Campus)

| Mentor Name | Designation & Role | Qualifications | Experience |
|---|---|---|---|
| **Dr. Ajay Sir** | Founder & Academic Director | B.Sc, D.El.Ed, M.Sc (Math), M.A. (Psychology), B.Ed, Ph.D. (Psychology) | 15+ Years (Educational Research & Advanced Pedagogy) |
| **Komal Ma'am** | Senior Faculty — Science & Elementary Pedagogy | B.Sc, D.El.Ed | More than 7 Years Experience (+91 70078 05655) |
| **Arvind Sir** | Senior Faculty — English & Economics | M.A. English & Economics | More than 10 Years Experience |
| **Simran Ma'am** | Faculty — Computer Applications & Mathematics | BCA | More than 3 Years Experience (+91 85459 58647) |
| **Sapna Ma'am** | Faculty — Foundation Wing & Humanities | B.A. | More than 2 Years Experience (+91 92366 05530) |
| **Shivank Sir** | Faculty — Science & Practical Physics | B.Sc | More than 2 Years Experience (+91 73982 17481) |
| **Sona Ma'am** | Senior Counselor & Behavioral Mentor | B.A. with Psychology, M.A. with Psychology | More than 5 Years Experience (+91 63940 43659) |
| **V. K. Yadav Sir** | Senior Faculty & Board Mentor | Senior Academic Mentor | Board Examination & Concept Mastery (+91 75700 25729) |
| **Rishi Parihar** | Lead Web Developer & Technical Operations Head | Full-Stack Developer & Software Engineer | Full-Stack Web Architecture & Security (+91 90448 92605) |

---

*© 2024–2026 AJ Klasses, Orai, Uttar Pradesh. All rights reserved.*
