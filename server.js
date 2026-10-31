/**
 * AJ KLASSES — INTEGRATED STUDENT MANAGEMENT BACKEND SYSTEM
 * Modules: Admissions, Enrolled Students, Results, Attendance & Student Academic History
 * Technology: Node.js 22 + Express + Native SQLite (DatabaseSync)
 * Architecture: Clean REST API, Privacy-Preserving Rate Limiter, PBKDF2 Crypto, Audit Logging
 */

const express = require('express');
const helmet = require('helmet');         // ✅ SECURITY: 15+ hardened HTTP headers
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// SECURITY HARDENING: INPUT SANITIZATION HELPER
// ============================================================
function sanitizeHtml(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const cleaned = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      cleaned[key] = sanitizeHtml(value);
    } else if (Array.isArray(value)) {
      cleaned[key] = value.map(v => typeof v === 'string' ? sanitizeHtml(v) : v);
    } else {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

// ============================================================
// SECURITY HARDENING: REQUEST ID MIDDLEWARE
// ============================================================
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
  next();
});

// ============================================================
// SECURITY HARDENING: HELMET.JS — 15+ SECURITY HEADERS (Phase 1 Upgrade)
// ============================================================
app.use(helmet({
  // Strict Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc:     ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      baseUri:    ["'self'"],
      formAction: ["'self'"]
    }
  },
  // HTTP Strict Transport Security — force HTTPS for 1 year
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  // Block clickjacking
  frameguard: { action: 'deny' },
  // No MIME sniffing
  noSniff: true,
  // No referrer on cross-origin
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Disable X-Powered-By: Express (hides tech stack)
  hidePoweredBy: true,
  // XSS filter for legacy browsers
  xssFilter: true,
  // Disable DNS prefetch (prevents data leakage)
  dnsPrefetchControl: { allow: false },
  // Prevent IE from opening downloads in site context
  ieNoOpen: true,
  // No caching for downloads
  noCache: false
}));

// Additional: Disable Permissions for camera/mic/geolocation
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  // Prevent API responses from being cached — critical for student data privacy
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
  }
  next();
});

// ============================================================
// SECURITY HARDENING: CORS RESTRICTION
// ============================================================
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (same-origin, curl, mobile apps, local file://)
    if (!origin || origin === 'null') {
      return callback(null, true);
    }
    // Allow any localhost/127.0.0.1 port (e.g. 3000, 5500 Live Server, 8080)
    const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
    if (isLocal || (process.env.ALLOWED_ORIGIN && origin === process.env.ALLOWED_ORIGIN)) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy violation: Origin not allowed'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

app.use(express.json({ limit: '3mb' }));
app.use(express.urlencoded({ extended: true, limit: '3mb' }));

// ============================================================
// SECURITY HARDENING: CODE-LEVEL FIREWALL & INTRUSION DETECTION (IPS)
// ============================================================
const SUSPICIOUS_PATH_PATTERNS = [
  /(\.env|\.git|\.aws|\.ssh|wp-config|phpmyadmin|wp-login|setup\.php|eval-stdin|actuator|xmlrpc\.php)/i,
  /(\.\.[\/\\])/, // Path traversal attempts
  /(union[\s+]+select|select[\s+]+.*?from|information_schema|waitfor[\s+]+delay|<script|onload\s*=)/i // Injection probes
];

const SENSITIVE_BLOCKED_FILES = [
  '/server.js', '/package.json', '/package-lock.json',
  '/test_suite.js', '/database_schema.sql', '/.env',
  '/.gitignore', '/readme.md'
];
const SENSITIVE_BLOCKED_PREFIXES = ['/data/', '/node_modules/', '/.git/'];

app.use((req, res, next) => {
  const ipHash = hashIp(req);
  const normalizedPath = (req.path || '').toLowerCase();
  const queryStr = req.url || '';

  // 1. Firewall Blocklist Check — O(1) in-memory block
  if (blockedIpsSet.has(ipHash)) {
    return res.status(403).json({
      success: false,
      error: 'Forbidden',
      message: 'Access denied by institute security firewall due to repeated suspicious activity.'
    });
  }

  // 2. Sensitive server files protection
  if (SENSITIVE_BLOCKED_FILES.includes(normalizedPath) || SENSITIVE_BLOCKED_PREFIXES.some(p => normalizedPath.startsWith(p))) {
    recordSecurityEvent(ipHash, 'SENSITIVE_FILE_PROBE', req, `Attempted access to: ${req.path}`);
    return res.status(403).json({ success: false, message: 'Access denied.' });
  }

  // 3. Automated scanner / exploit pattern detection
  const isSuspicious = SUSPICIOUS_PATH_PATTERNS.some(pat => pat.test(normalizedPath) || pat.test(queryStr));
  if (isSuspicious) {
    const now = Date.now();
    const entry = suspiciousScoreMap.get(ipHash) || { score: 0, resetAt: now + 10 * 60 * 1000 };
    if (now > entry.resetAt) {
      entry.score = 1;
      entry.resetAt = now + 10 * 60 * 1000;
    } else {
      entry.score += 1;
    }
    suspiciousScoreMap.set(ipHash, entry);

    recordSecurityEvent(ipHash, 'EXPLOIT_SCANNER_PROBE', req, `Pattern match on: ${req.url}`);

    if (entry.score >= 5) {
      blockIp(ipHash, 'Automated exploit scanner probe detected (5 hits)', 24);
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: 'Suspicious scanning activity detected. Your IP hash has been temporarily quarantined by our firewall.'
      });
    }

    return res.status(400).json({ success: false, message: 'Invalid or restricted request path.' });
  }

  // 4. Structured Request Logging (Response time & security tracking)
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (req.path.startsWith('/api/') || res.statusCode >= 400) {
      console.log(`[HTTP] ${req.method} ${req.path} -> ${res.statusCode} (${duration}ms) [IP: ${ipHash.slice(0, 8)}...]`);
    }
  });

  next();
});


// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize SQLite Database
const dbPath = path.join(dataDir, 'aj_klasses.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode & foreign keys
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// ============================================================
// DATABASE INITIALIZATION & SCHEMA CREATION
// ============================================================

db.exec(`
  -- 1. Admission Applications Table
  CREATE TABLE IF NOT EXISTS admission_applications (
    id TEXT PRIMARY KEY,
    app_ref_number TEXT UNIQUE NOT NULL,
    student_name TEXT NOT NULL,
    parent_name TEXT NOT NULL,
    contact_number TEXT NOT NULL,
    email TEXT,
    desired_class TEXT NOT NULL,
    board TEXT DEFAULT 'CBSE',
    medium TEXT DEFAULT 'English',
    academic_session TEXT NOT NULL,
    desired_course TEXT NOT NULL,
    previous_school TEXT,
    message TEXT,
    status TEXT DEFAULT 'Pending',
    admin_remarks TEXT,
    linked_student_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_admissions_ref ON admission_applications(app_ref_number);

  -- 2. Students & Enrollments Table
  CREATE TABLE IF NOT EXISTS students (
    id TEXT PRIMARY KEY,
    roll_number TEXT NOT NULL,
    student_name TEXT NOT NULL,
    class_name TEXT NOT NULL,
    section TEXT DEFAULT 'A',
    academic_year TEXT NOT NULL,
    enrollment_status TEXT DEFAULT 'Active',
    parent_name TEXT,
    contact_number TEXT,
    email TEXT,
    admission_app_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (roll_number, class_name, academic_year)
  );

  CREATE INDEX IF NOT EXISTS idx_students_lookup ON students(roll_number, student_name);

  -- 3. Examinations Table
  CREATE TABLE IF NOT EXISTS exams (
    id TEXT PRIMARY KEY,
    exam_name TEXT NOT NULL,
    academic_year TEXT NOT NULL,
    target_classes TEXT NOT NULL,
    is_published INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (exam_name, academic_year)
  );

  -- 4. Results Master Table
  CREATE TABLE IF NOT EXISTS results (
    id TEXT PRIMARY KEY,
    student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    exam_id TEXT NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    is_published INTEGER DEFAULT 0,
    publication_date TEXT,
    teacher_remarks TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (student_id, exam_id)
  );

  -- 5. Result Subjects Table
  CREATE TABLE IF NOT EXISTS result_subjects (
    id TEXT PRIMARY KEY,
    result_id TEXT NOT NULL REFERENCES results(id) ON DELETE CASCADE,
    subject_name TEXT NOT NULL,
    marks_obtained REAL NOT NULL,
    max_marks REAL NOT NULL,
    passing_marks REAL NOT NULL,
    UNIQUE (result_id, subject_name)
  );

  -- 6. Attendance Sessions Table
  CREATE TABLE IF NOT EXISTS attendance_sessions (
    id TEXT PRIMARY KEY,
    session_date TEXT NOT NULL,
    class_name TEXT NOT NULL,
    section TEXT DEFAULT 'A',
    subject_name TEXT DEFAULT 'Regular Lecture',
    academic_year TEXT NOT NULL,
    recorded_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (session_date, class_name, section, subject_name, academic_year)
  );

  -- 7. Attendance Records Table
  CREATE TABLE IF NOT EXISTS attendance_records (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES attendance_sessions(id) ON DELETE CASCADE,
    student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    remarks TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (session_id, student_id)
  );

  -- 8. Audit Logs Table
  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    admin_username TEXT NOT NULL,
    action TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    target_id TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- 9. Admin Users Table
  CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- 10. Rate Limits Table
  CREATE TABLE IF NOT EXISTS rate_limits (
    ip_hash TEXT PRIMARY KEY,
    attempts INTEGER DEFAULT 1,
    first_attempt INTEGER NOT NULL,
    last_attempt INTEGER NOT NULL
  );

  -- 11. Teachers / Faculty Directory Table
  CREATE TABLE IF NOT EXISTS teachers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    department TEXT NOT NULL,
    qualification TEXT NOT NULL,
    experience TEXT NOT NULL,
    phone TEXT,
    specialization TEXT,
    bio TEXT,
    initials TEXT,
    photo_url TEXT,
    display_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- 12. Events Gallery Table (5 GB Storage System)
  CREATE TABLE IF NOT EXISTS gallery_events (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    event_date TEXT NOT NULL,
    image_url TEXT NOT NULL,
    file_size_bytes INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- 13. IP Blocklist Table (Firewall)
  CREATE TABLE IF NOT EXISTS ip_blocklist (
    id TEXT PRIMARY KEY,
    ip_hash TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
  );
  CREATE INDEX IF NOT EXISTS idx_blocklist_hash ON ip_blocklist(ip_hash);

  -- 14. Suspicious Security Events Table
  CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    ip_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    path TEXT,
    method TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(created_at);
`);

// Migration safety: Ensure enrollment_status exists on existing students table
try {
  db.exec("ALTER TABLE students ADD COLUMN enrollment_status TEXT DEFAULT 'Active';");
} catch (e) {}
try {
  db.exec("ALTER TABLE students ADD COLUMN parent_name TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE students ADD COLUMN contact_number TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE students ADD COLUMN email TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE students ADD COLUMN admission_app_id TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE students ADD COLUMN verification_hash TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE admission_applications ADD COLUMN verification_hash TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE admission_applications ADD COLUMN notification_dispatched_at DATETIME;");
} catch (e) {}

// Table: Admission Notifications (Audit & WhatsApp/Email delivery log)
db.exec(`
  CREATE TABLE IF NOT EXISTS admission_notifications (
    id TEXT PRIMARY KEY,
    admission_id TEXT NOT NULL,
    student_id TEXT,
    student_name TEXT NOT NULL,
    roll_number TEXT NOT NULL,
    contact_number TEXT,
    email TEXT,
    verification_hash TEXT NOT NULL,
    channel TEXT NOT NULL,
    message_content TEXT NOT NULL,
    status TEXT DEFAULT 'Dispatched',
    dispatched_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

function generateVerificationHashCode(studentId, rollNumber) {
  const seed = `${studentId}:${rollNumber}:${crypto.randomBytes(8).toString('hex')}`;
  return crypto.createHash('sha256').update(seed).digest('hex').substring(0, 10).toUpperCase();
}

function buildAdmissionNotification(student, hash) {
  const cleanPhone = (student.contact_number || '').replace(/\D/g, '');
  const message = [
    `🎓 *AJ KLASSES, ORAI — ADMISSION CONFIRMED* 🎓`,
    ``,
    `Dear *${student.student_name}*,`,
    `Congratulations! Your admission at *AJ Klasses* has been *OFFICIALLY APPROVED*.`,
    ``,
    `📋 *Your Official Academic Credentials:*`,
    `• *Student Name:* ${student.student_name}`,
    `• *Roll Number:* *${student.roll_number}*`,
    `• *Class & Section:* ${student.class_name} (${student.section || 'A'})`,
    `• *Academic Session:* ${student.academic_year}`,
    `• *Security Verification Hash:* *${hash}*`,
    ``,
    `🔗 *Integrated Student Portals:*`,
    `• Result Portal: http://localhost:3000/results.html`,
    `• Attendance Portal: http://localhost:3000/attendance.html`,
    `• Academic History: http://localhost:3000/student-history.html`,
    ``,
    `📍 *Institute Address:* Teli Vali Street, Tulsi Nagar, Orai (Plus Code: XFP4+4F7)`,
    `📞 *Helpline / WhatsApp:* +91 63940 43659`,
    ``,
    `_Note: Keep this Roll Number and Verification Hash safe for all portal lookups and institute communications._`
  ].join('\n');

  const whatsappUrl = cleanPhone 
    ? `https://api.whatsapp.com/send?phone=91${cleanPhone}&text=${encodeURIComponent(message)}`
    : null;

  return {
    student_name: student.student_name,
    roll_number: student.roll_number,
    contact_number: student.contact_number,
    email: student.email,
    verification_hash: hash,
    message,
    whatsapp_url: whatsappUrl,
    whatsapp_web_url: cleanPhone ? `https://web.whatsapp.com/send?phone=91${cleanPhone}&text=${encodeURIComponent(message)}` : null,
    email_dispatched: Boolean(student.email),
    dispatched_at: new Date().toISOString()
  };
}

// Helper Functions
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

function verifyPassword(password, salt, storedHash) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  // SECURITY: Use timing-safe comparison to prevent timing attacks
  if (hash.length !== storedHash.length) return false;
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

function hashIp(req) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  return crypto.createHash('sha256').update(ip + '-aj-salt').digest('hex');
}

function logAudit(adminUsername, action, entity, targetId, details) {
  try {
    db.prepare(`
      INSERT INTO audit_logs (id, admin_username, action, target_entity, target_id, details)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), adminUsername, action, entity, targetId, JSON.stringify(details));
  } catch (e) {
    console.error('[Audit Log Error]', e.message);
  }
}

// In-Memory active admin sessions (token -> user data)
const adminSessions = new Map();

// ✅ SECURITY (Phase 1): In-Memory brute-force lockout tracker
// Tracks FAILED admin login attempts per IP hash
// After 5 failures → IP locked out for 30 minutes
const bruteForceMap = new Map(); // ipHash -> { count, lockedUntil }
const BRUTE_FORCE_MAX_ATTEMPTS = 5;
const BRUTE_FORCE_LOCKOUT_MS   = 30 * 60 * 1000; // 30 minutes

// ✅ SECURITY (Phase 1): Auto-cleanup of expired sessions every 30 min
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [token, session] of adminSessions.entries()) {
    if (session.expiresAt < now) {
      adminSessions.delete(token);
      cleaned++;
    }
  }
  // Also clean expired brute-force locks
  for (const [ipHash, entry] of bruteForceMap.entries()) {
    if (entry.lockedUntil && entry.lockedUntil < now) {
      bruteForceMap.delete(ipHash);
    }
  }
  if (cleaned > 0) console.log(`[Security] Cleaned ${cleaned} expired admin session(s).`);
}, 30 * 60 * 1000);

// ✅ PRIVACY (Phase 1): Phone number masking for public-facing APIs
// e.g. 9876543210 → 987XXXXX10
function maskPhone(phone) {
  if (!phone) return null;
  const clean = String(phone).replace(/\D/g, '');
  if (clean.length < 6) return '***';
  return clean.slice(0, 3) + 'X'.repeat(clean.length - 5) + clean.slice(-2);
}

// ============================================================
// ✅ SECURITY (Phase 2 & 3): FIREWALL & INTRUSION DETECTION
// ============================================================
const blockedIpsSet = new Set();
const suspiciousScoreMap = new Map(); // ipHash -> { score, resetAt }

function reloadBlockedIps() {
  try {
    blockedIpsSet.clear();
    const rows = db.prepare("SELECT ip_hash FROM ip_blocklist WHERE expires_at IS NULL OR expires_at > datetime('now')").all();
    rows.forEach(r => blockedIpsSet.add(r.ip_hash));
  } catch (e) {
    console.error('[Firewall Error] Failed to reload blocked IPs:', e.message);
  }
}

function blockIp(ipHash, reason, durationHours = 24) {
  try {
    const id = crypto.randomUUID();
    const expiresAt = durationHours ? new Date(Date.now() + durationHours * 3600 * 1000).toISOString() : null;
    db.prepare(`
      INSERT OR REPLACE INTO ip_blocklist (id, ip_hash, reason, blocked_at, expires_at)
      VALUES (?, ?, ?, datetime('now'), ?)
    `).run(id, ipHash, reason, expiresAt);
    blockedIpsSet.add(ipHash);
    console.warn(`[Firewall Blocked] 🚫 IP Hash ${ipHash.slice(0, 12)}... blocked for ${durationHours}h. Reason: ${reason}`);
  } catch (e) {
    console.error('[Firewall Error]', e.message);
  }
}

function unblockIp(ipHash) {
  try {
    db.prepare('DELETE FROM ip_blocklist WHERE ip_hash = ?').run(ipHash);
    blockedIpsSet.delete(ipHash);
    return true;
  } catch (e) {
    console.error('[Firewall Unblock Error]', e.message);
    return false;
  }
}

function recordSecurityEvent(ipHash, eventType, req, details = '') {
  try {
    db.prepare(`
      INSERT INTO security_events (id, ip_hash, event_type, path, method, details)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), ipHash, eventType, req.path || '', req.method || '', String(details).slice(0, 500));
  } catch (e) {
    console.error('[Security Event Error]', e.message);
  }
}

// Initial load of active blocked IPs into memory cache
reloadBlockedIps();


// Seed initial admin and demo datasets
(function seedInitialData() {
  const checkAdmin = db.prepare('SELECT id FROM admin_users LIMIT 1').get();
  if (!checkAdmin) {
    const adminId = crypto.randomUUID();
    const defaultPassword = process.env.ADMIN_INITIAL_PASSWORD || 'AJadmin@2025';
    const { hash, salt } = hashPassword(defaultPassword);

    db.prepare(`
      INSERT INTO admin_users (id, username, password_hash, salt, full_name, role)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(adminId, 'admin', hash, salt, 'Institute Administrator', 'super_admin');

    console.log('[AJ Klasses RMS] Seeded default administrator: "admin"');
  }

  // Seed verified 7 Teachers / Faculty if none exist
  const checkTeachers = db.prepare('SELECT id FROM teachers LIMIT 1').get();
  if (!checkTeachers) {
    const teachersList = [
      {
        name: 'Dr. Ajay Sir',
        role: 'Founder & Academic Director',
        department: 'Mathematics & Psychology',
        qualification: 'B.Sc, D.El.Ed, M.Sc (Math), M.A. with Psychology, B.Ed, Ph.D. with Psychology',
        experience: '15+ Years Experience (Educational Research & Advanced Pedagogy)',
        phone: null, // Space reserved as requested
        specialization: 'Advanced Mathematics, Educational Psychology & Board Merit Preparation',
        bio: 'Founder and Director at AJ Klasses. Holds doctoral credentials (Ph.D.) in Psychology along with dual Master degrees in Mathematics and Psychology. Pioneered personalized mentoring frameworks that drive top board ranks across the Bundelkhand region.',
        initials: 'AR',
        photo_url: 'assets/teachers/dr_ajay_sir.jpg',
        display_order: 1
      },
      {
        name: 'Komal Ma\'am',
        role: 'Senior Faculty — Science & Elementary Pedagogy',
        department: 'Science',
        qualification: 'B.Sc, D.El.Ed',
        experience: 'More than 7 Years Experience',
        phone: '7007805655', // Mobile provided
        specialization: 'General Science, Concept Building & Foundational Curriculum',
        bio: 'B.Sc and D.El.Ed with more than 7 years of specialized classroom experience nurturing strong fundamental concepts in middle and foundation wings with patient, concept-first teaching methodologies.',
        initials: 'KM',
        photo_url: 'assets/teachers/komal_maam.jpg',
        display_order: 2
      },
      {
        name: 'Arvind Sir',
        role: 'Senior Faculty — English & Economics',
        department: 'English & Economics',
        qualification: 'M.A. English & Economics',
        experience: 'More than 10 Years Experience',
        phone: null, // Space reserved as requested
        specialization: 'Advanced English Grammar, Literature, Macro & Micro Economics',
        bio: 'Veteran educator with more than a decade of rich academic experience preparing secondary and senior secondary students for board examinations, language fluency, and economic theories.',
        initials: 'AS',
        photo_url: null,
        display_order: 3
      },
      {
        name: 'Simran Ma\'am',
        role: 'Fees Accountant & Computer Teacher',
        department: 'Computer Science & Accounts',
        qualification: 'BCA',
        experience: 'More than 3 Years Experience',
        phone: '8545958647', // Mobile provided
        specialization: 'Information Technology, Coding Fundamentals & Fee Management',
        bio: 'BCA graduate with over 3 years of experience handling computer education and institute fee accounting with accuracy and dedication.',
        initials: 'SM',
        photo_url: 'assets/teachers/simran_maam.jpg',
        display_order: 4
      },
      {
        name: 'Sapna Ma\'am',
        role: 'Junior Teacher & Accountant',
        department: 'Foundation & Accounts',
        qualification: 'B.A.',
        experience: 'More than 2 Years Experience',
        phone: '9236605530', // Mobile provided
        specialization: 'Junior Wing Teaching & Fee Accounting',
        bio: 'B.A. graduate with over 2 years of experience in junior wing teaching and institute fee management.',
        initials: 'SP',
        photo_url: 'assets/teachers/sapna_maam.jpg',
        display_order: 5
      },
      {
        name: 'Shivank Sir',
        role: 'Faculty — Science & Practical Physics',
        department: 'Science',
        qualification: 'B.Sc',
        experience: 'More than 2 Years Experience',
        phone: '7398217481', // Mobile provided
        specialization: 'Physical Sciences, Experimental Demonstrations & Numericals',
        bio: 'B.Sc graduate with over 2 years of proven teaching expertise simplifying scientific laws, numerical mechanics, and interactive science experiments for junior and high school students.',
        initials: 'SS',
        photo_url: 'assets/teachers/shivank_sir.jpg',
        display_order: 6
      },
      {
        name: 'Sona Ma\'am',
        role: 'Senior Counselor & Behavioral Mentor',
        department: 'Psychology & Guidance',
        qualification: 'B.A. with Psychology, M.A. with Psychology',
        experience: 'More than 5 Years Experience',
        phone: '6394043659', // Mobile provided
        specialization: 'Cognitive Psychology, Exam Stress Management & Child Guidance',
        bio: 'Specialized psychological mentor holding both Bachelor\'s and Master\'s degrees in Psychology with over 5 years of counseling experience assisting students with focus, academic motivation, and mental wellness.',
        initials: 'SN',
        photo_url: null,
        display_order: 7
      },
      {
        name: 'V. K. Yadav Sir (Braj Kishor Yadav)',
        role: 'Senior Faculty & Board Mentor',
        department: 'Faculty Wing',
        qualification: 'Senior Faculty & Academic Mentor',
        experience: 'Rich Teaching & Mentorship Experience',
        phone: '7570025729', // Provided Mobile: 75700 25729
        specialization: 'Academic Mentorship, Board Examination Drills & Concept Mastery',
        bio: 'Senior faculty mentor at AJ Klasses, Orai. Guides students with concept-oriented teaching, patient problem solving, and board examination merit coaching.',
        initials: 'VK',
        photo_url: 'assets/teachers/vk_yadav_sir.jpg',
        display_order: 8
      },
      {
        name: 'Rishi Parihar',
        role: 'Lead Web Developer & Technical Operations Head',
        department: 'IT & Digital Infrastructure',
        qualification: 'Full-Stack Developer & Software Engineer',
        experience: 'Full-Stack Web Architecture & Security',
        phone: '9044892605',
        specialization: 'Full-Stack Architecture, IT Security, Student Portals & Database Systems',
        bio: 'Lead Full-Stack Web Developer and Technical Architect for AJ Klasses. Designed and engineered the institute web portals, automated results system, and security architecture.',
        initials: 'RP',
        photo_url: 'assets/teachers/rishi_parihar.jpg',
        display_order: 9
      }
    ];

    const stmt = db.prepare(`
      INSERT INTO teachers (id, name, role, department, qualification, experience, phone, specialization, bio, initials, photo_url, display_order)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    teachersList.forEach(t => {
      stmt.run(crypto.randomUUID(), t.name, t.role, t.department, t.qualification, t.experience, t.phone, t.specialization, t.bio, t.initials, t.photo_url, t.display_order);
    });
    console.log('[AJ Klasses RMS] Seeded 8 verified faculty members with qualifications & contact details.');
  }

  // Seed initial Events Gallery records
  const checkGallery = db.prepare('SELECT id FROM gallery_events LIMIT 1').get();
  if (!checkGallery) {
    const initialEvents = [
      {
        title: 'Annual Academic Toppers Felicitation Ceremony',
        description: 'Honoring our district rank holders, CBSE/UP Board toppers, and Olympiad medalists with medals, scholarships, and merit certificates.',
        category: 'Toppers & Awards',
        event_date: '2025-01-26',
        image_url: 'assets/toppers-achievement.jpg',
        file_size_bytes: 904799
      },
      {
        title: 'State-of-the-Art Classroom Lecture & Concept Sessions',
        description: 'Interactive classroom pedagogy with visual boards, concept-first explanations, and disciplined learning environment.',
        category: 'Classroom & Campus',
        event_date: '2025-02-10',
        image_url: 'assets/hero-classroom.jpg',
        file_size_bytes: 853174
      },
      {
        title: 'Personalized 1-on-1 Mentor Doubt Resolution Clinic',
        description: 'Daily dedicated mentor clinic where teachers resolve student queries individually, review tests, and guide study schedules.',
        category: 'Workshops & Counseling',
        event_date: '2025-02-18',
        image_url: 'assets/mentor-session.jpg',
        file_size_bytes: 824994
      },
      {
        title: 'National Science Day Working Models Exhibition',
        description: 'Students of Classes 8–12 presenting physics mechanics, working electric motors, chemistry reactions, and robotics prototypes.',
        category: 'Science & Exhibitions',
        event_date: '2025-02-28',
        image_url: 'assets/toppers-achievement.jpg',
        file_size_bytes: 780000
      },
      {
        title: 'Board Exam Stress Management & Mind Mapping Workshop',
        description: 'Psychological guidance session lead by Dr. Ajay Sir and Sona Ma\'am on stress management, cognitive relaxation, and memory retention.',
        category: 'Workshops & Counseling',
        event_date: '2025-03-05',
        image_url: 'assets/mentor-session.jpg',
        file_size_bytes: 750000
      },
      {
        title: 'Republic Day Cultural Celebrations & Speech Competition',
        description: 'Patriotic speeches, quiz tournaments, and cultural performances celebrating national spirit and academic dedication.',
        category: 'Annual Functions',
        event_date: '2025-01-26',
        image_url: 'assets/hero-classroom.jpg',
        file_size_bytes: 810000
      }
    ];

    const galStmt = db.prepare(`
      INSERT INTO gallery_events (id, title, description, category, event_date, image_url, file_size_bytes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    initialEvents.forEach(e => {
      galStmt.run(crypto.randomUUID(), e.title, e.description, e.category, e.event_date, e.image_url, e.file_size_bytes);
    });
    console.log('[AJ Klasses RMS] Seeded initial events in Events Gallery.');
  }
})();

// ============================================================
// RATE LIMITING MIDDLEWARE
// ============================================================

function checkRateLimit(action, maxAttempts, windowMinutes) {
  return function (req, res, next) {
    const rawIpHash = hashIp(req);
    const ipHash = `${action}:${rawIpHash}`;
    const now = Date.now();
    const windowMs = windowMinutes * 60 * 1000;

    const row = db.prepare('SELECT attempts, first_attempt FROM rate_limits WHERE ip_hash = ?').get(ipHash);

    if (!row) {
      db.prepare('INSERT INTO rate_limits (ip_hash, attempts, first_attempt, last_attempt) VALUES (?, 1, ?, ?)')
        .run(ipHash, now, now);
      return next();
    }

    if (now - row.first_attempt > windowMs) {
      db.prepare('UPDATE rate_limits SET attempts = 1, first_attempt = ?, last_attempt = ? WHERE ip_hash = ?')
        .run(now, now, ipHash);
      return next();
    }

    if (row.attempts >= maxAttempts) {
      return res.status(429).json({
        success: false,
        message: 'Too many requests. Please wait a few moments before trying again or contact the institute desk.'
      });
    }

    db.prepare('UPDATE rate_limits SET attempts = attempts + 1, last_attempt = ? WHERE ip_hash = ?')
      .run(now, ipHash);
    next();
  };
}

// Clean up old rate limit logs periodically
setInterval(() => {
  const oneHourAgo = Date.now() - 3600 * 1000;
  db.prepare('DELETE FROM rate_limits WHERE last_attempt < ?').run(oneHourAgo);
}, 15 * 60 * 1000);

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Unauthorized. Please log in.' });
  }

  const token = authHeader.split(' ')[1];
  const session = adminSessions.get(token);

  if (!session || session.expiresAt < Date.now()) {
    adminSessions.delete(token);
    return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
  }

  req.adminUser = session.user;
  next();
}

// ✅ SECURITY (Phase 3): Multi-Role RBAC Middleware
// Roles: 'super_admin' (all permissions), 'counselor' (admissions), 'teacher' (attendance & results)
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    requireAdmin(req, res, () => {
      const userRole = req.adminUser.role || 'super_admin';
      if (userRole === 'super_admin' || allowedRoles.includes(userRole)) {
        return next();
      }
      return res.status(403).json({
        success: false,
        message: `Access denied. Role "${userRole}" is not authorized for this resource.`
      });
    });
  };
}


// ============================================================
// MODULE 1: ADMISSIONS PORTAL (PUBLIC & ADMIN)
// ============================================================

/**
 * POST /api/admissions/apply
 * Public submission of admission application
 */
app.post('/api/admissions/apply', checkRateLimit('admission_apply', 15, 15), (req, res) => {
  const {
    student_name,
    parent_name,
    contact_number,
    email,
    desired_class,
    board,
    medium,
    academic_session,
    desired_course,
    previous_school,
    message
  } = req.body;

  // Validation
  if (!student_name || !parent_name || !contact_number || !desired_class || !academic_session || !desired_course) {
    return res.status(400).json({
      success: false,
      message: 'Please complete all required fields (Student Name, Parent Name, Mobile Number, Class, Session, Course).'
    });
  }

  const cleanedPhone = contact_number.replace(/\D/g, '');
  if (cleanedPhone.length < 10 || cleanedPhone.length > 12) {
    return res.status(400).json({
      success: false,
      message: 'Please provide a valid Indian contact number (10 digits).'
    });
  }

  // Prevent duplicate submissions within last 5 minutes for identical phone & student
  const recentCheck = db.prepare(`
    SELECT app_ref_number FROM admission_applications
    WHERE contact_number = ? AND LOWER(TRIM(student_name)) = LOWER(TRIM(?))
      AND created_at >= datetime('now', '-5 minutes')
  `).get(cleanedPhone, student_name);

  if (recentCheck) {
    return res.status(400).json({
      success: false,
      message: `An application was already submitted recently for this student (Ref: ${recentCheck.app_ref_number}). Our counsellor will contact you shortly.`
    });
  }

  // Generate unique application reference: AJ-ADM-YYYY-XXXX
  // SECURITY: Use crypto.randomInt() instead of Math.random() for unpredictable reference numbers
  const randomSuffix = crypto.randomInt(1000, 9999);
  const yearShort = new Date().getFullYear();
  const appRef = `AJ-ADM-${yearShort}-${randomSuffix}`;
  const appId = crypto.randomUUID();

  db.prepare(`
    INSERT INTO admission_applications (
      id, app_ref_number, student_name, parent_name, contact_number, email, desired_class,
      board, medium, academic_session, desired_course, previous_school, message, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
  `).run(
    appId,
    appRef,
    student_name.trim(),
    parent_name.trim(),
    cleanedPhone,
    (email || '').trim().toLowerCase(),
    desired_class.trim(),
    (board || 'CBSE').trim(),
    (medium || 'English').trim(),
    academic_session.trim(),
    desired_course.trim(),
    (previous_school || '').trim(),
    (message || '').trim()
  );

  res.json({
    success: true,
    message: 'Admission application submitted successfully! Your application reference number has been generated.',
    appRefNumber: appRef
  });
});

/**
 * GET /api/admissions/status
 * Safe public tracking by reference number (returns only minimum non-sensitive status)
 */
app.get('/api/admissions/status', checkRateLimit('admission_status', 20, 15), (req, res) => {
  const ref = (req.query.ref || '').trim().toUpperCase();
  if (!ref) {
    return res.status(400).json({ success: false, message: 'Application reference number is required.' });
  }

  const appRecord = db.prepare(`
    SELECT app_ref_number, desired_class, desired_course, academic_session, status, created_at, linked_student_id, verification_hash
    FROM admission_applications
    WHERE app_ref_number = ?
  `).get(ref);

  if (!appRecord) {
    return res.status(404).json({
      success: false,
      message: 'No admission application found with this reference number. Please verify or contact the institute.'
    });
  }

  let rollNumber = null;
  let verificationHash = appRecord.verification_hash || null;
  let studentName = null;

  if (appRecord.status === 'Approved' && appRecord.linked_student_id) {
    const student = db.prepare('SELECT roll_number, student_name, verification_hash FROM students WHERE id = ?').get(appRecord.linked_student_id);
    if (student) {
      rollNumber = student.roll_number;
      studentName = student.student_name;
      verificationHash = verificationHash || student.verification_hash;
    }
  }

  res.json({
    success: true,
    data: {
      refNumber: appRecord.app_ref_number,
      desiredClass: appRecord.desired_class,
      course: appRecord.desired_course,
      session: appRecord.academic_session,
      status: appRecord.status,
      submittedDate: appRecord.created_at,
      rollNumber,
      studentName,
      verificationHash
    }
  });
});

/**
 * Admin: Get all admission applications
 */
app.get('/api/admin/admissions', requireAdmin, (req, res) => {
  const statusFilter = req.query.status;
  let query = 'SELECT * FROM admission_applications';
  let params = [];

  if (statusFilter && statusFilter !== 'all') {
    query += ' WHERE status = ?';
    params.push(statusFilter);
  }
  query += ' ORDER BY created_at DESC';

  const applications = db.prepare(query).all(...params);
  res.json({ success: true, applications });
});

/**
 * Admin: Approve Application (Idempotent: Creates student record + generates Roll No & Security Verification Hash + Dispatches WhatsApp/Email)
 */
app.post('/api/admin/admissions/:id/approve', requireAdmin, (req, res) => {
  const appId = req.params.id;
  const { roll_number, class_name, section, academic_year, admin_remarks, link_student_id } = req.body;

  const application = db.prepare('SELECT * FROM admission_applications WHERE id = ?').get(appId);
  if (!application) {
    return res.status(404).json({ success: false, message: 'Application not found.' });
  }

  // Idempotency check: If already approved and linked, do not create duplicate
  if (application.status === 'Approved' && application.linked_student_id) {
    const existingStudent = db.prepare('SELECT * FROM students WHERE id = ?').get(application.linked_student_id);
    const existingHash = application.verification_hash || existingStudent?.verification_hash || 'AJ-VERIFIED';
    const notification = buildAdmissionNotification(existingStudent, existingHash);
    return res.json({
      success: true,
      message: 'This application has already been approved and credentials dispatched.',
      student: existingStudent,
      notification
    });
  }

  let finalStudentId;
  const targetClass = class_name || application.desired_class;
  const targetYear = academic_year || application.academic_session;
  const targetSection = (section || 'A').toUpperCase();

  if (link_student_id) {
    // Link to an existing student
    const existing = db.prepare('SELECT id FROM students WHERE id = ?').get(link_student_id);
    if (!existing) {
      return res.status(400).json({ success: false, message: 'Specified student record to link does not exist.' });
    }
    finalStudentId = existing.id;
    db.prepare("UPDATE students SET enrollment_status = 'Active' WHERE id = ?").run(finalStudentId);
  } else {
    // Generate or use provided roll number
    let targetRoll = (roll_number || '').trim().toUpperCase();
    if (!targetRoll) {
      const randomRollNum = Math.floor(100 + Math.random() * 900);
      targetRoll = `AJ-${targetYear.split('-')[0]}-${randomRollNum}`;
    }

    // Check roll number collision
    const collision = db.prepare(`
      SELECT id FROM students WHERE roll_number = ? AND class_name = ? AND academic_year = ?
    `).get(targetRoll, targetClass, targetYear);

    if (collision) {
      return res.status(400).json({
        success: false,
        message: `Roll Number "${targetRoll}" is already assigned to a student in ${targetClass} (${targetYear}). Please specify a unique roll number.`
      });
    }

    finalStudentId = crypto.randomUUID();
    db.prepare(`
      INSERT INTO students (
        id, roll_number, student_name, class_name, section, academic_year,
        enrollment_status, parent_name, contact_number, email, admission_app_id
      ) VALUES (?, ?, ?, ?, ?, ?, 'Active', ?, ?, ?, ?)
    `).run(
      finalStudentId,
      targetRoll,
      application.student_name,
      targetClass,
      targetSection,
      targetYear,
      application.parent_name,
      application.contact_number,
      application.email,
      appId
    );
  }

  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(finalStudentId);

  // Generate cryptographic verification hash code for the student
  const verificationHash = generateVerificationHashCode(finalStudentId, student.roll_number);

  // Update student and admission record with the verification hash
  db.prepare('UPDATE students SET verification_hash = ? WHERE id = ?').run(verificationHash, finalStudentId);

  db.prepare(`
    UPDATE admission_applications
    SET status = 'Approved', linked_student_id = ?, verification_hash = ?, notification_dispatched_at = CURRENT_TIMESTAMP, admin_remarks = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(finalStudentId, verificationHash, admin_remarks || 'Approved and enrolled.', appId);

  // Generate WhatsApp and Email notification payload
  const notification = buildAdmissionNotification(student, verificationHash);

  // Record dispatch in admission_notifications log
  try {
    db.prepare(`
      INSERT INTO admission_notifications (
        id, admission_id, student_id, student_name, roll_number, contact_number, email, verification_hash, channel, message_content, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Dispatched')
    `).run(
      crypto.randomUUID(),
      appId,
      finalStudentId,
      student.student_name,
      student.roll_number,
      student.contact_number,
      student.email,
      verificationHash,
      student.email ? 'both' : 'whatsapp',
      notification.message
    );
  } catch (e) {
    console.error('[Notification Log Error]', e.message);
  }

  logAudit(req.adminUser.username, 'APPROVE_ADMISSION', 'admission_applications', appId, {
    studentId: finalStudentId,
    class: targetClass,
    rollNumber: student.roll_number,
    verificationHash
  });

  res.json({
    success: true,
    message: `Application approved! Student enrolled with Roll Number: ${student.roll_number} and Security Verification Hash: ${verificationHash}.`,
    student: {
      ...student,
      verification_hash: verificationHash
    },
    notification
  });
});

/**
 * Admin: Resend Roll Number & Verification Hash via WhatsApp / Email
 */
app.post('/api/admin/admissions/:id/resend-credentials', requireAdmin, (req, res) => {
  const appId = req.params.id;
  const application = db.prepare('SELECT * FROM admission_applications WHERE id = ?').get(appId);
  if (!application) {
    return res.status(404).json({ success: false, message: 'Application not found.' });
  }

  if (application.status !== 'Approved' || !application.linked_student_id) {
    return res.status(400).json({ success: false, message: 'Only approved applications have student credentials to send.' });
  }

  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(application.linked_student_id);
  if (!student) {
    return res.status(404).json({ success: false, message: 'Linked student record not found.' });
  }

  const hash = application.verification_hash || student.verification_hash || generateVerificationHashCode(student.id, student.roll_number);
  const notification = buildAdmissionNotification(student, hash);

  try {
    db.prepare(`
      INSERT INTO admission_notifications (
        id, admission_id, student_id, student_name, roll_number, contact_number, email, verification_hash, channel, message_content, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Resent')
    `).run(
      crypto.randomUUID(), appId, student.id, student.student_name, student.roll_number,
      student.contact_number, student.email, hash,
      student.email ? 'both' : 'whatsapp', notification.message
    );
  } catch (e) {}

  res.json({
    success: true,
    message: `Credentials prepared for Roll Number: ${student.roll_number}! WhatsApp message generated.`,
    notification
  });
});

/**
 * Admin: Reject Application
 */
app.post('/api/admin/admissions/:id/reject', requireAdmin, (req, res) => {
  const appId = req.params.id;
  const { admin_remarks } = req.body;

  db.prepare(`
    UPDATE admission_applications
    SET status = 'Rejected', admin_remarks = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(admin_remarks || 'Application rejected by administration.', appId);

  logAudit(req.adminUser.username, 'REJECT_ADMISSION', 'admission_applications', appId, { remarks: admin_remarks });

  res.json({ success: true, message: 'Application rejected.' });
});

// ============================================================
// MODULE 2: ATTENDANCE PORTAL (PUBLIC & ADMIN)
// ============================================================

/**
 * POST /api/attendance/lookup
 * Student-facing attendance lookup (ONLY Roll Number & Student Name)
 */
app.post('/api/attendance/lookup', checkRateLimit('attendance_lookup', 30, 15), (req, res) => {
  const rollNumber = (req.body.rollNumber || '').trim().toUpperCase();
  const studentName = (req.body.studentName || '').trim().toLowerCase();

  if (!rollNumber || !studentName) {
    return res.status(400).json({
      success: false,
      message: "We couldn't verify these details or attendance records are not currently available. Please check the information or contact the institute."
    });
  }

  const student = db.prepare(`
    SELECT id, roll_number, student_name, class_name, section, academic_year, enrollment_status
    FROM students
    WHERE UPPER(TRIM(roll_number)) = ?
      AND LOWER(TRIM(student_name)) = ?
      AND enrollment_status = 'Active'
    LIMIT 1
  `).get(rollNumber, studentName);

  if (!student) {
    return res.status(404).json({
      success: false,
      message: "We couldn't verify these details or attendance records are not currently available. Please check the information or contact the institute."
    });
  }

  // Fetch all attendance records
  const records = db.prepare(`
    SELECT ar.status, ar.remarks, s.session_date, s.subject_name
    FROM attendance_records ar
    JOIN attendance_sessions s ON s.id = ar.session_id
    WHERE ar.student_id = ?
    ORDER BY s.session_date DESC
  `).all(student.id);

  let totalSessions = records.length;
  let presentCount = 0;
  let absentCount = 0;
  let lateCount = 0;
  let leaveCount = 0;

  records.forEach(r => {
    if (r.status === 'Present') presentCount++;
    else if (r.status === 'Absent') absentCount++;
    else if (r.status === 'Late') lateCount++;
    else if (r.status === 'Leave') leaveCount++;
  });

  // Calculate percentage based on documented standard formula:
  // (Present + 0.5 * Late + 0.5 * Leave) / Total * 100
  let percentage = 0;
  if (totalSessions > 0) {
    percentage = Number((((presentCount + lateCount * 0.5 + leaveCount * 0.5) / totalSessions) * 100).toFixed(2));
  }

  res.json({
    success: true,
    data: {
      student: {
        student_name: student.student_name,
        roll_number: student.roll_number,
        class_name: student.class_name,
        section: student.section,
        academic_year: student.academic_year
      },
      summary: {
        total_sessions: totalSessions,
        present_count: presentCount,
        absent_count: absentCount,
        late_count: lateCount,
        leave_count: leaveCount,
        attendance_percentage: percentage,
        formula_explanation: 'Attendance Percentage is calculated as: (Present + 0.5 × Late + 0.5 × Approved Leave) ÷ Total Sessions × 100.'
      },
      records: records.map(r => ({
        date: r.session_date,
        subject: r.subject_name,
        status: r.status,
        remarks: r.remarks || ''
      }))
    }
  });
});

/**
 * Admin: Fetch eligible students to mark attendance for a class
 */
app.get('/api/admin/attendance/eligible-students', requireAdmin, (req, res) => {
  const { class_name, section, academic_year } = req.query;
  if (!class_name) {
    return res.status(400).json({ success: false, message: 'Class name is required.' });
  }

  let query = "SELECT id, roll_number, student_name, class_name, section FROM students WHERE enrollment_status = 'Active' AND class_name = ?";
  let params = [class_name];

  if (section) {
    query += ' AND section = ?';
    params.push(section);
  }
  if (academic_year) {
    query += ' AND academic_year = ?';
    params.push(academic_year);
  }
  query += ' ORDER BY roll_number ASC';

  const students = db.prepare(query).all(...params);
  res.json({ success: true, students });
});

/**
 * Admin: Record attendance for a class session
 */
app.post('/api/admin/attendance/record', requireAdmin, (req, res) => {
  const { session_date, class_name, section, subject_name, academic_year, records } = req.body;

  if (!session_date || !class_name || !records || !Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ success: false, message: 'Date, class, and attendance entries are required.' });
  }

  const sec = (section || 'A').toUpperCase();
  const sub = subject_name || 'Regular Lecture';
  const year = academic_year || '2024-25';

  // Check if session exists or create one
  let session = db.prepare(`
    SELECT id FROM attendance_sessions
    WHERE session_date = ? AND class_name = ? AND section = ? AND subject_name = ? AND academic_year = ?
  `).get(session_date, class_name, sec, sub, year);

  let sessionId;
  if (session) {
    sessionId = session.id;
  } else {
    sessionId = crypto.randomUUID();
    db.prepare(`
      INSERT INTO attendance_sessions (id, session_date, class_name, section, subject_name, academic_year, recorded_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(sessionId, session_date, class_name, sec, sub, year, req.adminUser.full_name || req.adminUser.username);
  }

  // Upsert attendance records transactionally
  let recordedCount = 0;
  for (const item of records) {
    if (!item.student_id || !item.status) continue;

    const existingRecord = db.prepare(`
      SELECT id FROM attendance_records WHERE session_id = ? AND student_id = ?
    `).get(sessionId, item.student_id);

    if (existingRecord) {
      db.prepare(`
        UPDATE attendance_records
        SET status = ?, remarks = ?
        WHERE id = ?
      `).run(item.status, item.remarks || '', existingRecord.id);
    } else {
      db.prepare(`
        INSERT INTO attendance_records (id, session_id, student_id, status, remarks)
        VALUES (?, ?, ?, ?, ?)
      `).run(crypto.randomUUID(), sessionId, item.student_id, item.status, item.remarks || '');
    }
    recordedCount++;
  }

  logAudit(req.adminUser.username, 'RECORD_ATTENDANCE', 'attendance_sessions', sessionId, {
    class: class_name,
    date: session_date,
    count: recordedCount
  });

  res.json({
    success: true,
    message: `Attendance recorded successfully for ${recordedCount} students.`
  });
});

// ============================================================
// MODULE 3: STUDENT ACADEMIC HISTORY PORTAL
// ============================================================

/**
 * POST /api/history/lookup
 * Complete Academic & Attendance History (ONLY Roll Number & Student Name)
 */
app.post('/api/history/lookup', checkRateLimit('history_lookup', 30, 15), (req, res) => {
  const rollNumber = (req.body.rollNumber || '').trim().toUpperCase();
  const studentName = (req.body.studentName || '').trim().toLowerCase();

  if (!rollNumber || !studentName) {
    return res.status(400).json({
      success: false,
      message: "We couldn't verify these details or student history is not available. Please check the information or contact the institute."
    });
  }

  const student = db.prepare(`
    SELECT id, roll_number, student_name, class_name, section, academic_year, enrollment_status,
           parent_name, admission_app_id, created_at
    FROM students
    WHERE UPPER(TRIM(roll_number)) = ?
      AND LOWER(TRIM(student_name)) = ?
    LIMIT 1
  `).get(rollNumber, studentName);

  if (!student) {
    return res.status(404).json({
      success: false,
      message: "We couldn't verify these details or student history is not available. Please check the information or contact the institute."
    });
  }

  // 1. Fetch Admission / Enrollment Origin
  let admissionDetails = null;
  if (student.admission_app_id) {
    const appData = db.prepare(`
      SELECT app_ref_number, board, medium, desired_course, created_at
      FROM admission_applications WHERE id = ?
    `).get(student.admission_app_id);
    if (appData) {
      admissionDetails = {
        refNumber: appData.app_ref_number,
        board: appData.board,
        medium: appData.medium,
        course: appData.desired_course,
        enrolledDate: appData.created_at
      };
    }
  }

  // 2. Fetch All Published Examination Results
  const results = db.prepare(`
    SELECT r.id, r.publication_date, r.teacher_remarks, e.exam_name, e.academic_year
    FROM results r
    JOIN exams e ON e.id = r.exam_id
    WHERE r.student_id = ? AND r.is_published = 1 AND e.is_published = 1
    ORDER BY r.created_at DESC
  `).all(student.id);

  const academicHistory = results.map(resRow => {
    const subjects = db.prepare(`
      SELECT subject_name, marks_obtained, max_marks, passing_marks
      FROM result_subjects WHERE result_id = ?
    `).all(resRow.id);

    let totObtained = 0;
    let totMax = 0;
    subjects.forEach(s => {
      totObtained += s.marks_obtained;
      totMax += s.max_marks;
    });

    const pct = totMax > 0 ? Number(((totObtained / totMax) * 100).toFixed(2)) : 0;

    return {
      exam_name: resRow.exam_name,
      academic_year: resRow.academic_year,
      publication_date: resRow.publication_date,
      teacher_remarks: resRow.teacher_remarks,
      total_obtained: totObtained,
      total_max: totMax,
      percentage: pct,
      subjects: subjects.map(s => ({
        subject_name: s.subject_name,
        marks_obtained: s.marks_obtained,
        max_marks: s.max_marks,
        passing_marks: s.passing_marks,
        status: s.marks_obtained >= s.passing_marks ? 'PASS' : 'FAIL'
      }))
    };
  });

  // 3. Fetch Overall Attendance Records & Stats
  const attendanceRows = db.prepare(`
    SELECT ar.status, ar.remarks, s.session_date, s.subject_name
    FROM attendance_records ar
    JOIN attendance_sessions s ON s.id = ar.session_id
    WHERE ar.student_id = ?
    ORDER BY s.session_date DESC
  `).all(student.id);

  let totalSessions = attendanceRows.length;
  let presentCount = 0;
  let absentCount = 0;
  let lateCount = 0;
  let leaveCount = 0;

  attendanceRows.forEach(r => {
    if (r.status === 'Present') presentCount++;
    else if (r.status === 'Absent') absentCount++;
    else if (r.status === 'Late') lateCount++;
    else if (r.status === 'Leave') leaveCount++;
  });

  let attPercentage = totalSessions > 0
    ? Number((((presentCount + lateCount * 0.5 + leaveCount * 0.5) / totalSessions) * 100).toFixed(2))
    : 0;

  const hasHistory = academicHistory.length > 0 || totalSessions > 0;

  res.json({
    success: true,
    hasHistory: hasHistory,
    data: {
      profile: {
        student_name: student.student_name,
        roll_number: student.roll_number,
        class_name: student.class_name,
        section: student.section,
        academic_year: student.academic_year,
        enrollment_status: student.enrollment_status,
        parent_name: student.parent_name || '—',
        joined_date: student.created_at,
        admission_details: admissionDetails
      },
      academic_results: academicHistory,
      attendance: {
        total_sessions: totalSessions,
        present_count: presentCount,
        absent_count: absentCount,
        late_count: lateCount,
        leave_count: leaveCount,
        percentage: attPercentage,
        recent_sessions: attendanceRows.slice(0, 10).map(r => ({
          date: r.session_date,
          subject: r.subject_name,
          status: r.status
        }))
      }
    }
  });
});

// ============================================================
// MODULE 4: EXISTING RESULT PORTAL & EXAM MANAGEMENT
// ============================================================

/**
 * POST /api/results/lookup
 * (Strictly Preserved Existing Functionality)
 */
app.post('/api/results/lookup', checkRateLimit('lookup', 50, 15), (req, res) => {
  const rollNumber = (req.body.rollNumber || '').trim().toUpperCase();
  const studentName = (req.body.studentName || '').trim().toLowerCase();

  if (!rollNumber || !studentName || rollNumber.length > 50 || studentName.length > 150) {
    return res.status(400).json({
      success: false,
      message: "We couldn't verify these details or the result is not currently available. Please check the information or contact the institute."
    });
  }

  const student = db.prepare(`
    SELECT id, roll_number, student_name, class_name, section, academic_year, enrollment_status
    FROM students
    WHERE UPPER(TRIM(roll_number)) = ?
      AND LOWER(TRIM(student_name)) = ?
      AND enrollment_status = 'Active'
    LIMIT 1
  `).get(rollNumber, studentName);

  if (!student) {
    return res.status(404).json({
      success: false,
      message: "We couldn't verify these details or the result is not currently available. Please check the information or contact the institute."
    });
  }

  const result = db.prepare(`
    SELECT r.id AS result_id, r.publication_date, r.teacher_remarks,
           e.exam_name, e.academic_year AS exam_academic_year
    FROM results r
    JOIN exams e ON e.id = r.exam_id
    WHERE r.student_id = ?
      AND r.is_published = 1
      AND e.is_published = 1
    ORDER BY r.created_at DESC
    LIMIT 1
  `).get(student.id);

  if (!result) {
    return res.status(404).json({
      success: false,
      message: "We couldn't verify these details or the result is not currently available. Please check the information or contact the institute."
    });
  }

  const subjects = db.prepare(`
    SELECT subject_name, marks_obtained, max_marks, passing_marks
    FROM result_subjects
    WHERE result_id = ?
    ORDER BY subject_name ASC
  `).all(result.result_id);

  let totalObtained = 0;
  let totalMax = 0;
  let hasFailed = false;

  const formattedSubjects = subjects.map(sub => {
    totalObtained += sub.marks_obtained;
    totalMax += sub.max_marks;
    const isPassed = sub.marks_obtained >= sub.passing_marks;
    if (!isPassed) hasFailed = true;

    return {
      subject_name: sub.subject_name,
      marks_obtained: sub.marks_obtained,
      max_marks: sub.max_marks,
      passing_marks: sub.passing_marks,
      status: isPassed ? 'PASS' : 'FAIL'
    };
  });

  const percentage = totalMax > 0 ? Number(((totalObtained / totalMax) * 100).toFixed(2)) : 0;

  let overallStatus = 'PASSED';
  if (hasFailed) {
    overallStatus = 'NEEDS IMPROVEMENT';
  } else if (percentage >= 75.0) {
    overallStatus = 'PASSED WITH DISTINCTION';
  } else if (percentage >= 60.0) {
    overallStatus = 'PASSED (FIRST DIVISION)';
  }

  res.json({
    success: true,
    data: {
      institute: {
        name: 'AJ Klasses',
        address: 'Tulsi Nagar, Behind Diamond Hotel, Orai, Jalaun District, Uttar Pradesh — 285001',
        phone: '+91 63940 43659',
        email: 'pariharrishi777@gmail.com',
        directors: 'Dr. Ajay Rathour & Abhishek Rathour'
      },
      student: {
        student_name: student.student_name,
        roll_number: student.roll_number,
        class_name: student.class_name,
        section: student.section || 'A',
        academic_year: student.academic_year
      },
      examination: {
        exam_name: result.exam_name,
        academic_year: result.exam_academic_year,
        publication_date: result.publication_date || new Date().toISOString().split('T')[0]
      },
      subjects: formattedSubjects,
      summary: {
        total_obtained: totalObtained,
        total_max: totalMax,
        percentage: percentage,
        overall_status: overallStatus,
        teacher_remarks: result.teacher_remarks || 'Consistent academic discipline observed.'
      }
    }
  });
});

// Admin Authentication Endpoints
// ✅ SECURITY (Phase 1): Brute-Force Lockout — 5 wrong attempts = 30 min IP block
app.post('/api/admin/login', checkRateLimit('admin_login', 20, 15), (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Please enter both username and password.' });
  }

  // --- BRUTE FORCE CHECK ---
  const ipHash = hashIp(req);
  const bfEntry = bruteForceMap.get(ipHash);
  const now = Date.now();

  if (bfEntry && bfEntry.lockedUntil && bfEntry.lockedUntil > now) {
    const minutesLeft = Math.ceil((bfEntry.lockedUntil - now) / 60000);
    return res.status(429).json({
      success: false,
      message: `Too many failed login attempts. Admin access locked for ${minutesLeft} more minute(s). Contact institute if this is an error.`
    });
  }
  // --- END BRUTE FORCE CHECK ---

  const user = db.prepare('SELECT * FROM admin_users WHERE LOWER(username) = LOWER(?)').get(username.trim());

  if (!user || !verifyPassword(password, user.salt, user.password_hash)) {
    // ✅ Record failed attempt in brute-force tracker
    const existing = bruteForceMap.get(ipHash) || { count: 0, lockedUntil: null };
    existing.count += 1;
    if (existing.count >= BRUTE_FORCE_MAX_ATTEMPTS) {
      existing.lockedUntil = now + BRUTE_FORCE_LOCKOUT_MS;
      blockIp(ipHash, 'Exceeded maximum failed admin login attempts (Brute Force Lockout)', 1);
      recordSecurityEvent(ipHash, 'ADMIN_BRUTE_FORCE_LOCKOUT', req, `5 failed attempts for username: ${username}`);
      console.warn(`[SECURITY] Brute-force lockout triggered for IP hash: ${ipHash.slice(0, 12)}...`);
    } else {
      recordSecurityEvent(ipHash, 'ADMIN_LOGIN_FAILED', req, `Failed attempt (${existing.count}/${BRUTE_FORCE_MAX_ATTEMPTS}) for username: ${username}`);
    }
    bruteForceMap.set(ipHash, existing);

    const attemptsLeft = Math.max(0, BRUTE_FORCE_MAX_ATTEMPTS - existing.count);
    return res.status(401).json({
      success: false,
      message: attemptsLeft > 0
        ? `Invalid administrative credentials. ${attemptsLeft} attempt(s) remaining before lockout.`
        : 'Admin access locked for 30 minutes due to repeated failures.'
    });
  }

  // ✅ Successful login — clear brute-force counter for this IP
  bruteForceMap.delete(ipHash);

  const token = crypto.randomBytes(32).toString('hex');
  const sessionDurationMs = 8 * 60 * 60 * 1000; // 8 hours

  adminSessions.set(token, {
    user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role },
    expiresAt: now + sessionDurationMs
  });

  console.log(`[Audit] Admin login SUCCESS: user="${user.username}" at ${new Date().toISOString()}`);

  res.json({
    success: true,
    token,
    user: { username: user.username, full_name: user.full_name, role: user.role }
  });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    adminSessions.delete(token);
  }
  res.json({ success: true, message: 'Logged out successfully.' });
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({ success: true, user: req.adminUser });
});

// Admin Dashboard Summary
app.get('/api/admin/dashboard', requireAdmin, (req, res) => {
  const totalStudents = db.prepare("SELECT COUNT(*) as count FROM students WHERE enrollment_status = 'Active'").get().count;
  const totalExams = db.prepare('SELECT COUNT(*) as count FROM exams').get().count;
  const publishedResults = db.prepare('SELECT COUNT(*) as count FROM results WHERE is_published = 1').get().count;
  const draftResults = db.prepare('SELECT COUNT(*) as count FROM results WHERE is_published = 0').get().count;
  const pendingAdmissions = db.prepare("SELECT COUNT(*) as count FROM admission_applications WHERE status = 'Pending'").get().count;
  const totalAttendanceSessions = db.prepare('SELECT COUNT(*) as count FROM attendance_sessions').get().count;
  const totalTeachers = db.prepare('SELECT COUNT(*) as count FROM teachers').get().count;
  const galleryStorage = getGalleryStorageUsage();

  const recentResults = db.prepare(`
    SELECT r.id, s.student_name, s.roll_number, s.class_name, e.exam_name, r.is_published, r.updated_at
    FROM results r
    JOIN students s ON s.id = r.student_id
    JOIN exams e ON e.id = r.exam_id
    ORDER BY r.updated_at DESC
    LIMIT 6
  `).all();

  const recentAdmissions = db.prepare(`
    SELECT id, app_ref_number, student_name, desired_class, desired_course, status, created_at
    FROM admission_applications
    ORDER BY created_at DESC
    LIMIT 5
  `).all();

  res.json({
    success: true,
    metrics: {
      totalStudents,
      totalExams,
      publishedResults,
      draftResults,
      pendingAdmissions,
      totalAttendanceSessions,
      totalTeachers,
      galleryCount: galleryStorage.count,
      galleryUsedFormatted: galleryStorage.usedFormatted
    },
    recentResults,
    recentAdmissions
  });
});

// Admin Students CRUD
app.get('/api/admin/students', requireAdmin, (req, res) => {
  const students = db.prepare('SELECT * FROM students ORDER BY class_name ASC, roll_number ASC').all();
  res.json({ success: true, students });
});

app.post('/api/admin/students', requireAdmin, (req, res) => {
  const { roll_number, student_name, class_name, section, academic_year, parent_name, contact_number, email } = req.body;

  if (!roll_number || !student_name || !class_name || !academic_year) {
    return res.status(400).json({ success: false, message: 'All required student fields must be provided.' });
  }

  const existing = db.prepare(`
    SELECT id FROM students WHERE UPPER(TRIM(roll_number)) = ? AND class_name = ? AND academic_year = ?
  `).get(roll_number.trim().toUpperCase(), class_name.trim(), academic_year.trim());

  if (existing) {
    return res.status(400).json({
      success: false,
      message: `Roll Number "${roll_number}" already exists for ${class_name} (${academic_year}).`
    });
  }

  const id = crypto.randomUUID();
  db.prepare(`
    INSERT INTO students (id, roll_number, student_name, class_name, section, academic_year, enrollment_status, parent_name, contact_number, email)
    VALUES (?, ?, ?, ?, ?, ?, 'Active', ?, ?, ?)
  `).run(
    id,
    roll_number.trim().toUpperCase(),
    student_name.trim(),
    class_name.trim(),
    (section || 'A').trim().toUpperCase(),
    academic_year.trim(),
    (parent_name || '').trim(),
    (contact_number || '').trim(),
    (email || '').trim().toLowerCase()
  );

  res.json({ success: true, message: 'Student created successfully.', id });
});

app.put('/api/admin/students/:id', requireAdmin, (req, res) => {
  const { roll_number, student_name, class_name, section, academic_year, enrollment_status, parent_name, contact_number, email } = req.body;
  const studentId = req.params.id;

  db.prepare(`
    UPDATE students
    SET roll_number = ?, student_name = ?, class_name = ?, section = ?, academic_year = ?,
        enrollment_status = COALESCE(?, enrollment_status), parent_name = ?, contact_number = ?, email = ?
    WHERE id = ?
  `).run(
    roll_number.trim().toUpperCase(),
    student_name.trim(),
    class_name.trim(),
    (section || 'A').trim().toUpperCase(),
    academic_year.trim(),
    enrollment_status,
    (parent_name || '').trim(),
    (contact_number || '').trim(),
    (email || '').trim().toLowerCase(),
    studentId
  );

  res.json({ success: true, message: 'Student updated successfully.' });
});

app.delete('/api/admin/students/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM students WHERE id = ?').run(req.params.id);
  res.json({ success: true, message: 'Student and associated records deleted.' });
});

// Admin Exams CRUD
app.get('/api/admin/exams', requireAdmin, (req, res) => {
  const exams = db.prepare('SELECT * FROM exams ORDER BY academic_year DESC, created_at DESC').all();
  res.json({ success: true, exams });
});

app.post('/api/admin/exams', requireAdmin, (req, res) => {
  const { exam_name, academic_year, target_classes, is_published } = req.body;
  if (!exam_name || !academic_year || !target_classes) {
    return res.status(400).json({ success: false, message: 'Exam name, academic year, and target classes are required.' });
  }

  const existing = db.prepare(`
    SELECT id FROM exams WHERE LOWER(TRIM(exam_name)) = ? AND academic_year = ?
  `).get(exam_name.trim().toLowerCase(), academic_year.trim());

  if (existing) {
    return res.status(400).json({
      success: false,
      message: `An examination named "${exam_name}" already exists for ${academic_year}.`
    });
  }

  const id = crypto.randomUUID();
  db.prepare(`
    INSERT INTO exams (id, exam_name, academic_year, target_classes, is_published)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, exam_name.trim(), academic_year.trim(), target_classes.trim(), is_published ? 1 : 0);

  res.json({ success: true, message: 'Examination created successfully.', id });
});

app.put('/api/admin/exams/:id', requireAdmin, (req, res) => {
  const { exam_name, academic_year, target_classes, is_published } = req.body;
  db.prepare(`
    UPDATE exams
    SET exam_name = ?, academic_year = ?, target_classes = ?, is_published = ?
    WHERE id = ?
  `).run(exam_name.trim(), academic_year.trim(), target_classes.trim(), is_published ? 1 : 0, req.params.id);

  res.json({ success: true, message: 'Examination updated successfully.' });
});

app.delete('/api/admin/exams/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM exams WHERE id = ?').run(req.params.id);
  res.json({ success: true, message: 'Examination deleted successfully.' });
});

// Notes Upload Directory & Multer configuration
const notesUploadsDir = path.join(__dirname, 'uploads', 'notes');
if (!fs.existsSync(notesUploadsDir)) {
  fs.mkdirSync(notesUploadsDir, { recursive: true });
}

const notesStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, notesUploadsDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.pdf';
    const safeExt = ['.pdf', '.jpg', '.jpeg', '.png', '.webp'].includes(ext) ? ext : '.pdf';
    cb(null, `note_${crypto.randomUUID()}${safeExt}`);
  }
});

const notesUpload = multer({
  storage: notesStorage,
  limits: { fileSize: 30 * 1024 * 1024 } // 30 MB max
});

// Admin Results CRUD
app.get('/api/admin/results', requireAdmin, (req, res) => {
  const results = db.prepare(`
    SELECT r.id, r.student_id, r.exam_id, r.is_published, r.publication_date, r.teacher_remarks,
           r.student_note_url, r.student_note_text,
           s.student_name, s.roll_number, s.class_name, s.section, e.exam_name, e.academic_year
    FROM results r
    JOIN students s ON s.id = r.student_id
    JOIN exams e ON e.id = r.exam_id
    ORDER BY s.class_name ASC, s.roll_number ASC
  `).all();

  const resultsWithSubjects = results.map(r => {
    const subjects = db.prepare('SELECT * FROM result_subjects WHERE result_id = ?').all(r.id);
    const total_obtained = subjects.reduce((sum, s) => sum + Number(s.marks_obtained || 0), 0);
    const total_max = subjects.reduce((sum, s) => sum + Number(s.max_marks || 0), 0);
    return { ...r, subjects, total_obtained, total_max };
  });

  res.json({ success: true, results: resultsWithSubjects });
});

app.get('/api/admin/results/:id', requireAdmin, (req, res) => {
  const resultId = req.params.id;
  const result = db.prepare(`
    SELECT r.id, r.student_id, r.exam_id, r.is_published, r.publication_date, r.teacher_remarks,
           r.student_note_url, r.student_note_text,
           s.student_name, s.roll_number, s.class_name, s.section, e.exam_name, e.academic_year
    FROM results r
    JOIN students s ON s.id = r.student_id
    JOIN exams e ON e.id = r.exam_id
    WHERE r.id = ?
  `).get(resultId);

  if (!result) return res.status(404).json({ success: false, message: 'Result not found.' });

  const subjects = db.prepare('SELECT * FROM result_subjects WHERE result_id = ?').all(resultId);
  res.json({ success: true, result: { ...result, subjects } });
});

app.post('/api/admin/results', requireAdmin, (req, res) => {
  let { student_id, exam_id, exam_name, is_published, publication_date, teacher_remarks, student_note_url, student_note_text, subjects } = req.body;

  // If exam_name is provided directly (user typed exam name), resolve or auto-create it
  if (!exam_id && exam_name && exam_name.trim()) {
    let exam = db.prepare('SELECT id FROM exams WHERE LOWER(TRIM(exam_name)) = LOWER(TRIM(?))').get(exam_name.trim());
    if (!exam) {
      const newExamId = crypto.randomUUID();
      const currentYear = new Date().getFullYear();
      const academicYear = `${currentYear}-${(currentYear + 1).toString().slice(-2)}`;
      db.prepare(`
        INSERT INTO exams (id, exam_name, academic_year, target_classes, is_published)
        VALUES (?, ?, ?, 'All Classes', 1)
      `).run(newExamId, exam_name.trim(), academicYear);
      exam = { id: newExamId };
    }
    exam_id = exam.id;
  }

  if (!student_id || !exam_id || !subjects || !Array.isArray(subjects) || subjects.length === 0) {
    return res.status(400).json({ success: false, message: 'Student, examination name, and subject marks are required.' });
  }

  for (const s of subjects) {
    if (Number(s.marks_obtained) > Number(s.max_marks)) {
      return res.status(400).json({
        success: false,
        message: `Marks obtained (${s.marks_obtained}) cannot exceed maximum marks (${s.max_marks}) for ${s.subject_name}.`
      });
    }
  }

  const existing = db.prepare('SELECT id FROM results WHERE student_id = ? AND exam_id = ?').get(student_id, exam_id);
  if (existing) {
    return res.status(400).json({
      success: false,
      message: 'A result already exists for this student and examination. Edit the existing record instead.'
    });
  }

  const resultId = crypto.randomUUID();
  const pubDate = is_published ? (publication_date || new Date().toISOString().split('T')[0]) : null;

  db.prepare(`
    INSERT INTO results (id, student_id, exam_id, is_published, publication_date, teacher_remarks, student_note_url, student_note_text)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(resultId, student_id, exam_id, is_published ? 1 : 0, pubDate, teacher_remarks || '', student_note_url || null, student_note_text || null);

  for (const sub of subjects) {
    db.prepare(`
      INSERT INTO result_subjects (id, result_id, subject_name, marks_obtained, max_marks, passing_marks)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      crypto.randomUUID(),
      resultId,
      sub.subject_name.trim(),
      Number(sub.marks_obtained),
      Number(sub.max_marks),
      Number(sub.passing_marks)
    );
  }

  res.json({ success: true, message: 'Result recorded successfully.', resultId });
});

app.put('/api/admin/results/:id', requireAdmin, (req, res) => {
  const resultId = req.params.id;
  let { exam_id, exam_name, is_published, publication_date, teacher_remarks, student_note_url, student_note_text, subjects } = req.body;
  const pubDate = is_published ? (publication_date || new Date().toISOString().split('T')[0]) : null;

  if (!exam_id && exam_name && exam_name.trim()) {
    let exam = db.prepare('SELECT id FROM exams WHERE LOWER(TRIM(exam_name)) = LOWER(TRIM(?))').get(exam_name.trim());
    if (!exam) {
      const newExamId = crypto.randomUUID();
      const currentYear = new Date().getFullYear();
      const academicYear = `${currentYear}-${(currentYear + 1).toString().slice(-2)}`;
      db.prepare(`
        INSERT INTO exams (id, exam_name, academic_year, target_classes, is_published)
        VALUES (?, ?, ?, 'All Classes', 1)
      `).run(newExamId, exam_name.trim(), academicYear);
      exam = { id: newExamId };
    }
    exam_id = exam.id;
  }

  const currentResult = db.prepare('SELECT * FROM results WHERE id = ?').get(resultId);
  if (!currentResult) return res.status(404).json({ success: false, message: 'Result not found.' });

  const finalExamId = exam_id || currentResult.exam_id;
  const finalNoteUrl = student_note_url !== undefined ? student_note_url : currentResult.student_note_url;
  const finalNoteText = student_note_text !== undefined ? student_note_text : currentResult.student_note_text;

  db.prepare(`
    UPDATE results
    SET exam_id = ?, is_published = ?, publication_date = ?, teacher_remarks = ?,
        student_note_url = ?, student_note_text = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(finalExamId, is_published ? 1 : 0, pubDate, teacher_remarks || '', finalNoteUrl, finalNoteText, resultId);

  if (subjects && Array.isArray(subjects) && subjects.length > 0) {
    for (const s of subjects) {
      if (Number(s.marks_obtained) > Number(s.max_marks)) {
        return res.status(400).json({
          success: false,
          message: `Marks obtained cannot exceed max marks for ${s.subject_name}.`
        });
      }
    }
    db.prepare('DELETE FROM result_subjects WHERE result_id = ?').run(resultId);
    for (const sub of subjects) {
      db.prepare(`
        INSERT INTO result_subjects (id, result_id, subject_name, marks_obtained, max_marks, passing_marks)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(crypto.randomUUID(), resultId, sub.subject_name.trim(), Number(sub.marks_obtained), Number(sub.max_marks), Number(sub.passing_marks));
    }
  }

  res.json({ success: true, message: 'Result updated successfully.' });
});

app.post('/api/admin/results/:id/note', requireAdmin, (req, res) => {
  notesUpload.single('note_file')(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message || 'Error processing file' });
    const resultId = req.params.id;
    const { note_text } = req.body;
    let noteUrl = null;
    if (req.file) {
      noteUrl = `/uploads/notes/${req.file.filename}`;
    }

    const current = db.prepare('SELECT * FROM results WHERE id = ?').get(resultId);
    if (!current) return res.status(404).json({ success: false, message: 'Result record not found.' });

    const finalUrl = noteUrl !== null ? noteUrl : current.student_note_url;
    const finalText = note_text !== undefined ? note_text : current.student_note_text;

    db.prepare(`
      UPDATE results
      SET student_note_url = ?, student_note_text = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(finalUrl, finalText, resultId);

    res.json({
      success: true,
      message: 'Student note and copy updated successfully!',
      note_url: finalUrl,
      note_text: finalText
    });
  });
});

app.post('/api/admin/upload-note', requireAdmin, (req, res) => {
  notesUpload.single('note_file')(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message || 'File upload error' });
    if (!req.file) return res.status(400).json({ success: false, message: 'Please select a note file to upload.' });
    const noteUrl = `/uploads/notes/${req.file.filename}`;
    res.json({ success: true, note_url: noteUrl, original_name: req.file.originalname });
  });
});

app.patch('/api/admin/results/:id/publish', requireAdmin, (req, res) => {
  const resultId = req.params.id;
  const { is_published } = req.body;
  const pubDate = is_published ? new Date().toISOString().split('T')[0] : null;

  db.prepare(`
    UPDATE results
    SET is_published = ?, publication_date = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(is_published ? 1 : 0, pubDate, resultId);

  res.json({
    success: true,
    message: is_published ? 'Result published successfully.' : 'Result returned to draft status.'
  });
});

app.delete('/api/admin/results/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM results WHERE id = ?').run(req.params.id);
  res.json({ success: true, message: 'Result deleted successfully.' });
});

// Admin Bulk CSV Import
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.csv', '.txt'];
    if (allowed.includes(ext) || file.mimetype.includes('csv') || file.mimetype.includes('text')) {
      cb(null, true);
    } else {
      cb(new Error('Only valid CSV files (.csv) are allowed for bulk import.'));
    }
  }
});

function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter(line => line.trim().length > 0);
  if (lines.length < 2) return [];

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/['"]/g, ''));
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].match(/(".*?"|[^",\s]+)(?=\s*,|\s*$)/g) || lines[i].split(',');
    const row = {};
    headers.forEach((h, index) => {
      let val = values[index] ? values[index].trim() : '';
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.substring(1, val.length - 1);
      }
      row[h] = val;
    });
    row.__rowNumber = i + 1;
    rows.push(row);
  }
  return rows;
}

app.post('/api/admin/bulk-import', requireAdmin, upload.single('csvFile'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Please upload a CSV file.' });
  }

  // SECURITY: Enforce file size and row count limits on CSV imports
  const MAX_CSV_SIZE = 2 * 1024 * 1024; // 2 MB
  const MAX_CSV_ROWS = 1000;
  if (req.file.size > MAX_CSV_SIZE) {
    return res.status(400).json({ success: false, message: 'CSV file exceeds the 2 MB limit.' });
  }

  const dryRun = req.query.dryRun === 'true' || req.body.dryRun === 'true';
  const csvContent = req.file.buffer.toString('utf-8');
  const rows = parseCSV(csvContent);

  if (rows.length === 0) {
    return res.status(400).json({ success: false, message: 'The uploaded file is empty or missing headers.' });
  }

  if (rows.length > MAX_CSV_ROWS) {
    return res.status(400).json({ success: false, message: `CSV exceeds the maximum of ${MAX_CSV_ROWS} rows. Please split the file.` });
  }

  const validationErrors = [];
  const validRecords = [];

  rows.forEach(r => {
    const rowNum = r.__rowNumber;
    const roll = (r.roll_number || r.roll || '').trim().toUpperCase();
    const name = (r.student_name || r.name || '').trim();
    const cls = (r.class || r.class_name || '').trim();
    const sec = (r.section || 'A').trim().toUpperCase();
    const year = (r.academic_year || r.year || '').trim();
    const exam = (r.exam_name || r.exam || '').trim();
    const sub = (r.subject || r.subject_name || '').trim();
    const obtained = parseFloat(r.marks_obtained);
    const max = parseFloat(r.max_marks);
    const pass = parseFloat(r.passing_marks || '33');
    const remarks = (r.teacher_remarks || r.remarks || '').trim();

    if (!roll || !name || !cls || !year || !exam || !sub || isNaN(obtained) || isNaN(max)) {
      validationErrors.push({
        row: rowNum,
        error: 'Missing required values (roll_number, student_name, class, academic_year, exam_name, subject, marks_obtained, max_marks).'
      });
      return;
    }

    if (obtained > max) {
      validationErrors.push({
        row: rowNum,
        error: `Marks obtained (${obtained}) cannot exceed maximum marks (${max}) for ${sub}.`
      });
      return;
    }

    validRecords.push({ rowNum, roll, name, cls, sec, year, exam, sub, obtained, max, pass, remarks });
  });

  if (dryRun) {
    return res.json({
      success: true,
      dryRun: true,
      totalRows: rows.length,
      validCount: validRecords.length,
      errorCount: validationErrors.length,
      errors: validationErrors,
      samplePreview: validRecords.slice(0, 10)
    });
  }

  if (validRecords.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'No valid records to import. Please review errors.',
      errors: validationErrors
    });
  }

  const resultMap = new Map();
  validRecords.forEach(rec => {
    const key = `${rec.roll}|${rec.cls}|${rec.year}|${rec.exam}`;
    if (!resultMap.has(key)) {
      resultMap.set(key, {
        roll: rec.roll,
        name: rec.name,
        cls: rec.cls,
        sec: rec.sec,
        year: rec.year,
        exam: rec.exam,
        remarks: rec.remarks,
        subjects: []
      });
    }
    resultMap.get(key).subjects.push({
      subject_name: rec.sub,
      marks_obtained: rec.obtained,
      max_marks: rec.max,
      passing_marks: rec.pass
    });
  });

  let importedStudents = 0;
  let importedResults = 0;

  for (const item of resultMap.values()) {
    let student = db.prepare('SELECT id FROM students WHERE roll_number = ? AND class_name = ? AND academic_year = ?')
      .get(item.roll, item.cls, item.year);

    let studentId;
    if (!student) {
      studentId = crypto.randomUUID();
      db.prepare(`
        INSERT INTO students (id, roll_number, student_name, class_name, section, academic_year, enrollment_status)
        VALUES (?, ?, ?, ?, ?, ?, 'Active')
      `).run(studentId, item.roll, item.name, item.cls, item.sec, item.year);
      importedStudents++;
    } else {
      studentId = student.id;
    }

    let exam = db.prepare('SELECT id FROM exams WHERE exam_name = ? AND academic_year = ?').get(item.exam, item.year);
    let examId;
    if (!exam) {
      examId = crypto.randomUUID();
      db.prepare(`
        INSERT INTO exams (id, exam_name, academic_year, target_classes, is_published)
        VALUES (?, ?, ?, ?, 0)
      `).run(examId, item.exam, item.year, item.cls);
    } else {
      examId = exam.id;
    }

    let result = db.prepare('SELECT id FROM results WHERE student_id = ? AND exam_id = ?').get(studentId, examId);
    let resultId;
    if (!result) {
      resultId = crypto.randomUUID();
      db.prepare(`
        INSERT INTO results (id, student_id, exam_id, is_published, publication_date, teacher_remarks)
        VALUES (?, ?, ?, 0, NULL, ?)
      `).run(resultId, studentId, examId, item.remarks || 'Imported via CSV');
      importedResults++;
    } else {
      resultId = result.id;
    }

    for (const sub of item.subjects) {
      const existingSub = db.prepare('SELECT id FROM result_subjects WHERE result_id = ? AND subject_name = ?')
        .get(resultId, sub.subject_name);

      if (existingSub) {
        db.prepare(`
          UPDATE result_subjects
          SET marks_obtained = ?, max_marks = ?, passing_marks = ?
          WHERE id = ?
        `).run(sub.marks_obtained, sub.max_marks, sub.passing_marks, existingSub.id);
      } else {
        db.prepare(`
          INSERT INTO result_subjects (id, result_id, subject_name, marks_obtained, max_marks, passing_marks)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(crypto.randomUUID(), resultId, sub.subject_name, sub.marks_obtained, sub.max_marks, sub.passing_marks);
      }
    }
  }

  res.json({
    success: true,
    message: `Bulk import completed! ${importedStudents} new students added, ${importedResults} results created/updated in Draft mode.`,
    errors: validationErrors
  });
});

// SECURITY: Require admin auth for sample-csv download
app.get('/api/admin/sample-csv', requireAdmin, (req, res) => {
  const sampleCSV = [
    'roll_number,student_name,class,section,academic_year,exam_name,subject,marks_obtained,max_marks,passing_marks,teacher_remarks',
    'AJ-2025-201,Ananya Gupta,Class 10,A,2024-25,Class 10 Pre-Board Assessment,Mathematics,95,100,33,Excellent problem solving',
    'AJ-2025-201,Ananya Gupta,Class 10,A,2024-25,Class 10 Pre-Board Assessment,Science,92,100,33,Excellent problem solving',
    'AJ-2025-201,Ananya Gupta,Class 10,A,2024-25,Class 10 Pre-Board Assessment,English,88,100,33,Good articulation'
  ].join('\r\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="AJ_Klasses_Results_Template.csv"');
  res.send(sampleCSV);
});

// ============================================================
// MODULE 5: TEACHERS / FACULTY DIRECTORY (PUBLIC & ADMIN)
// ============================================================

// Public Teachers Endpoint (Privacy protected — phone numbers masked)
app.get('/api/teachers', (req, res) => {
  try {
    const teachers = db.prepare('SELECT * FROM teachers ORDER BY display_order ASC, created_at ASC').all();
    const safeTeachers = teachers.map(t => ({
      ...t,
      phone: maskPhone(t.phone)
    }));
    res.json({
      success: true,
      count: safeTeachers.length,
      data: safeTeachers
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve teachers directory.' });
  }
});

// Admin Create Teacher
app.post('/api/admin/teachers', requireAdmin, (req, res) => {
  const { name, role, department, qualification, experience, phone, specialization, bio, photo_url } = req.body;
  if (!name || !qualification || !experience) {
    return res.status(400).json({ success: false, message: 'Please provide Teacher Name, Qualification, and Experience.' });
  }

  const id = crypto.randomUUID();
  const initials = name.split(' ').map(n => n[0]).filter(Boolean).slice(0, 2).join('').toUpperCase() || 'AJ';
  const countRow = db.prepare('SELECT COUNT(*) as c FROM teachers').get();
  const displayOrder = (countRow?.c || 0) + 1;

  db.prepare(`
    INSERT INTO teachers (id, name, role, department, qualification, experience, phone, specialization, bio, initials, photo_url, display_order)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, role || 'Faculty Mentor', department || 'General', qualification, experience, phone ? phone.trim() : null, specialization || '', bio || '', initials, photo_url || null, displayOrder);

  logAudit(req.adminUser.username, 'CREATE_TEACHER', 'teachers', id, { name, role });
  res.json({ success: true, message: 'Teacher added successfully.', id });
});

// Admin Update Teacher
app.put('/api/admin/teachers/:id', requireAdmin, (req, res) => {
  const teacherId = req.params.id;
  const { name, role, department, qualification, experience, phone, specialization, bio, photo_url } = req.body;

  const existing = db.prepare('SELECT id FROM teachers WHERE id = ?').get(teacherId);
  if (!existing) {
    return res.status(404).json({ success: false, message: 'Teacher not found.' });
  }

  const initials = name ? name.split(' ').map(n => n[0]).filter(Boolean).slice(0, 2).join('').toUpperCase() : 'AJ';

  db.prepare(`
    UPDATE teachers
    SET name = ?, role = ?, department = ?, qualification = ?, experience = ?, phone = ?, specialization = ?, bio = ?, initials = ?, photo_url = ?
    WHERE id = ?
  `).run(name, role, department, qualification, experience, phone ? phone.trim() : null, specialization, bio, initials, photo_url || null, teacherId);

  logAudit(req.adminUser.username, 'UPDATE_TEACHER', 'teachers', teacherId, { name });
  res.json({ success: true, message: 'Teacher details updated successfully.' });
});

// Admin Delete Teacher
app.delete('/api/admin/teachers/:id', requireAdmin, (req, res) => {
  const teacherId = req.params.id;
  db.prepare('DELETE FROM teachers WHERE id = ?').run(teacherId);
  logAudit(req.adminUser.username, 'DELETE_TEACHER', 'teachers', teacherId, {});
  res.json({ success: true, message: 'Teacher removed successfully.' });
});

// ============================================================
// MODULE 6: EVENTS GALLERY WITH 5 GB STORAGE TRACKING
// ============================================================

const TOTAL_STORAGE_QUOTA_BYTES = 5 * 1024 * 1024 * 1024; // 5 GB quota = 5,368,709,120 bytes
const galleryUploadsDir = path.join(__dirname, 'uploads', 'gallery');
if (!fs.existsSync(galleryUploadsDir)) {
  fs.mkdirSync(galleryUploadsDir, { recursive: true });
}

function getGalleryStorageUsage() {
  const row = db.prepare('SELECT COALESCE(SUM(file_size_bytes), 0) AS used_bytes, COUNT(*) AS count FROM gallery_events').get();
  const usedBytes = Number(row?.used_bytes || 0);
  const count = Number(row?.count || 0);
  const remainingBytes = Math.max(0, TOTAL_STORAGE_QUOTA_BYTES - usedBytes);
  const percentage = Math.min(100, Number(((usedBytes / TOTAL_STORAGE_QUOTA_BYTES) * 100).toFixed(2)));

  return {
    usedBytes,
    totalBytes: TOTAL_STORAGE_QUOTA_BYTES,
    remainingBytes,
    count,
    percentage,
    usedFormatted: (usedBytes / (1024 * 1024)).toFixed(2) + ' MB',
    totalFormatted: '5.00 GB',
    remainingFormatted: (remainingBytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
  };
}

const galleryStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, galleryUploadsDir);
  },
  filename: (req, file, cb) => {
    // SECURITY: Use UUID-based filenames to prevent path traversal and info leakage
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    const safeExt = ['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext) ? ext : '.jpg';
    cb(null, `event_${crypto.randomUUID()}${safeExt}`);
  }
});

const galleryUpload = multer({
  storage: galleryStorage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB single file max
  fileFilter: (req, file, cb) => {
    // SECURITY: SVG removed — SVG files can contain embedded JavaScript (stored XSS)
    const allowed = /jpeg|jpg|png|webp|gif/;
    const ext = path.extname(file.originalname).toLowerCase();
    const mime = file.mimetype;
    if (allowed.test(ext) && allowed.test(mime)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files (JPEG, PNG, WebP, GIF) are allowed.'));
    }
  }
});

// Public Gallery Feed
app.get('/api/gallery', (req, res) => {
  try {
    const category = req.query.category;
    let events;
    if (category && category !== 'all') {
      events = db.prepare('SELECT * FROM gallery_events WHERE category = ? ORDER BY event_date DESC, created_at DESC').all(category);
    } else {
      events = db.prepare('SELECT * FROM gallery_events ORDER BY event_date DESC, created_at DESC').all();
    }
    const storage = getGalleryStorageUsage();
    res.json({ success: true, count: events.length, data: events, storage });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve gallery events.' });
  }
});

// Admin Upload Event Photo with 5 GB Quota Check
app.post('/api/admin/gallery/upload', requireAdmin, (req, res) => {
  galleryUpload.single('image')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ success: false, message: err.message || 'Error processing image upload.' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Please select an event photo to upload.' });
    }

    const { title, category, event_date, description } = req.body;
    if (!title || !title.trim()) {
      try { fs.unlinkSync(req.file.path); } catch (e) {}
      return res.status(400).json({ success: false, message: 'Please enter an event title.' });
    }

    const currentUsage = getGalleryStorageUsage();
    const fileSize = req.file.size;

    if (currentUsage.usedBytes + fileSize > TOTAL_STORAGE_QUOTA_BYTES) {
      try { fs.unlinkSync(req.file.path); } catch (e) {}
      return res.status(400).json({
        success: false,
        message: `Storage quota exceeded! AJ Klasses gallery is allocated 5.0 GB total storage. Current usage is ${currentUsage.usedFormatted}. Please remove older media to free up space.`
      });
    }

    const id = crypto.randomUUID();
    const imageUrl = `/uploads/gallery/${req.file.filename}`;
    const evDate = (event_date && event_date.trim()) || new Date().toISOString().split('T')[0];
    const evCat = (category && category.trim()) || 'General Events';

    db.prepare(`
      INSERT INTO gallery_events (id, title, description, category, event_date, image_url, file_size_bytes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, title.trim(), (description || '').trim(), evCat, evDate, imageUrl, fileSize);

    logAudit(req.adminUser.username, 'UPLOAD_GALLERY_EVENT', 'gallery_events', id, { title, fileSize, category: evCat });

    const updatedStorage = getGalleryStorageUsage();
    res.json({
      success: true,
      message: 'Event photo uploaded successfully to AJ Klasses Gallery!',
      data: {
        id,
        title: title.trim(),
        category: evCat,
        event_date: evDate,
        image_url: imageUrl,
        file_size_bytes: fileSize
      },
      storage: updatedStorage
    });
  });
});

// Admin Delete Gallery Event
app.delete('/api/admin/gallery/:id', requireAdmin, (req, res) => {
  const eventId = req.params.id;
  const ev = db.prepare('SELECT * FROM gallery_events WHERE id = ?').get(eventId);
  if (!ev) {
    return res.status(404).json({ success: false, message: 'Event not found.' });
  }

  // Remove file from disk if uploaded in /uploads/gallery/
  if (ev.image_url && ev.image_url.startsWith('/uploads/gallery/')) {
    const filename = path.basename(ev.image_url);
    const diskPath = path.join(galleryUploadsDir, filename);
    if (fs.existsSync(diskPath)) {
      try {
        fs.unlinkSync(diskPath);
      } catch (err) {
        console.error('Error deleting file:', err);
      }
    }
  }

  db.prepare('DELETE FROM gallery_events WHERE id = ?').run(eventId);
  logAudit(req.adminUser.username, 'DELETE_GALLERY_EVENT', 'gallery_events', eventId, { title: ev.title });

  const updatedStorage = getGalleryStorageUsage();
  res.json({
    success: true,
    message: 'Gallery item deleted successfully and storage space freed.',
    storage: updatedStorage
  });
});

// ============================================================
// MODULE 7: INSTITUTE SECURITY & FIREWALL MANAGEMENT (ADMIN)
// ============================================================

// Admin Security Dashboard Stats
app.get('/api/admin/security/stats', requireAdmin, (req, res) => {
  try {
    const blockedCount = db.prepare("SELECT COUNT(*) AS count FROM ip_blocklist WHERE expires_at IS NULL OR expires_at > datetime('now')").get();
    const securityEventsCount = db.prepare("SELECT COUNT(*) AS count FROM security_events WHERE created_at >= datetime('now', '-24 hours')").get();
    const auditLogsCount = db.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE created_at >= datetime('now', '-24 hours')").get();
    const recentEvents = db.prepare("SELECT * FROM security_events ORDER BY created_at DESC LIMIT 15").all();

    // Check backup status
    const backupDir = path.join(__dirname, 'data', 'backups');
    let backupCount = 0;
    let latestBackup = null;
    if (fs.existsSync(backupDir)) {
      const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.db')).sort().reverse();
      backupCount = files.length;
      latestBackup = files[0] || null;
    }

    res.json({
      success: true,
      data: {
        activeBlockedIps: blockedCount ? blockedCount.count : 0,
        securityEvents24h: securityEventsCount ? securityEventsCount.count : 0,
        adminAuditLogs24h: auditLogsCount ? auditLogsCount.count : 0,
        totalBackups: backupCount,
        latestBackup,
        activeAdminSessions: adminSessions.size,
        recentSecurityEvents: recentEvents
      }
    });
  } catch (err) {
    console.error('[Security Stats Error]', err);
    res.status(500).json({ success: false, message: 'Failed to retrieve security stats.', error: err.message });
  }
});

// Admin View Blocked IPs
app.get('/api/admin/security/blocked-ips', requireAdmin, (req, res) => {
  try {
    const blocked = db.prepare('SELECT * FROM ip_blocklist ORDER BY blocked_at DESC').all();
    res.json({ success: true, count: blocked.length, data: blocked });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve blocked IPs.' });
  }
});

// Admin Unblock IP (Super Admin Only)
app.post('/api/admin/security/unblock-ip', requireRole('super_admin'), (req, res) => {
  const { ip_hash } = req.body;
  if (!ip_hash) {
    return res.status(400).json({ success: false, message: 'ip_hash is required.' });
  }
  const ok = unblockIp(ip_hash);
  if (ok) {
    logAudit(req.adminUser.username, 'FIREWALL_UNBLOCK_IP', 'ip_blocklist', ip_hash, { ip_hash });
    res.json({ success: true, message: `IP Hash ${ip_hash.slice(0, 10)}... unblocked from firewall.` });
  } else {
    res.status(500).json({ success: false, message: 'Failed to unblock IP.' });
  }
});

// ============================================================
// STATIC FILE SERVING — SECURITY HARDENED
// ============================================================

// SECURITY: Block access to sensitive files and directories
app.use((req, res, next) => {
  const blocked = [
    '/server.js', '/package.json', '/package-lock.json',
    '/test_suite.js', '/database_schema.sql', '/.env',
    '/.gitignore', '/README.md'
  ];
  const blockedPrefixes = ['/data/', '/node_modules/', '/.git/'];
  const normalizedPath = req.path.toLowerCase();

  if (blocked.includes(normalizedPath) || blockedPrefixes.some(p => normalizedPath.startsWith(p))) {
    return res.status(403).json({ success: false, message: 'Access denied.' });
  }
  next();
});

// Serve only static assets (HTML, CSS, JS client files, images, uploads)
app.use('/assets', express.static(path.join(__dirname, 'assets'), { maxAge: '7d' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), { maxAge: '1d' }));
app.use('/admin', express.static(path.join(__dirname, 'admin')));
app.use(express.static(path.join(__dirname), {
  index: 'index.html',
  dotfiles: 'deny',
  extensions: ['html', 'css', 'js', 'png', 'jpg', 'jpeg', 'webp', 'gif', 'ico', 'woff', 'woff2', 'ttf']
}));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================================
// GLOBAL ERROR HANDLER — SECURITY HARDENED
// ============================================================
app.use((err, req, res, _next) => {
  // SECURITY: Never leak stack traces or internal details to client
  console.error(`[ERROR] RequestId=${req.requestId || 'N/A'} Path=${req.path}`, err.message);
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ success: false, message: 'Cross-origin request blocked.' });
  }
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ success: false, message: 'File too large. Maximum size is 50 MB.' });
  }
  res.status(err.status || 500).json({
    success: false,
    message: 'An internal error occurred. Please try again or contact the institute.',
    requestId: req.requestId
  });
});

// Crash protection — prevent server from dying on unhandled errors
process.on('uncaughtException', (err) => console.error('[CRASH CAUGHT]', err.message));
process.on('unhandledRejection', (reason) => console.error('[REJECTION CAUGHT]', reason));

// ✅ SECURITY (Phase 1): Scheduled daily database backup at 2:00 AM
function runDatabaseBackup() {
  try {
    const backupDir = path.join(__dirname, 'data', 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

    const dateStr = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    const backupPath = path.join(backupDir, `aj_klasses_${dateStr}.db`);

    // Only backup once per day
    if (!fs.existsSync(backupPath)) {
      fs.copyFileSync(dbPath, backupPath);
      console.log(`[Backup] ✅ Database backed up: ${backupPath}`);

      // Auto-delete backups older than 30 days
      const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.db'));
      files.sort(); // oldest first
      if (files.length > 30) {
        const toDelete = files.slice(0, files.length - 30);
        toDelete.forEach(f => {
          try { fs.unlinkSync(path.join(backupDir, f)); } catch (e) {}
        });
        console.log(`[Backup] Removed ${toDelete.length} old backup(s) to save space.`);
      }
    }
  } catch (err) {
    console.error('[Backup] ❌ Backup failed:', err.message);
  }
}

// ✅ DPDP ACT 2023 / PHASE 3: Automated Data Retention & Privacy Cleanup
function runDataRetentionCleanup() {
  try {
    const now = Date.now();
    const oneDayAgo = now - 24 * 60 * 60 * 1000;

    // 1. Purge rate limit records older than 24 hours
    const rateRes = db.prepare('DELETE FROM rate_limits WHERE last_attempt < ?').run(oneDayAgo);

    // 2. Purge audit logs older than 365 days (1 year retention policy)
    const auditRes = db.prepare("DELETE FROM audit_logs WHERE created_at < datetime('now', '-365 days')").run();

    // 3. Purge expired IP blocklist entries
    const blockRes = db.prepare("DELETE FROM ip_blocklist WHERE expires_at IS NOT NULL AND expires_at < datetime('now')").run();
    reloadBlockedIps();

    // 4. Purge security events older than 90 days
    const secRes = db.prepare("DELETE FROM security_events WHERE created_at < datetime('now', '-90 days')").run();

    // 5. Purge temporary admission notification logs older than 180 days
    const notifRes = db.prepare("DELETE FROM admission_notifications WHERE dispatched_at < datetime('now', '-180 days')").run();

    console.log(`[Data Retention] ✅ DPDP Auto-cleanup: rate limits (${rateRes.changes}), expired blocks (${blockRes.changes}), security events (${secRes.changes}), audit logs (${auditRes.changes}).`);
  } catch (err) {
    console.error('[Data Retention Error]', err.message);
  }
}

// Run backup & retention immediately on startup, then every 24 hours
runDatabaseBackup();
setInterval(runDatabaseBackup, 24 * 60 * 60 * 1000);

runDataRetentionCleanup();
setInterval(runDataRetentionCleanup, 24 * 60 * 60 * 1000);

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🏫 AJ KLASSES SERVER RUNNING ON PORT ${PORT}`);
  console.log(`=======================================================`);
  console.log(`🔒 COMPLETE SECURITY & DPDP COMPLIANCE ACTIVE:`);
  console.log(`   [PHASE 1]`);
  console.log(`   ✅ Helmet.js       — 15+ hardened HTTP security headers & HSTS`);
  console.log(`   ✅ Brute-Force     — 5 wrong attempts = 30-min lockout`);
  console.log(`   ✅ Session Expiry  — Admin tokens expire in 8 hours + auto-purge`);
  console.log(`   ✅ PBKDF2+SHA512   — Timing-safe password hashing (100k rounds)`);
  console.log(`   ✅ SHA-256 Rate    — Rate limiting with privacy-safe IP hashing`);
  console.log(`   ✅ Privacy Policy  — Complete DPDP Act 2023 compliant page & links`);
  console.log(`   [PHASE 2]`);
  console.log(`   ✅ Daily Backup    — Automated database snapshots (30-day rotation)`);
  console.log(`   ✅ Phone Masking   — Masked in all public-facing faculty APIs`);
  console.log(`   ✅ Upload Guard    — Image MIME/magic validation, SVG blocked, CSV filter`);
  console.log(`   ✅ Path Traversal  — Blocked with strict UUID filenames & dotfiles deny`);
  console.log(`   [PHASE 3]`);
  console.log(`   ✅ Code Firewall   — Active IP blocklist with automated quarantine`);
  console.log(`   ✅ Intrusion IPS   — SQLi / exploit scanning pattern auto-detection`);
  console.log(`   ✅ Security Audit  — security_events & audit_logs table tracking`);
  console.log(`   ✅ Data Retention  — 24h cron purges expired records (DPDP Act)`);
  console.log(`   ✅ Multi-Role RBAC — super_admin, counselor, teacher permission guards`);
  console.log(`=======================================================`);
  console.log(`1. Admission Portal:    http://localhost:${PORT}/admission.html`);
  console.log(`2. Result Portal:       http://localhost:${PORT}/results.html`);
  console.log(`3. Attendance Portal:   http://localhost:${PORT}/attendance.html`);
  console.log(`4. Student History:     http://localhost:${PORT}/student-history.html`);
  console.log(`5. Staff Admin Console: http://localhost:${PORT}/admin/login.html`);
  console.log(`6. Privacy Policy:      http://localhost:${PORT}/privacy-policy.html`);
  console.log(`=======================================================`);
});

