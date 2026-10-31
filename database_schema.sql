-- ============================================================
-- AJ KLASSES — INTEGRATED DATABASE SCHEMA & ACCESS POLICIES
-- Platform: PostgreSQL / Supabase
-- Modules: Admissions, Enrolled Students, Results, Attendance & Academic History
-- Security Model: Strict Row Level Security (RLS) + SECURITY DEFINER RPCs
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Admission Applications Table
CREATE TABLE IF NOT EXISTS public.admission_applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_ref_number VARCHAR(60) UNIQUE NOT NULL,
    student_name VARCHAR(150) NOT NULL,
    parent_name VARCHAR(150) NOT NULL,
    contact_number VARCHAR(20) NOT NULL,
    email VARCHAR(150),
    desired_class VARCHAR(50) NOT NULL,
    board VARCHAR(50) DEFAULT 'CBSE',
    medium VARCHAR(30) DEFAULT 'English',
    academic_session VARCHAR(30) NOT NULL,
    desired_course VARCHAR(150) NOT NULL,
    previous_school VARCHAR(200),
    message TEXT,
    status VARCHAR(30) DEFAULT 'Pending' CHECK (status IN ('Pending', 'Under Review', 'Approved', 'Rejected', 'Waitlisted')),
    admin_remarks TEXT,
    linked_student_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admissions_ref ON public.admission_applications(app_ref_number);
CREATE INDEX IF NOT EXISTS idx_admissions_status ON public.admission_applications(status);

-- 2. Students & Enrollments Table
CREATE TABLE IF NOT EXISTS public.students (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    roll_number VARCHAR(50) NOT NULL,
    student_name VARCHAR(150) NOT NULL,
    class_name VARCHAR(50) NOT NULL,
    section VARCHAR(20) DEFAULT 'A',
    academic_year VARCHAR(20) NOT NULL,
    enrollment_status VARCHAR(30) DEFAULT 'Active' CHECK (enrollment_status IN ('Active', 'Inactive', 'Completed', 'Withdrawn')),
    parent_name VARCHAR(150),
    contact_number VARCHAR(20),
    email VARCHAR(150),
    admission_app_id UUID REFERENCES public.admission_applications(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT uq_student_roll_class_year UNIQUE (roll_number, class_name, academic_year)
);

CREATE INDEX IF NOT EXISTS idx_students_lookup ON public.students (LOWER(TRIM(roll_number)), LOWER(TRIM(student_name)));

-- Link admission_applications foreign key to students
ALTER TABLE public.admission_applications
    DROP CONSTRAINT IF EXISTS fk_admission_student,
    ADD CONSTRAINT fk_admission_student FOREIGN KEY (linked_student_id) REFERENCES public.students(id) ON DELETE SET NULL;

-- 3. Examinations Table
CREATE TABLE IF NOT EXISTS public.exams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    exam_name VARCHAR(150) NOT NULL,
    academic_year VARCHAR(20) NOT NULL,
    target_classes VARCHAR(100) NOT NULL,
    is_published BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT uq_exam_year UNIQUE (exam_name, academic_year)
);

-- 4. Results Master Table
CREATE TABLE IF NOT EXISTS public.results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id UUID NOT NULL REFERENCES public.students(id) ON DELETE CASCADE,
    exam_id UUID NOT NULL REFERENCES public.exams(id) ON DELETE CASCADE,
    is_published BOOLEAN DEFAULT FALSE,
    publication_date DATE,
    teacher_remarks TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT uq_result_student_exam UNIQUE (student_id, exam_id)
);

CREATE INDEX IF NOT EXISTS idx_results_lookup ON public.results (student_id, exam_id, is_published);

-- 5. Result Subject-wise Marks Table
CREATE TABLE IF NOT EXISTS public.result_subjects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    result_id UUID NOT NULL REFERENCES public.results(id) ON DELETE CASCADE,
    subject_name VARCHAR(100) NOT NULL,
    marks_obtained NUMERIC(5,2) NOT NULL CHECK (marks_obtained >= 0),
    max_marks NUMERIC(5,2) NOT NULL CHECK (max_marks > 0),
    passing_marks NUMERIC(5,2) NOT NULL CHECK (passing_marks >= 0),
    CONSTRAINT chk_marks_le_max CHECK (marks_obtained <= max_marks),
    CONSTRAINT uq_result_subject UNIQUE (result_id, subject_name)
);

-- 6. Attendance Sessions Table
CREATE TABLE IF NOT EXISTS public.attendance_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_date DATE NOT NULL,
    class_name VARCHAR(50) NOT NULL,
    section VARCHAR(20) DEFAULT 'A',
    subject_name VARCHAR(100) DEFAULT 'Regular Class',
    academic_year VARCHAR(30) NOT NULL,
    recorded_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT uq_attendance_session UNIQUE (session_date, class_name, section, subject_name, academic_year)
);

CREATE INDEX IF NOT EXISTS idx_attendance_sessions_class ON public.attendance_sessions (class_name, section, session_date);

-- 7. Attendance Records Table
CREATE TABLE IF NOT EXISTS public.attendance_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES public.attendance_sessions(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES public.students(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('Present', 'Absent', 'Late', 'Leave')),
    remarks TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT uq_session_student_attendance UNIQUE (session_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_attendance_records_student ON public.attendance_records (student_id, status);

-- 8. Audit Logs Table
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    admin_username VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_entity VARCHAR(50) NOT NULL,
    target_id VARCHAR(100),
    details TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 9. Administrator Users Table
CREATE TABLE IF NOT EXISTS public.admin_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    role VARCHAR(50) DEFAULT 'admin' CHECK (role IN ('super_admin', 'admin', 'teacher')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 10. Rate Limits Table
CREATE TABLE IF NOT EXISTS public.rate_limit_logs (
    ip_hash VARCHAR(64) PRIMARY KEY,
    attempts INT DEFAULT 1,
    first_attempt_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_attempt_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================

ALTER TABLE public.admission_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.result_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attendance_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attendance_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limit_logs ENABLE ROW LEVEL SECURITY;

-- Allow public INSERT into admission_applications for new applicants
CREATE POLICY public_apply_admission ON public.admission_applications
    FOR INSERT TO anon, authenticated
    WITH CHECK (status = 'Pending');

-- Authenticated Admin Full CRUD Policies
CREATE POLICY admin_admissions_all ON public.admission_applications FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_students_all ON public.students FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_exams_all ON public.exams FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_results_all ON public.results FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_result_subjects_all ON public.result_subjects FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_attendance_sessions_all ON public.attendance_sessions FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_attendance_records_all ON public.attendance_records FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_audit_logs_all ON public.audit_logs FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_users_all ON public.admin_users FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);

-- ============================================================
-- SECURE PUBLIC RPCs (STORED PROCEDURES WITH SECURITY DEFINER)
-- ============================================================

-- A. Public Result Lookup RPC
CREATE OR REPLACE FUNCTION public.lookup_student_result(
    p_roll_number TEXT,
    p_student_name TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_norm_roll TEXT := UPPER(TRIM(p_roll_number));
    v_norm_name TEXT := LOWER(TRIM(p_student_name));
    v_student RECORD;
    v_result RECORD;
    v_subjects JSONB;
    v_total_obtained NUMERIC := 0;
    v_total_max NUMERIC := 0;
    v_percentage NUMERIC := 0;
    v_has_failed BOOLEAN := FALSE;
    v_overall_status TEXT;
BEGIN
    SELECT * INTO v_student
    FROM public.students
    WHERE UPPER(TRIM(roll_number)) = v_norm_roll
      AND LOWER(TRIM(student_name)) = v_norm_name
      AND enrollment_status = 'Active'
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', FALSE,
            'message', 'We couldn''t verify these details or the result is not currently available. Please check the information or contact the institute.'
        );
    END IF;

    SELECT r.*, e.exam_name, e.academic_year AS exam_academic_year
    INTO v_result
    FROM public.results r
    JOIN public.exams e ON e.id = r.exam_id
    WHERE r.student_id = v_student.id
      AND r.is_published = TRUE
      AND e.is_published = TRUE
    ORDER BY r.created_at DESC
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', FALSE,
            'message', 'We couldn''t verify these details or the result is not currently available. Please check the information or contact the institute.'
        );
    END IF;

    SELECT 
        COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'subject_name', rs.subject_name,
                    'marks_obtained', rs.marks_obtained,
                    'max_marks', rs.max_marks,
                    'passing_marks', rs.passing_marks,
                    'status', CASE WHEN rs.marks_obtained >= rs.passing_marks THEN 'PASS' ELSE 'FAIL' END
                ) ORDER BY rs.subject_name ASC
            ),
            '[]'::jsonb
        ),
        COALESCE(SUM(rs.marks_obtained), 0),
        COALESCE(SUM(rs.max_marks), 0),
        BOOL_OR(rs.marks_obtained < rs.passing_marks)
    INTO v_subjects, v_total_obtained, v_total_max, v_has_failed
    FROM public.result_subjects rs
    WHERE rs.result_id = v_result.id;

    IF v_total_max > 0 THEN
        v_percentage := ROUND((v_total_obtained / v_total_max) * 100, 2);
    END IF;

    IF v_has_failed THEN
        v_overall_status := 'NEEDS IMPROVEMENT';
    ELSIF v_percentage >= 75.0 THEN
        v_overall_status := 'PASSED WITH DISTINCTION';
    ELSIF v_percentage >= 60.0 THEN
        v_overall_status := 'PASSED (FIRST DIVISION)';
    ELSE
        v_overall_status := 'PASSED';
    END IF;

    RETURN jsonb_build_object(
        'success', TRUE,
        'data', jsonb_build_object(
            'institute', jsonb_build_object(
                'name', 'AJ Klasses',
                'location', 'Orai, Jalaun District, Uttar Pradesh',
                'phone', '+91 63940 43659',
                'email', 'pariharrishi777@gmail.com'
            ),
            'student', jsonb_build_object(
                'student_name', v_student.student_name,
                'roll_number', v_student.roll_number,
                'class_name', v_student.class_name,
                'section', v_student.section,
                'academic_year', v_student.academic_year
            ),
            'examination', jsonb_build_object(
                'exam_name', v_result.exam_name,
                'academic_year', v_result.exam_academic_year,
                'publication_date', TO_CHAR(COALESCE(v_result.publication_date, CURRENT_DATE), 'DD Mon YYYY')
            ),
            'subjects', v_subjects,
            'summary', jsonb_build_object(
                'total_obtained', v_total_obtained,
                'total_max', v_total_max,
                'percentage', v_percentage,
                'overall_status', v_overall_status,
                'teacher_remarks', COALESCE(v_result.teacher_remarks, 'Diligent effort demonstrated. Keep progressing towards excellence.')
            )
        )
    );
END;
$$;

-- B. Public Attendance Lookup RPC
CREATE OR REPLACE FUNCTION public.lookup_student_attendance(
    p_roll_number TEXT,
    p_student_name TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_norm_roll TEXT := UPPER(TRIM(p_roll_number));
    v_norm_name TEXT := LOWER(TRIM(p_student_name));
    v_student RECORD;
    v_records JSONB;
    v_total INT := 0;
    v_present INT := 0;
    v_absent INT := 0;
    v_late INT := 0;
    v_leave INT := 0;
    v_percentage NUMERIC := 0;
BEGIN
    SELECT * INTO v_student
    FROM public.students
    WHERE UPPER(TRIM(roll_number)) = v_norm_roll
      AND LOWER(TRIM(student_name)) = v_norm_name
      AND enrollment_status = 'Active'
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', FALSE,
            'message', 'We couldn''t verify these details or attendance records are not currently available. Please check the information or contact the institute.'
        );
    END IF;

    SELECT
        COUNT(*),
        COUNT(*) FILTER (WHERE ar.status = 'Present'),
        COUNT(*) FILTER (WHERE ar.status = 'Absent'),
        COUNT(*) FILTER (WHERE ar.status = 'Late'),
        COUNT(*) FILTER (WHERE ar.status = 'Leave'),
        COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'date', TO_CHAR(s.session_date, 'YYYY-MM-DD'),
                    'formatted_date', TO_CHAR(s.session_date, 'DD Mon YYYY'),
                    'subject', s.subject_name,
                    'status', ar.status,
                    'remarks', COALESCE(ar.remarks, '')
                ) ORDER BY s.session_date DESC
            ),
            '[]'::jsonb
        )
    INTO v_total, v_present, v_absent, v_late, v_leave, v_records
    FROM public.attendance_records ar
    JOIN public.attendance_sessions s ON s.id = ar.session_id
    WHERE ar.student_id = v_student.id;

    IF v_total > 0 THEN
        v_percentage := ROUND(((v_present::NUMERIC + (v_late::NUMERIC * 0.5) + (v_leave::NUMERIC * 0.5)) / v_total::NUMERIC) * 100, 2);
    END IF;

    RETURN jsonb_build_object(
        'success', TRUE,
        'data', jsonb_build_object(
            'student', jsonb_build_object(
                'student_name', v_student.student_name,
                'roll_number', v_student.roll_number,
                'class_name', v_student.class_name,
                'section', v_student.section,
                'academic_year', v_student.academic_year
            ),
            'summary', jsonb_build_object(
                'total_sessions', v_total,
                'present_count', v_present,
                'absent_count', v_absent,
                'late_count', v_late,
                'leave_count', v_leave,
                'attendance_percentage', v_percentage,
                'formula_note', 'Attendance Percentage calculated as: (Present + 0.5 × Late + 0.5 × Approved Leave) ÷ Total Applicable Sessions × 100.'
            ),
            'records', v_records
        )
    );
END;
$$;

-- 11. Teachers / Faculty Table (PostgreSQL)
CREATE TABLE IF NOT EXISTS public.teachers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(150) NOT NULL,
    role VARCHAR(150) NOT NULL,
    department VARCHAR(100) NOT NULL,
    qualification TEXT NOT NULL,
    experience VARCHAR(100) NOT NULL,
    phone VARCHAR(25),
    specialization TEXT,
    bio TEXT,
    initials VARCHAR(10),
    photo_url TEXT,
    display_order INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 12. Events Gallery Table with 5 GB Cloud Media Vault
CREATE TABLE IF NOT EXISTS public.gallery_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    event_date DATE NOT NULL,
    image_url TEXT NOT NULL,
    file_size_bytes BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE public.teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gallery_events ENABLE ROW LEVEL SECURITY;

-- Allow public read access to teachers & gallery events
CREATE POLICY public_read_teachers ON public.teachers FOR SELECT TO anon, authenticated USING (TRUE);
CREATE POLICY public_read_gallery ON public.gallery_events FOR SELECT TO anon, authenticated USING (TRUE);

-- Admin full management policies
CREATE POLICY admin_manage_teachers ON public.teachers FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY admin_manage_gallery ON public.gallery_events FOR ALL TO authenticated USING (TRUE) WITH CHECK (TRUE);

