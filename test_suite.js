/**
 * AJ KLASSES — AUTOMATED VERIFICATION & TEST SUITE
 * Tests all security controls, lookup edge cases, admin permissions, and data integrity.
 */

const http = require('http');

const PORT = 3000;
const BASE_URL = `http://localhost:${PORT}`;

function makeRequest(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const reqHeaders = { ...headers };
    let postData = null;

    if (body && typeof body === 'object') {
      postData = JSON.stringify(body);
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(url, { method, headers: reqHeaders }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ status: res.statusCode, headers: res.headers, data: json });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, data });
        }
      });
    });

    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, failureMsg = '') {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passedTests++;
  } else {
    console.error(`  ✗ FAIL: ${testName} - ${failureMsg}`);
    failedTests++;
  }
}

async function runTests() {
  console.log('\n=======================================================');
  console.log('STARTING AJ KLASSES RESULT SYSTEM TEST SUITE');
  console.log('=======================================================\n');

  try {
    // 1. Valid Roll Number + Matching Student Name (Published Result)
    console.log('[TEST GROUP 1: PUBLIC RESULT LOOKUP & PRIVACY]');
    {
      const res = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: 'AJ-2025-101',
        studentName: 'Rahul Sharma'
      });
      assert(res.status === 200 && res.data.success === true, 'Valid student lookup returns 200');
      assert(res.data.data.student.student_name === 'Rahul Sharma', 'Matching student name returned');
      assert(res.data.data.student.roll_number === 'AJ-2025-101', 'Matching roll number returned');
      assert(Array.isArray(res.data.data.subjects) && res.data.data.subjects.length > 0, 'Subject marks array returned');
      assert(res.data.data.summary.percentage === 95, 'Percentage calculated correctly (95%)');
      assert(res.data.data.student.id === undefined, 'Private student ID is not leaked');
      assert(res.data.data.password_hash === undefined, 'Internal credentials are not leaked');
    }

    // 2. Case Insensitivity & Trim Normalization
    {
      const res = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: '  aj-2025-101  ',
        studentName: '  rAhUl ShArMa  '
      });
      assert(res.status === 200 && res.data.success === true, 'Case-insensitive & trimmed lookup succeeds');
    }

    // 3. Incorrect Roll Number
    {
      const res = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: 'AJ-999-999',
        studentName: 'Rahul Sharma'
      });
      assert(res.status === 404 && res.data.success === false, 'Incorrect roll number returns 404 generic error');
      assert(res.data.message.includes("couldn't verify these details"), 'Generic failure message returned');
    }

    // 4. Incorrect Student Name with Existing Roll Number
    {
      const res = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: 'AJ-2025-101',
        studentName: 'Vikram Aditya'
      });
      assert(res.status === 404 && res.data.success === false, 'Mismatched student name returns 404 generic error');
    }

    // 5. Missing Form Fields
    {
      const res = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: '',
        studentName: ''
      });
      assert(res.status === 400 && res.data.success === false, 'Empty fields return 400');
    }

    // 6. Excessively Long Input (Buffer / Memory overflow protection)
    {
      const longString = 'A'.repeat(500);
      const res = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: longString,
        studentName: 'Rahul Sharma'
      });
      assert(res.status === 400, 'Excessively long roll number rejected with 400');
    }

    // 7. Draft / Unpublished Result Protection (Aman Dwivedi has draft result)
    {
      const res = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: 'AJ-2025-103',
        studentName: 'Aman Dwivedi'
      });
      assert(res.status === 404 && res.data.success === false, 'Draft/unpublished result is never returned to public (404)');
    }

    console.log('\n[TEST GROUP 2: ADMIN AUTHENTICATION & ACCESS CONTROL]');
    // 8. Unauthorized Access to Admin Endpoint
    {
      const res = await makeRequest('GET', '/api/admin/dashboard');
      assert(res.status === 401, 'Unauthenticated request to /api/admin/dashboard returns 401');
    }

    // 9. Admin Invalid Login
    {
      const res = await makeRequest('POST', '/api/admin/login', {
        username: 'admin',
        password: 'WrongPassword@123'
      });
      assert(res.status === 401, 'Invalid password rejected with 401');
    }

    // 10. Admin Valid Login
    let adminToken = '';
    {
      const res = await makeRequest('POST', '/api/admin/login', {
        username: 'admin',
        password: process.env.ADMIN_INITIAL_PASSWORD || 'AJadmin@2025'
      });
      assert(res.status === 200 && res.data.success === true, 'Admin login succeeds with valid credentials');
      assert(typeof res.data.token === 'string' && res.data.token.length > 20, 'Session token issued');
      adminToken = res.data.token;
    }

    // 11. Authenticated Dashboard Access
    {
      const res = await makeRequest('GET', '/api/admin/dashboard', null, {
        'Authorization': `Bearer ${adminToken}`
      });
      assert(res.status === 200 && res.data.metrics.totalStudents >= 3, 'Admin dashboard returns metrics with token');
    }

    console.log('\n[TEST GROUP 3: STUDENT & RESULT DATA MANAGEMENT]');
    // 12. Add New Student
    const testRoll = 'AJ-TEST-' + Math.floor(Math.random() * 9000 + 1000);
    let createdStudentId = '';
    {
      const res = await makeRequest('POST', '/api/admin/students', {
        roll_number: testRoll,
        student_name: 'Test Student Alpha',
        class_name: 'Class 10',
        section: 'A',
        academic_year: '2024-25'
      }, { 'Authorization': `Bearer ${adminToken}` });
      assert(res.status === 200 && res.data.success === true, 'New student created successfully');
      createdStudentId = res.data.id;
    }

    // 13. Duplicate Student Roll Number Detection
    {
      const res = await makeRequest('POST', '/api/admin/students', {
        roll_number: testRoll,
        student_name: 'Different Name',
        class_name: 'Class 10',
        section: 'A',
        academic_year: '2024-25'
      }, { 'Authorization': `Bearer ${adminToken}` });
      assert(res.status === 400 && res.data.success === false, 'Duplicate roll number in same class/year is blocked (400)');
    }

    // 14. Validation: Marks Obtained > Maximum Marks
    {
      const examsRes = await makeRequest('GET', '/api/admin/exams', null, { 'Authorization': `Bearer ${adminToken}` });
      const examId = examsRes.data.exams[0].id;

      const res = await makeRequest('POST', '/api/admin/results', {
        student_id: createdStudentId,
        exam_id: examId,
        is_published: 0,
        subjects: [
          { subject_name: 'Mathematics', marks_obtained: 105, max_marks: 100, passing_marks: 33 }
        ]
      }, { 'Authorization': `Bearer ${adminToken}` });
      assert(res.status === 400, 'Marks obtained exceeding max marks (105 > 100) is rejected (400)');
    }

    // 15. Create Draft Result and Verify Hidden, then Publish and Verify Visible
    {
      const examsRes = await makeRequest('GET', '/api/admin/exams', null, { 'Authorization': `Bearer ${adminToken}` });
      const examId = examsRes.data.exams[0].id;

      // Create as Draft
      const res = await makeRequest('POST', '/api/admin/results', {
        student_id: createdStudentId,
        exam_id: examId,
        is_published: 0,
        subjects: [
          { subject_name: 'Mathematics', marks_obtained: 92, max_marks: 100, passing_marks: 33 },
          { subject_name: 'Science', marks_obtained: 88, max_marks: 100, passing_marks: 33 }
        ],
        teacher_remarks: 'Superb dedication.'
      }, { 'Authorization': `Bearer ${adminToken}` });
      assert(res.status === 200, 'Draft marksheet recorded successfully');
      const resultId = res.data.resultId;

      // Verify not accessible via public lookup
      const publicCheck1 = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: testRoll,
        studentName: 'Test Student Alpha'
      });
      assert(publicCheck1.status === 404, 'Public lookup cannot find student while result is in Draft status');

      // Publish the result
      const pubRes = await makeRequest('PATCH', `/api/admin/results/${resultId}/publish`, {
        is_published: 1
      }, { 'Authorization': `Bearer ${adminToken}` });
      assert(pubRes.status === 200, 'Admin published the marksheet');

      // Verify now accessible via public lookup
      const publicCheck2 = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: testRoll,
        studentName: 'Test Student Alpha'
      });
      assert(publicCheck2.status === 200 && publicCheck2.data.success === true, 'Public lookup succeeds after publication');
      assert(publicCheck2.data.data.summary.total_obtained === 180, 'Marks correctly aggregated (180/200)');
    }

    console.log('\n[TEST GROUP 4: ADMISSIONS PORTAL & PUBLIC STATUS TRACKING]');
    // 16. Submit Public Admission Application
    let testAppRef = '';
    {
      const uniqueSuffix = Math.floor(10000000 + Math.random() * 90000000);
      const res = await makeRequest('POST', '/api/admissions/apply', {
        student_name: `Pooja Verma ${uniqueSuffix}`,
        parent_name: 'Sanjay Verma',
        contact_number: `98${uniqueSuffix}`,
        email: `pooja.${uniqueSuffix}@example.com`,
        desired_class: 'Class 11',
        board: 'CBSE',
        medium: 'English',
        academic_session: '2025-26',
        desired_course: 'JEE Main + Advanced Foundation',
        previous_school: 'Orai Public School',
        message: 'Interested in weekend batches.'
      });
      assert(res.status === 200 && res.data.success === true, 'Public admission application submitted successfully');
      assert(typeof res.data.appRefNumber === 'string' && res.data.appRefNumber.startsWith('AJ-ADM-'), 'Valid application reference generated (AJ-ADM-*)');
      testAppRef = res.data.appRefNumber;
    }

    // 17. Track Admission Status Publicly
    {
      const res = await makeRequest('GET', `/api/admissions/status?ref=${encodeURIComponent(testAppRef)}`);
      assert(res.status === 200 && res.data.success === true, 'Public status tracking succeeds with valid reference');
      assert(res.data.data.refNumber === testAppRef, 'Matching reference number returned in tracking');
      assert(res.data.data.status === 'Pending', 'Initial application status is Pending');
      assert(res.data.data.desiredClass === 'Class 11', 'Desired class matches submitted data');
    }

    // 18. Invalid Reference Number Tracking
    {
      const res = await makeRequest('GET', '/api/admissions/status?ref=AJ-ADM-0000-0000');
      assert(res.status === 404 && res.data.success === false, 'Nonexistent application reference returns 404');
    }

    // 19. Missing Required Fields in Admission
    {
      const res = await makeRequest('POST', '/api/admissions/apply', {
        student_name: '',
        parent_name: 'Sanjay Verma'
      });
      assert(res.status === 400 && res.data.success === false, 'Missing mandatory admission fields rejected with 400');
    }

    console.log('\n[TEST GROUP 5: ATTENDANCE & ACADEMIC PROGRESSION LOOKUP]');
    // 20. Public Attendance Lookup (Rahul Sharma)
    {
      const res = await makeRequest('POST', '/api/attendance/lookup', {
        rollNumber: 'AJ-2025-101',
        studentName: 'Rahul Sharma'
      });
      assert(res.status === 200 && res.data.success === true, 'Public attendance lookup returns 200 for valid student');
      assert(res.data.data.student.student_name === 'Rahul Sharma', 'Matching student name returned in attendance');
      assert(typeof res.data.data.summary.attendance_percentage === 'number', 'Attendance rate percentage calculated');
      assert(Array.isArray(res.data.data.records), 'Attendance records array returned');
    }

    // 21. Public Academic Progression History Lookup
    {
      const res = await makeRequest('POST', '/api/history/lookup', {
        rollNumber: 'AJ-2025-101',
        studentName: 'Rahul Sharma'
      });
      assert(res.status === 200 && res.data.success === true, 'Public student history lookup returns 200');
      assert(res.data.data.profile.roll_number === 'AJ-2025-101', 'Matching roll number in student history profile');
      assert(Array.isArray(res.data.data.academic_results), 'Academic results list returned in student progression history');
      assert(typeof res.data.data.attendance.percentage === 'number', 'Overall attendance rate included in student progression');
    }

    // 22. Attendance Lookup with Mismatched Name
    {
      const res = await makeRequest('POST', '/api/attendance/lookup', {
        rollNumber: 'AJ-2025-101',
        studentName: 'Unregistered Student'
      });
      assert(res.status === 404 && res.data.success === false, 'Attendance lookup rejects mismatched name with 404');
    }

    console.log('\n[TEST GROUP 6: FACULTY & STAFF DIRECTORY MODULE]');
    // 23. Public Teachers Directory
    {
      const res = await makeRequest('GET', '/api/teachers');
      assert(res.status === 200 && res.data.success === true, 'Public GET /api/teachers returns 200');
      assert(Array.isArray(res.data.data) && res.data.count >= 7, 'Faculty directory contains at least 7 seeded mentors');
      assert(res.data.data.some(t => t.name.includes('Dr. Ajay')), 'Found Dr. Ajay in directory');
      assert(res.data.data.some(t => t.name.includes('Komal')), 'Found Komal Ma\'am in directory');
    }

    // 24. Unauthorized Teacher Management
    {
      const res = await makeRequest('POST', '/api/admin/teachers', {
        name: 'Guest Teacher',
        qualification: 'M.Sc',
        experience: '5 Years'
      });
      assert(res.status === 401, 'Unauthorized teacher creation rejected with 401');
    }

    // 25. Admin Teacher Creation Validation
    {
      const res = await makeRequest('POST', '/api/admin/teachers', {
        name: '',
        qualification: ''
      }, { 'Authorization': `Bearer ${adminToken}` });
      assert(res.status === 400, 'Teacher creation with missing fields rejected with 400');
    }

    // 26. Admin Teacher Full CRUD Cycle
    let testTeacherId = '';
    {
      // Create
      const createRes = await makeRequest('POST', '/api/admin/teachers', {
        name: 'Er. Sandeep Kushwaha',
        role: 'Senior Physics Faculty',
        department: 'Physics',
        qualification: 'B.Tech (IIT Kanpur), M.Tech',
        experience: '9+ Years',
        phone: '9876543299',
        specialization: 'Optics, Mechanics & Advanced Problem Solving',
        bio: 'Passionate about conceptual physics and numerical mastery.'
      }, { 'Authorization': `Bearer ${adminToken}` });
      assert(createRes.status === 200 && createRes.data.success === true, 'Admin can create new faculty member');
      testTeacherId = createRes.data.id;

      // Update
      const updateRes = await makeRequest('PUT', `/api/admin/teachers/${testTeacherId}`, {
        name: 'Er. Sandeep Kushwaha',
        role: 'Lead Physics Mentor & HOD',
        department: 'Physics',
        qualification: 'B.Tech (IIT Kanpur), M.Tech',
        experience: '10+ Years',
        phone: '9876543299',
        specialization: 'Optics, Mechanics & Advanced Problem Solving',
        bio: 'Updated biography for physics lead.'
      }, { 'Authorization': `Bearer ${adminToken}` });
      assert(updateRes.status === 200 && updateRes.data.success === true, 'Admin can update faculty profile details');

      // Delete
      const deleteRes = await makeRequest('DELETE', `/api/admin/teachers/${testTeacherId}`, null, {
        'Authorization': `Bearer ${adminToken}`
      });
      assert(deleteRes.status === 200 && deleteRes.data.success === true, 'Admin can delete faculty member');
    }

    console.log('\n[TEST GROUP 7: EVENTS GALLERY & 5 GB STORAGE QUOTA]');
    // 27. Public Events Gallery Feed & Storage Quota Telemetry
    {
      const res = await makeRequest('GET', '/api/gallery');
      assert(res.status === 200 && res.data.success === true, 'Public GET /api/gallery returns 200');
      assert(Array.isArray(res.data.data) && res.data.count >= 6, 'Gallery contains at least 6 seeded events');
      assert(res.data.storage !== undefined, 'Storage quota telemetry included in response');
      assert(res.data.storage.totalBytes === 5368709120, 'Storage quota strictly configured to 5 GB (5,368,709,120 bytes)');
      assert(typeof res.data.storage.usedFormatted === 'string', 'Formatted storage usage returned');
      assert(typeof res.data.storage.remainingFormatted === 'string', 'Formatted remaining capacity returned');
      assert(res.data.storage.totalFormatted === '5.00 GB', 'Formatted total storage is 5.00 GB');
    }

    // 28. Gallery Category Filtering
    {
      const res = await makeRequest('GET', '/api/gallery?category=Toppers%20Felicitation');
      assert(res.status === 200 && res.data.success === true, 'Gallery filter by category returns 200');
      assert(res.data.data.every(e => e.category === 'Toppers Felicitation'), 'All returned events match the queried category');
    }

    // 29. Unauthorized Gallery Admin Actions
    {
      const res = await makeRequest('DELETE', '/api/admin/gallery/nonexistent-id');
      assert(res.status === 401, 'Unauthorized deletion of gallery item rejected with 401');
    }
    console.log(`TEST SUMMARY: ${passedTests} PASSED, ${failedTests} FAILED`);
    console.log('=======================================================\n');

    process.exit(failedTests === 0 ? 0 : 1);

  } catch (err) {
    console.error('Fatal error during test execution:', err);
    process.exit(1);
  }
}

// Give server time to be up
setTimeout(runTests, 1000);
