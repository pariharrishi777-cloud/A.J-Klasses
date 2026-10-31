/**
 * AJ KLASSES — AUTOMATED SECURITY & FUNCTIONALITY VERIFICATION SUITE
 */
const { spawn } = require('child_process');
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

let passed = 0;
let failed = 0;

function assert(condition, testName, failureMsg = '') {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${testName} - ${failureMsg}`);
    failed++;
  }
}

async function waitForServer(retries = 30) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await makeRequest('GET', '/');
      if (res.status === 200) return true;
    } catch (e) {}
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error('Server failed to start within timeout.');
}

async function runSecuritySuite() {
  console.log('\n=======================================================');
  console.log('AJ KLASSES SECURITY & INTEGRITY VERIFICATION SUITE');
  console.log('=======================================================\n');

  // Start the server process
  const server = spawn('node', ['server.js'], { stdio: 'pipe' });
  server.stdout.on('data', d => {
    // console.log('[Server stdout]', d.toString().trim());
  });
  server.stderr.on('data', d => {
    console.error('[Server stderr]', d.toString().trim());
  });

  try {
    await waitForServer();
    console.log('Server online on port', PORT);

    // ----------------------------------------------------
    // GROUP 1: SECURITY HEADERS & DEFENSE-IN-DEPTH
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 1: SECURITY HEADERS & DEFENSE-IN-DEPTH]');
    {
      const res = await makeRequest('GET', '/');
      assert(res.headers['x-frame-options'] === 'DENY', 'X-Frame-Options is DENY (anti-clickjacking)');
      assert(res.headers['x-content-type-options'] === 'nosniff', 'X-Content-Type-Options is nosniff (anti-MIME sniffing)');
      assert(res.headers['referrer-policy'] === 'strict-origin-when-cross-origin', 'Referrer-Policy header present');
      assert(typeof res.headers['permissions-policy'] === 'string', 'Permissions-Policy header restricting sensitive APIs');
      assert(typeof res.headers['content-security-policy'] === 'string', 'Content-Security-Policy (CSP) header is present');
      assert(typeof res.headers['x-request-id'] === 'string', 'X-Request-Id header present for audit tracing');
    }

    // ----------------------------------------------------
    // GROUP 2: API CACHE PROTECTION FOR SENSITIVE DATA
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 2: API CACHE PROTECTION]');
    {
      const res = await makeRequest('GET', '/api/teachers');
      assert(res.headers['cache-control'] && res.headers['cache-control'].includes('no-store'), 'API responses include Cache-Control: no-store');
    }

    // ----------------------------------------------------
    // GROUP 3: SENSITIVE FILE ACCESS BLOCKING
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 3: SENSITIVE FILE ACCESS BLOCKING]');
    {
      const resServer = await makeRequest('GET', '/server.js');
      assert(resServer.status === 403, 'Direct access to /server.js is forbidden (403)');

      const resPkg = await makeRequest('GET', '/package.json');
      assert(resPkg.status === 403, 'Direct access to /package.json is forbidden (403)');

      const resDb = await makeRequest('GET', '/data/aj_klasses.db');
      assert(resDb.status === 403, 'Direct access to SQLite database file is forbidden (403)');

      const resEnv = await makeRequest('GET', '/.env');
      assert(resEnv.status === 403, 'Direct access to /.env is forbidden (403)');
    }

    // ----------------------------------------------------
    // GROUP 4: CORS ENFORCEMENT
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 4: CORS ENFORCEMENT]');
    {
      // Untrusted Origin
      const resEvil = await makeRequest('GET', '/api/teachers', null, {
        'Origin': 'https://malicious-attacker-domain.com'
      });
      assert(resEvil.status === 403, 'Untrusted cross-origin origin is rejected with 403');

      // Trusted Origin (Localhost)
      const resGood = await makeRequest('GET', '/api/teachers', null, {
        'Origin': `http://localhost:${PORT}`
      });
      assert(resGood.status === 200, 'Same-origin / localhost origin is accepted');
    }

    // ----------------------------------------------------
    // GROUP 5: AUTHENTICATION & ACCESS CONTROL HARDENING
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 5: AUTHENTICATION HARDENING]');
    {
      // Protected Sample CSV
      const resCsv = await makeRequest('GET', '/api/admin/sample-csv');
      assert(resCsv.status === 401, 'Unauthorized access to sample CSV is rejected (401)');

      // Invalid Admin Login
      const resBadLogin = await makeRequest('POST', '/api/admin/login', {
        username: 'admin',
        password: 'IncorrectPassword!#$'
      });
      assert(resBadLogin.status === 401, 'Invalid credentials rejected with 401');

      // Valid Admin Login
      const resGoodLogin = await makeRequest('POST', '/api/admin/login', {
        username: 'admin',
        password: process.env.ADMIN_INITIAL_PASSWORD || 'AJadmin@2025'
      });
      assert(resGoodLogin.status === 200 && typeof resGoodLogin.data.token === 'string', 'Valid login succeeds and returns token');

      // Authenticated sample-csv access
      const token = resGoodLogin.data.token;
      const resCsvAuth = await makeRequest('GET', '/api/admin/sample-csv', null, {
        'Authorization': `Bearer ${token}`
      });
      assert(resCsvAuth.status === 200, 'Authenticated request to sample CSV succeeds (200)');
    }

    // ----------------------------------------------------
    // GROUP 6: PUBLIC RESULT LOOKUP INTEGRITY & PRIVACY
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 6: PUBLIC RESULT LOOKUP & PRIVACY]');
    {
      const res = await makeRequest('POST', '/api/results/lookup', {
        rollNumber: 'AJ-2025-101',
        studentName: 'Rahul Sharma'
      });
      assert(res.status === 200 && res.data.success === true, 'Valid student lookup returns 200');
      assert(res.data.data.student.student_name === 'Rahul Sharma', 'Matching student name returned');
      assert(res.data.data.student.id === undefined, 'Internal student UUID is not exposed');
      assert(res.data.data.password_hash === undefined, 'No sensitive hash exposed in lookup');
    }

    // ----------------------------------------------------
    // GROUP 7: UNPREDICTABLE ADMISSION REFERENCE NUMBERS
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 7: ADMISSION SUBMISSION & CRYPTOGRAPHIC IDS]');
    {
      const uniqueSuffix = Math.floor(10000000 + Math.random() * 90000000);
      const res = await makeRequest('POST', '/api/admissions/apply', {
        student_name: `Security Test Student ${uniqueSuffix}`,
        parent_name: 'Test Parent',
        contact_number: `98${uniqueSuffix}`,
        email: `test.${uniqueSuffix}@example.com`,
        desired_class: 'Class 11',
        academic_session: '2025-26',
        desired_course: 'JEE Main Foundation'
      });
      assert(res.status === 200 && res.data.success === true, 'Admission application accepted');
      assert(/^AJ-ADM-\d{4}-\d{4}$/.test(res.data.appRefNumber), 'Application ref matches standard pattern (AJ-ADM-YYYY-XXXX)');
    }

    // ----------------------------------------------------
    // GROUP 8: TEACHERS DIRECTORY VERIFICATION
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 8: FACULTY & STAFF DIRECTORY]');
    {
      const res = await makeRequest('GET', '/api/teachers');
      assert(res.status === 200 && res.data.success === true, 'Faculty directory returns 200');
      assert(Array.isArray(res.data.data) && res.data.count >= 8, 'Faculty directory contains at least 8 verified faculty members (including Braj Kishor Yadav)');
      const braj = res.data.data.find(t => t.name.includes('Braj Kishor'));
      assert(braj !== undefined, 'Braj Kishor Yadav present in faculty directory');
      if (braj) {
        assert(braj.phone === '7570025729', 'Braj Kishor Yadav contact number accurately configured');
      }
    }

    // ----------------------------------------------------
    // GROUP 9: ADMISSION APPROVAL, ROLL NUMBER & VERIFICATION HASH DISPATCH
    // ----------------------------------------------------
    console.log('\n[TEST GROUP 9: ADMISSION APPROVAL, ROLL NO & HASH DISPATCH]');
    {
      // 1. Submit application
      const uniqueSuffix = Math.floor(10000000 + Math.random() * 90000000);
      const applyRes = await makeRequest('POST', '/api/admissions/apply', {
        student_name: `Credential Test Student ${uniqueSuffix}`,
        parent_name: 'Harish Chandra',
        contact_number: `98${uniqueSuffix}`,
        email: `cred.${uniqueSuffix}@example.com`,
        desired_class: 'Class 10',
        academic_session: '2024-25',
        desired_course: 'Class 10 Board Prep'
      });
      assert(applyRes.status === 200 && applyRes.data.success === true, 'Applicant submitted for credential test');
      const testRef = applyRes.data.appRefNumber;

      // 2. Fetch admin list to get application ID
      const adminLoginRes = await makeRequest('POST', '/api/admin/login', {
        username: 'admin',
        password: process.env.ADMIN_INITIAL_PASSWORD || 'AJadmin@2025'
      });
      const token = adminLoginRes.data.token;

      const admListRes = await makeRequest('GET', '/api/admin/admissions', null, {
        'Authorization': `Bearer ${token}`
      });
      const appRecord = admListRes.data.applications.find(a => a.app_ref_number === testRef);
      assert(appRecord !== undefined, 'Found application in admin queue');

      // 3. Approve application
      const approveRes = await makeRequest('POST', `/api/admin/admissions/${appRecord.id}/approve`, {
        class_name: 'Class 10',
        academic_year: '2024-25'
      }, {
        'Authorization': `Bearer ${token}`
      });

      assert(approveRes.status === 200 && approveRes.data.success === true, 'Admission approved successfully');
      assert(typeof approveRes.data.student.roll_number === 'string', 'Allocated Roll Number returned');
      assert(typeof approveRes.data.notification.verification_hash === 'string' && approveRes.data.notification.verification_hash.length >= 8, 'Cryptographic Verification Hash code generated');
      assert(typeof approveRes.data.notification.whatsapp_url === 'string' && approveRes.data.notification.whatsapp_url.includes('api.whatsapp.com'), 'WhatsApp dispatch link generated with credentials');
      assert(approveRes.data.notification.message.includes(approveRes.data.student.roll_number), 'WhatsApp message contains student Roll Number');
      assert(approveRes.data.notification.message.includes(approveRes.data.notification.verification_hash), 'WhatsApp message contains Verification Hash code');

      // 4. Test Resend Credentials endpoint
      const resendRes = await makeRequest('POST', `/api/admin/admissions/${appRecord.id}/resend-credentials`, null, {
        'Authorization': `Bearer ${token}`
      });
      assert(resendRes.status === 200 && resendRes.data.success === true, 'Admin can re-dispatch credentials anytime');
      assert(resendRes.data.notification.verification_hash === approveRes.data.notification.verification_hash, 'Resent hash matches original verification hash');

      // 5. Test Public Tracking page displays Roll Number and Hash
      const statusRes = await makeRequest('GET', `/api/admissions/status?ref=${encodeURIComponent(testRef)}`);
      assert(statusRes.status === 200 && statusRes.data.data.status === 'Approved', 'Public tracking reflects Approved status');
      assert(statusRes.data.data.rollNumber === approveRes.data.student.roll_number, 'Public tracking returns newly allocated Roll Number');
      assert(statusRes.data.data.verificationHash === approveRes.data.notification.verification_hash, 'Public tracking returns Verification Hash code');
    }

    console.log('\n=======================================================');
    console.log(`TOTAL PASSED: ${passed} | TOTAL FAILED: ${failed}`);
    console.log('=======================================================\n');

  } finally {
    server.kill();
  }

  process.exit(failed === 0 ? 0 : 1);
}

runSecuritySuite().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
