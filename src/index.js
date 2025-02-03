require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const PDFDocument = require("pdfkit");
const cookieParser = require("cookie-parser");
const { DB_URL, JWT_SECRET, JWT_EXPIRES_IN } = require("./env");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());
app.use(cookieParser());


// 1) POSTGRES CONFIG
// ----------------------------------------
const pool = new Pool({
  connectionString: DB_URL,
});


// If you want to switch semesters, just change this constant:
const CURRENT_SEMESTER = "1st"; // or '2nd'

const gradePointsMap = { A: 5, B: 4, C: 3, D: 2, E: 1, F: 0 };

/**
 * Middleware to protect routes: verifies JWT from an httpOnly cookie.
 */
function authenticateToken(req, res, next) {
  // Retrieve JWT from "token" cookie
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedPayload) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }
    req.userId = decodedPayload.id;
    next();
  });
}


function setAuthCookie(res, token) {
  // Example cookie options
  const cookieOptions = {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000, // 1 day in ms
  };
  res.cookie("token", token, cookieOptions);
}


// 3) AUTH ROUTES (Cookie-based)
// ----------------------------------------

/**
 * SIGNUP: Creates a new student user.
 * Body: { first_name, last_name, email, password, department, phonenumber, age }
 * By default, level = '100'
 */
app.post("/auth/signup", async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      email,
      password,
      department,
      phonenumber,
      age,
    } = req.body;

    // 1) Check if user already exists
    const checkUserQuery = "SELECT id FROM student WHERE email = $1";
    const checkResult = await pool.query(checkUserQuery, [email]);

    if (checkResult.rows.length > 0) {
      return res.status(400).json({ error: "Email already in use" });
    }

    // 2) Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3) Insert new user (assuming default level = '100')
    const insertQuery = `
      INSERT INTO student (
        first_name, last_name, matric, email, password,
        department_id, phone_number, age, level
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '100')
      RETURNING id, first_name, last_name, email, department_id, level;
    `;
    const values = [
      first_name,
        last_name,
        uuidv4(),
      email,
      hashedPassword,
      department,
      phonenumber,
      age,
    ];

    const result = await pool.query(insertQuery, values);
    const user = result.rows[0];
    return res.status(201).json({ user });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * LOGIN: Verifies user credentials, sets JWT in httpOnly cookie.
 * Body: { email, password }
 */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1) Find user by email
    const userQuery = "SELECT * FROM student WHERE email = $1";
    const { rows } = await pool.query(userQuery, [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const user = rows[0];

    // 2) Compare password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // 3) Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN || "1d",
    });

    // 4) Set cookie
    setAuthCookie(res, token);

    // Remove password before returning user
    delete user.password;
    return res.json({ token, user });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * LOGOUT: Clears the token cookie.
 */
app.post("/auth/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ message: "Logged out successfully" });
});

// ----------------------------------------
// 4) STUDENT ROUTES (Protected)
// ----------------------------------------

/**
 * GET /student/profile
 * Return current student info (requires cookie-based token)
 */
app.get("/student/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const query = `
      SELECT id, first_name, last_name, email, department_id, level, phone_number, age
      FROM student
      WHERE id = $1
    `;
    const { rows } = await pool.query(query, [userId]);
    if (rows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }
    return res.json(rows[0]);
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /student/offerable-courses
 * Returns departmental courses for the student's (department, level, CURRENT_SEMESTER).
 * Splits them into "compulsory" and "elective".
 */
app.get("/student/offerable-courses", authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;

    // 1) Find student's department & level
    const studentQuery = `
      SELECT department_id, level
      FROM student
      WHERE id = $1
    `;
    const { rows: studentRows } = await pool.query(studentQuery, [userId]);
    if (studentRows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }

    const { department, level } = studentRows[0];

    // 2) Query departmental_course + course for those filters
    const offerableQuery = `
      SELECT dc.course_id, dc.semester, dc.mode, c.name AS course_name, c.unit
      FROM departmental_course dc
      JOIN course c ON dc.course_id = c.id
      WHERE dc.department_id = $1
        AND dc.level = $2
        AND dc.semester = $3
    `;
    const values = [department, level, CURRENT_SEMESTER];
    const { rows: courses } = await pool.query(offerableQuery, values);

    // 3) Separate into compulsory vs. elective
    const compulsory = courses.filter((c) => c.mode === "compulsory");
    const electives = courses.filter((c) => c.mode === "elective");

    return res.json({ compulsory, electives });
  } catch (err) {
    console.error("Offerable courses error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /student/register-courses
 * Body: { "electiveCourseIds": ["CSC101", "ENG203", ...] }
 *
 * 1) Automatically include any "compulsory" courses for (department, level, CURRENT_SEMESTER)
 * 2) Insert all selected courses (compulsory + chosen electives) into student_course_registration
 */
app.post("/student/register-courses", authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { electiveCourseIds = [] } = req.body;

    // 1) Get student (department, level)
    const studentQuery = `
      SELECT department, level
      FROM student
      WHERE id = $1
    `;
    const { rows: studentRows } = await pool.query(studentQuery, [userId]);
    if (studentRows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }
    const { department, level } = studentRows[0];

    // 2) Find all compulsory courses for that dept, level, CURRENT_SEMESTER
    const compulsoryQuery = `
      SELECT course_id
      FROM departmental_course
      WHERE department_id = $1
        AND level = $2
        AND semester = $3
        AND mode = 'compulsory'
    `;
    const compValues = [department, level, CURRENT_SEMESTER];
    const { rows: compRows } = await pool.query(compulsoryQuery, compValues);
    const compulsoryIds = compRows.map((row) => row.course_id);

    // 3) Combine all courseIds to register = compulsory + electives
    const allCourseIds = [...new Set([...compulsoryIds, ...electiveCourseIds])];

    if (allCourseIds.length === 0) {
      return res.status(400).json({ error: "No courses to register" });
    }

    // 4) Insert them into student_course_registration
    const insertPromises = allCourseIds.map(async (courseId) => {
      const insertQuery = `
        INSERT INTO student_course_registration (
          student_id, course_id
        )
        VALUES ($1, $2, $3, $4)
        RETURNING id, student_id, course_id, created_at
      `;
      const values = [
        userId,
        courseId,
      ];
      return pool.query(insertQuery, values);
    });

    const results = await Promise.all(insertPromises);
    const registrations = results.map((r) => r.rows[0]);

    return res.status(201).json({ registrations });
  } catch (err) {
    console.error("Register courses error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /student/cgpa
 * Calculate CGPA from student_course_grade (grade => points, use course.unit).
 */
app.get("/student/cgpa", authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const query = `
      SELECT g.grade, c.unit
      FROM student_course_grade g
      JOIN course c ON g.course_id = c.id
      WHERE g.student_id = $1
    `;
    const { rows } = await pool.query(query, [userId]);

    let totalPoints = 0;
    let totalUnits = 0;

    rows.forEach(({ grade, unit }) => {
      const point = gradePointsMap[grade] ?? 0;
      totalPoints += point * unit;
      totalUnits += unit;
    });

    const cgpa = totalUnits === 0 ? 0 : totalPoints / totalUnits;
    return res.json({ cgpa, totalUnits });
  } catch (err) {
    console.error("CGPA error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /student/transcript
 * Streams a PDF with student's courses & grades from student_course_grade
 */
app.get("/student/transcript", authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;

    // 1) Get student info
    const studentQuery = `
      SELECT id, first_name, last_name, email, department_id, level
      FROM student WHERE id = $1
    `;
    const studentResult = await pool.query(studentQuery, [userId]);
    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }
    const student = studentResult.rows[0];

    // 2) Get courses & grades
    const gradesQuery = `
      SELECT g.grade, g.semester, c.name AS course_name, c.unit
      FROM student_course_grade g
      JOIN course c ON g.course_id = c.id
      WHERE g.student_id = $1
    `;
    const { rows: gradeRows } = await pool.query(gradesQuery, [userId]);

    // 3) Generate PDF
    const doc = new PDFDocument({ size: "A4" });
    // set headers so browser downloads as PDF
    res.setHeader("Content-disposition", "attachment; filename=transcript.pdf");
    res.setHeader("Content-type", "application/pdf");

    doc.pipe(res);

    doc.fontSize(18).text("Student Transcript", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`Name: ${student.first_name} ${student.last_name}`);
    doc.text(`Email: ${student.email}`);
    doc.text(`Department ID: ${student.department_id}`);
    doc.text(`Level: ${student.level}`);
    doc.moveDown();
    doc.text("Courses & Grades:", { underline: true });
    doc.moveDown();

    gradeRows.forEach((g) => {
      doc.text(
        `Course: ${g.course_name} (Units: ${g.unit}), ` +
          `Semester: ${g.semester}, Grade: ${g.grade}`
      );
    });

    doc.end();
  } catch (err) {
    console.error("Transcript error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------------------------------
// 5) START SERVER
// ----------------------------------------
const PORT = 3000;
app.listen(PORT, () => {
    console.log("Database URL:", DB_URL);
  console.log(`Server running on port ${PORT}`);
});
