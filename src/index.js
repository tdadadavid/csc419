require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const PDFDocument = require("pdfkit");
const cookieParser = require("cookie-parser");
const { DB_URL, JWT_SECRET, JWT_EXPIRES_IN } = require("./env");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
	cors({
		origin: "http://localhost:5173", // Your frontend URL
		credentials: true, // Allow credentials (cookies)
		methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
		allowedHeaders: ["Content-Type", "Authorization"],
	})
);

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
        firstname, lastname, matric, email, password,
        department_id, phonenumber, age, level
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '100')
      RETURNING id, firstname, lastname, email, department_id, level;
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
      SELECT id, firstname, lastname, email, department_id, level, phonenumber, age
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

		const { department_id: department, level } = studentRows[0];

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
		console.log(courses);

		// 3) Separate into compulsory vs. elective
		const compulsory = courses.filter((c) => c.mode === "COMPULSORY");
		const electives = courses.filter((c) => c.mode === "ELECTIVE");

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
      SELECT department_id, level
      FROM student
      WHERE id = $1
    `;
		const { rows: studentRows } = await pool.query(studentQuery, [userId]);
		if (studentRows.length === 0) {
			return res.status(404).json({ error: "Student not found" });
		}
		const { department_id: department, level } = studentRows[0];

		// 2) Find all compulsory courses for that dept, level, CURRENT_SEMESTER
		const compulsoryQuery = `
      SELECT course_id
      FROM departmental_course
      WHERE department_id = $1
        AND level = $2
        AND semester = $3
        AND mode = 'COMPULSORY'
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
        VALUES ($1, $2)
        RETURNING id, student_id, course_id, createdat
      `;
			const values = [userId, courseId];
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
 * Calculate CGPA from student_course_registration (grade => points, use course.unit).
 */
app.get("/student/cgpa", authenticateToken, async (req, res) => {
	try {
		const userId = req.userId;
		const query = `
      SELECT g.grade, c.unit
      FROM student_course_registration g
      JOIN course c ON g.course_id = c.id
      WHERE g.student_id = $1 AND  g.grade IS NOT NULL
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
 * Streams a PDF with student's courses & grades from student_course_registration
 */
app.get("/student/transcript", authenticateToken, async (req, res) => {
	try {
		const userId = req.userId;

		// 1) Get student info
		const studentQuery = `
      SELECT id, firstname, lastname, email, department_id, level
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
      FROM student_course_registration g
      JOIN course c ON g.course_id = c.id
      WHERE g.student_id = $1 AND scr.grade IS NOT NULL
    `;
		const { rows: gradeRows } = await pool.query(gradesQuery, [userId]);

		// 3) Generate PDF
		// 3) Generate PDF
		const doc = new PDFDocument({
			size: "A4",
			margins: { top: 50, bottom: 50, left: 50, right: 50 },
		});

		// Set headers so browser downloads as PDF
		res.setHeader("Content-disposition", "attachment; filename=transcript.pdf");
		res.setHeader("Content-type", "application/pdf");

		doc.pipe(res);

		// Add university logo or header
		doc
			.fontSize(20)
			.font("Helvetica-Bold")
			.text("UNIVERSITY TRANSCRIPT", { align: "center" });
		doc
			.fontSize(14)
			.font("Helvetica")
			.text("Official Academic Record", { align: "center" });
		doc.moveDown();

		// Add horizontal line
		doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
		doc.moveDown();

		// Student information section
		doc
			.font("Helvetica-Bold")
			.fontSize(12)
			.text("STUDENT INFORMATION", { underline: true });
		doc.moveDown(0.5);
		doc
			.font("Helvetica")
			.fontSize(11)
			.text(`Full Name: ${student.firstname} ${student.lastname}`, {
				continued: false,
			})
			.text(`Student ID: ${student.id}`, { continued: false })
			.text(`Email: ${student.email}`, { continued: false })
			.text(`Department: ${student.department_id}`, { continued: false })
			.text(`Level: ${student.level}`, { continued: false });

		// Calculate CGPA
		let totalPoints = 0;
		let totalUnits = 0;

		gradeRows.forEach(({ grade, unit }) => {
			const gradePoints = { A: 5, B: 4, C: 3, D: 2, E: 1, F: 0 };
			const point = gradePoints[grade] || 0;
			totalPoints += point * unit;
			totalUnits += unit;
		});

		const cgpa = totalUnits === 0 ? 0 : (totalPoints / totalUnits).toFixed(2);

		doc.text(`CGPA: ${cgpa}`, { continued: false });

		doc.moveDown();

		// Add horizontal line
		doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
		doc.moveDown();

		// Academic record section
		doc
			.font("Helvetica-Bold")
			.fontSize(12)
			.text("ACADEMIC RECORD", { underline: true });
		doc.moveDown();

		// Create table header
		const tableTop = doc.y;
		const tableLeft = 50;
		const colWidths = [200, 60, 80, 80, 80]; // Course name, Units, Semester, Score, Grade

		doc.font("Helvetica-Bold").fontSize(10);
		doc.text("COURSE", tableLeft, tableTop);
		doc.text("UNITS", tableLeft + colWidths[0], tableTop);
		doc.text("SEMESTER", tableLeft + colWidths[0] + colWidths[1], tableTop);
		doc.text(
			"SCORE",
			tableLeft + colWidths[0] + colWidths[1] + colWidths[2],
			tableTop
		);
		doc.text(
			"GRADE",
			tableLeft + colWidths[0] + colWidths[1] + colWidths[2] + colWidths[3],
			tableTop
		);

		doc
			.moveTo(50, doc.y + 5)
			.lineTo(545, doc.y + 5)
			.stroke();
		doc.moveDown();

		// Group grades by semester for better organization
		const gradesBySemester = {};
		gradeRows.forEach((g) => {
			if (!gradesBySemester[g.semester]) {
				gradesBySemester[g.semester] = [];
			}
			gradesBySemester[g.semester].push(g);
		});

		// Print courses by semester
		Object.keys(gradesBySemester).forEach((semester) => {
			doc
				.font("Helvetica-Bold")
				.fontSize(11)
				.text(`${semester} Semester`, { underline: true });
			doc.moveDown(0.5);

			doc.font("Helvetica").fontSize(10);
			gradesBySemester[semester].forEach((g) => {
				const y = doc.y;
				doc.text(g.course_name, tableLeft, y);
				doc.text(g.unit, tableLeft + colWidths[0], y);
				doc.text(g.semester, tableLeft + colWidths[0] + colWidths[1], y);
				doc.text(
					g.score,
					tableLeft + colWidths[0] + colWidths[1] + colWidths[2],
					y
				);

				// Highlight grades with colors
				const gradeColor = {
					A: "#006400", // Dark Green
					B: "#008000", // Green
					C: "#DAA520", // GoldenRod
					D: "#FF8C00", // DarkOrange
					E: "#FF4500", // OrangeRed
					F: "#FF0000", // Red
				};

				doc
					.fillColor(gradeColor[g.grade] || "#000000")
					.text(
						g.grade,
						tableLeft +
							colWidths[0] +
							colWidths[1] +
							colWidths[2] +
							colWidths[3],
						y
					)
					.fillColor("#000000"); // Reset to black
			});

			doc.moveDown();
		});

		// Add horizontal line
		doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
		doc.moveDown();

		// Summary section
		doc
			.font("Helvetica-Bold")
			.fontSize(11)
			.text("SUMMARY", { underline: true });
		doc.moveDown(0.5);
		doc
			.font("Helvetica")
			.fontSize(10)
			.text(`Total Units Attempted: ${totalUnits}`, { continued: false })
			.text(`Cumulative GPA: ${cgpa}`, { continued: false });

		// Calculate position for signature section
		const signatureY = 600; // Fixed position for signature section
		const pageCenter = 297.5; // A4 width is 595 points, so center is 297.5

		// First add the signature text
		doc
			.fontSize(12)
			.font("Helvetica-Bold")
			.text("Dr Edegbami", {
				width: 595 - 100,
				align: "center",
			});

		doc
			.fontSize(10)
			.font("Helvetica")
			.text("University Registrar", {
				width: 595 - 100,
				align: "center",
			});

		// Then add the signature image BELOW the text
		const signatureImagePath = path.join(__dirname, "image.png");

		try {
			// Position the image in the center of the page, but below the "University Registrar" text
			const imageWidth = 150;
			const imageX = pageCenter - imageWidth / 2;
			const imageY = doc.y + 10; // Position it 10 points below the current position (after the text)

			// Add the signature image
			doc.image(signatureImagePath, imageX, imageY, {
				width: imageWidth,
			});
		} catch (error) {
			// Fallback if image cannot be loaded
			console.error("Error loading signature image:", error);
			// No need for fallback since we already have the text above
		}

		// Add footer with date of generation
		const footerY = 750;
		doc
			.fontSize(9)
			.font("Helvetica")
			.text(`Generated on: ${new Date().toLocaleDateString()}`, 50, footerY, {
				align: "center",
				width: 495,
			})
			.text(
				"This transcript is not valid without the university seal and signature.",
				{ align: "center", width: 495 }
			);

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
