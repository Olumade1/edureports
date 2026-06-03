app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "EduReports API is running"
  });
});
require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const axios = require("axios");

const app = express();

app.use(express.json());
app.use(cors());

app.use(express.static(__dirname));
app.use("/uploads", express.static("uploads"));

const SECRET = process.env.JWT_SECRET || "secret123";

/* =================================
   FILE UPLOAD
================================= */

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

/* =================================
   DATABASE
================================= */

const db = new sqlite3.Database("./database.db");

/* USERS */

db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  active INTEGER DEFAULT 0,
  activated_at TEXT,
  subscription_expires TEXT
)
`);

/* ADMINS */

db.run(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)
`);

/* LICENSE CODES */

db.run(`
CREATE TABLE IF NOT EXISTS license_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE,
  used INTEGER DEFAULT 0,
  used_by INTEGER
)
`);

/* STUDENTS */

db.run(`
CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  class TEXT,
  gender TEXT,
  dob TEXT,
  address TEXT,
  photo TEXT
)
`);

/* SUBJECTS */

db.run(`
CREATE TABLE IF NOT EXISTS subjects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT
)
`);

/* SCORES */

db.run(`
CREATE TABLE IF NOT EXISTS scores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER,
  subject_id INTEGER,
  test_score INTEGER,
  exam_score INTEGER,
  total INTEGER,
  term TEXT
)
`);

/* SCHOOL */

db.run(`
CREATE TABLE IF NOT EXISTS school (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  address TEXT,
  phone TEXT,
  email TEXT,
  logo TEXT
)
`);

/* REPORTS */

db.run(`
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER,
  average REAL,
  grade TEXT,
  verification_code TEXT
)
`);

/* =================================
   AUTH
================================= */

function authenticate(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader) {

    return res.status(401).json({
      success: false,
      message: "No token"
    });

  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, SECRET, (err, user) => {

    if (err) {

      return res.status(403).json({
        success: false,
        message: "Invalid token"
      });

    }

    req.user = user;

    next();

  });

}

/* =================================
   ADMIN ONLY
================================= */

function adminOnly(req, res, next) {

  if (req.user.role !== "admin") {

    return res.status(403).json({
      success: false,
      message: "Admins only"
    });

  }

  next();

}

/* =================================
   CREATE ADMIN
================================= */

app.get("/create-admin", async (req, res) => {

  try {

    const hashed = await bcrypt.hash("admin123", 10);

    db.run(
      `
      INSERT INTO admins
      (username, password)
      VALUES (?, ?)
      `,
      ["superadmin", hashed],

      function(err) {

        if (err) {

          return res.json({
            success: false,
            error: err.message
          });

        }

        res.json({
          success: true,
          message: "Super admin created"
        });

      }
    );

  } catch(err) {

    res.json({
      success: false,
      error: err.message
    });

  }

});

/* =================================
   ADMIN LOGIN
================================= */

app.post("/admin-login", (req, res) => {

  const { username, password } = req.body;

  db.get(
    `
    SELECT * FROM admins
    WHERE username = ?
    `,
    [username],

    async (err, admin) => {

      if (!admin) {

        return res.json({
          success: false,
          message: "Admin not found"
        });

      }

      const match =
        await bcrypt.compare(
          password,
          admin.password
        );

      if (!match) {

        return res.json({
          success: false,
          message: "Wrong password"
        });

      }

      const token = jwt.sign(
        {
          id: admin.id,
          role: "admin"
        },
        SECRET,
        {
          expiresIn: "7d"
        }
      );

      res.json({
        success: true,
        token
      });

    }
  );

});

/* =================================
   GENERATE LICENSE
================================= */

app.post(
  "/generate-license",
  authenticate,
  adminOnly,
  (req, res) => {

    function makeCode(length = 12) {

      const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

      let result = "";

      for (let i = 0; i < length; i++) {

        result += chars.charAt(
          Math.floor(Math.random() * chars.length)
        );

      }

      return result;

    }

    const code =
      "EDU-" + makeCode();

    db.run(
      `
      INSERT INTO license_codes
      (code)
      VALUES (?)
      `,
      [code],

      function(err) {

        if (err) {

          return res.json({
            success: false,
            error: err.message
          });

        }

        res.json({
          success: true,
          code
        });

      }
    );

  }
);

/* =================================
   USERS
================================= */

app.get(
  "/users",
  authenticate,
  adminOnly,
  (req, res) => {

    db.all(
      `
      SELECT
        id,
        username,
        active,
        subscription_expires
      FROM users
      ORDER BY id DESC
      `,
      [],

      (err, rows) => {

        if (err) {

          return res.json([]);

        }

        res.json(rows);

      }
    );

  }
);

/* =================================
   SIGNUP
================================= */

app.post("/signup", async (req, res) => {

  try {

    const { username, password } = req.body;

    const hashed =
      await bcrypt.hash(password, 10);

    db.run(
      `
      INSERT INTO users
      (username, password)
      VALUES (?, ?)
      `,
      [username, hashed],

      function(err) {

        if (err) {

          return res.json({
            success: false,
            message: err.message
          });

        }

        res.json({
          success: true
        });

      }
    );

  } catch(err) {

    res.json({
      success: false,
      error: err.message
    });

  }

});

/* =================================
   LOGIN
================================= */

app.post("/login", (req, res) => {

  const { username, password } = req.body;

  db.get(
    `
    SELECT * FROM users
    WHERE username = ?
    `,
    [username],

    async (err, user) => {

      if (!user) {

        return res.json({
          success: false,
          message: "User not found"
        });

      }

      const match =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!match) {

        return res.json({
          success: false,
          message: "Wrong password"
        });

      }

      const token = jwt.sign(
        {
          id: user.id
        },
        SECRET,
        {
          expiresIn: "7d"
        }
      );

      res.json({
        success: true,
        token,
        active: user.active || 0,
        subscription_expires:
          user.subscription_expires || null
      });

    }
  );

});

/* =================================
   ACTIVATE ACCOUNT
================================= */

app.post("/activate", authenticate, (req, res) => {

  const { code } = req.body;

  db.get(
    `
    SELECT * FROM license_codes
    WHERE code = ?
    `,
    [code],

    (err, license) => {

      if (err || !license) {

        return res.json({
          success: false,
          message: "Invalid code"
        });

      }

      if (license.used === 1) {

        return res.json({
          success: false,
          message: "Code already used"
        });

      }

      const now = new Date();

      const expiry = new Date();

      expiry.setMonth(
        expiry.getMonth() + 3
      );

      expiry.setDate(
        expiry.getDate() + 7
      );

      db.run(
        `
        UPDATE users
        SET
          active = 1,
          activated_at = ?,
          subscription_expires = ?
        WHERE id = ?
        `,
        [
          now.toISOString(),
          expiry.toISOString(),
          req.user.id
        ],

        function(err) {

          if (err) {

            return res.json({
              success: false,
              message: err.message
            });

          }

          db.run(
            `
            UPDATE license_codes
            SET
              used = 1,
              used_by = ?
            WHERE id = ?
            `,
            [
              req.user.id,
              license.id
            ]
          );

          res.json({
            success: true,
            expires:
              expiry.toISOString()
          });

        }
      );

    }
  );

});

/* =================================
   STUDENTS
================================= */

app.get("/students", authenticate, (req, res) => {

  const page =
    parseInt(req.query.page) || 1;

  const limit = 10;

  const offset =
    (page - 1) * limit;

  const search =
    req.query.search || "";

  db.all(
    `
    SELECT * FROM students
    WHERE name LIKE ?
    ORDER BY id DESC
    LIMIT ?
    OFFSET ?
    `,
    [
      `%${search}%`,
      limit,
      offset
    ],

    (err, rows) => {

      if (err) {

        return res.json([]);

      }

      res.json(rows);

    }
  );

});

app.post("/students", authenticate, (req, res) => {

  const {
    name,
    class: studentClass,
    gender,
    dob,
    address,
    photo
  } = req.body;

  db.run(
    `
    INSERT INTO students
    (name, class, gender, dob, address, photo)
    VALUES (?, ?, ?, ?, ?, ?)
    `,
    [
      name,
      studentClass,
      gender,
      dob,
      address,
      photo
    ],

    function(err) {

      if (err) {

        return res.json({
          success: false,
          error: err.message
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* UPDATE STUDENT */

app.put("/students/:id", authenticate, (req, res) => {

  const {
    name,
    class: studentClass,
    gender,
    dob,
    address,
    photo
  } = req.body;

  db.run(
    `
    UPDATE students
    SET
      name = ?,
      class = ?,
      gender = ?,
      dob = ?,
      address = ?,
      photo = ?
    WHERE id = ?
    `,
    [
      name,
      studentClass,
      gender,
      dob,
      address,
      photo,
      req.params.id
    ],

    function(err) {

      if (err) {

        return res.json({
          success: false,
          error: err.message
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* DELETE STUDENT */

app.delete("/students/:id", authenticate, (req, res) => {

  db.run(
    `
    DELETE FROM students
    WHERE id = ?
    `,
    [req.params.id],

    function(err) {

      if (err) {

        return res.json({
          success: false
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* =================================
   SUBJECTS
================================= */

app.get("/subjects", authenticate, (req, res) => {

  db.all(
    `
    SELECT * FROM subjects
    ORDER BY name ASC
    `,
    [],

    (err, rows) => {

      if (err) {

        return res.json([]);

      }

      res.json(rows);

    }
  );

});

app.post("/subjects", authenticate, (req, res) => {

  const { name } = req.body;

  db.run(
    `
    INSERT INTO subjects (name)
    VALUES (?)
    `,
    [name],

    function(err) {

      if (err) {

        return res.json({
          success: false
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* UPDATE SUBJECT */

app.put("/subjects/:id", authenticate, (req, res) => {

  const { name } = req.body;

  db.run(
    `
    UPDATE subjects
    SET name = ?
    WHERE id = ?
    `,
    [name, req.params.id],

    function(err) {

      if (err) {

        return res.json({
          success: false
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* DELETE SUBJECT */

app.delete("/subjects/:id", authenticate, (req, res) => {

  db.run(
    `
    DELETE FROM subjects
    WHERE id = ?
    `,
    [req.params.id],

    function(err) {

      if (err) {

        return res.json({
          success: false
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* =================================
   SCORES
================================= */

app.post("/scores", authenticate, (req, res) => {

  const {
    student_id,
    subject_id,
    test_score,
    exam_score,
    term
  } = req.body;

  const total =
    Number(test_score) +
    Number(exam_score);

  db.run(
    `
    INSERT INTO scores
    (
      student_id,
      subject_id,
      test_score,
      exam_score,
      total,
      term
    )
    VALUES (?, ?, ?, ?, ?, ?)
    `,
    [
      student_id,
      subject_id,
      test_score,
      exam_score,
      total,
      term
    ],

    function(err) {

      if (err) {

        return res.json({
          success: false,
          error: err.message
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* UPDATE SCORE */

app.put("/scores/:id", authenticate, (req, res) => {

  const {
    test_score,
    exam_score,
    term
  } = req.body;

  const total =
    Number(test_score) +
    Number(exam_score);

  db.run(
    `
    UPDATE scores
    SET
      test_score = ?,
      exam_score = ?,
      total = ?,
      term = ?
    WHERE id = ?
    `,
    [
      test_score,
      exam_score,
      total,
      term,
      req.params.id
    ],

    function(err) {

      if (err) {

        return res.json({
          success: false
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* DELETE SCORE */

app.delete("/scores/:id", authenticate, (req, res) => {

  db.run(
    `
    DELETE FROM scores
    WHERE id = ?
    `,
    [req.params.id],

    function(err) {

      if (err) {

        return res.json({
          success: false
        });

      }

      res.json({
        success: true
      });

    }
  );

});

/* =================================
   SCHOOL
================================= */

app.get("/school", authenticate, (req, res) => {

  db.get(
    `
    SELECT * FROM school
    LIMIT 1
    `,
    [],

    (err, row) => {

      res.json(row || {});

    }
  );

});

app.post("/school", authenticate, (req, res) => {

  const {
    name,
    address,
    phone,
    email,
    logo
  } = req.body;

  db.get(
    `
    SELECT * FROM school
    LIMIT 1
    `,
    [],

    (err, row) => {

      if (row) {

        db.run(
          `
          UPDATE school
          SET
            name = ?,
            address = ?,
            phone = ?,
            email = ?,
            logo = ?
          WHERE id = ?
          `,
          [
            name,
            address,
            phone,
            email,
            logo,
            row.id
          ],

          function(err) {

            if (err) {

              return res.json({
                success: false
              });

            }

            res.json({
              success: true
            });

          }
        );

      } else {

        db.run(
          `
          INSERT INTO school
          (
            name,
            address,
            phone,
            email,
            logo
          )
          VALUES (?, ?, ?, ?, ?)
          `,
          [
            name,
            address,
            phone,
            email,
            logo
          ],

          function(err) {

            if (err) {

              return res.json({
                success: false
              });

            }

            res.json({
              success: true
            });

          }
        );

      }

    }
  );

});

/* =================================
   UPLOADS
================================= */

app.post(
  "/upload/photo",
  upload.single("file"),
  (req, res) => {

    res.json({
      url: "/uploads/" + req.file.filename
    });

  }
);

app.post(
  "/upload/logo",
  upload.single("file"),
  (req, res) => {

    res.json({
      url: "/uploads/" + req.file.filename
    });

  }
);

/* =================================
   REPORT
================================= */

app.get("/report/:id", authenticate, (req, res) => {

  const studentId = req.params.id;
  const term = req.query.term;

  db.get(
    `
    SELECT * FROM students
    WHERE id = ?
    `,
    [studentId],

    (err, student) => {

      if (!student) {

        return res.json({
          success: false
        });

      }

      db.all(
        `
        SELECT
          subjects.name AS subject,
          scores.test_score,
          scores.exam_score,
          scores.total
        FROM scores
        JOIN subjects
        ON scores.subject_id = subjects.id
        WHERE scores.student_id = ?
        AND scores.term = ?
        `,
        [studentId, term],

        (err, scores) => {

          let total = 0;

          scores.forEach(s => {
            total += s.total;
          });

          const average =
            scores.length > 0
              ? total / scores.length
              : 0;

          db.get(
            `
            SELECT * FROM school
            LIMIT 1
            `,
            [],

            (err, school) => {

              res.json({

                student,

                school: school || {},

                scores,

                average,

                position: "-",

                verification_code:
                  "EDU-" +
                  studentId +
                  "-" +
                  term

              });

            }
          );

        }
      );

    }
  );

});

/* =================================
   VERIFY
================================= */

app.get("/verify/:code", (req, res) => {

  db.get(
    `
    SELECT
      reports.*,
      students.name,
      students.class
    FROM reports
    JOIN students
    ON students.id = reports.student_id
    WHERE verification_code = ?
    `,
    [req.params.code],

    (err, row) => {

      res.json(row || null);

    }
  );

});
/* =================================
   PAYSTACK PAYMENT
================================= */

app.post("/pay", authenticate, async (req, res) => {

  try {

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email: req.body.email,
        amount: req.body.amount * 100
      },
      {
        headers: {
          Authorization:
            `Bearer ${process.env.PAYSTACK_SECRET}`,
          "Content-Type": "application/json"
        }
      }
    );

    res.json(response.data);

  } catch(err) {

    res.json({
      success: false,
      error: err.message
    });

  }

});
/* =================================
   START SERVER
================================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});