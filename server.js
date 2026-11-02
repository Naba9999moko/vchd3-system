
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  console.error("DATABASE_URL болон SESSION_SECRET тохируулаагүй байна.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100
}));

app.use(session({
  store: new PgSession({
    pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fullname TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'employee',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      author_id INTEGER REFERENCES users(id),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const adminPhone = process.env.ADMIN_PHONE;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminPhone && adminPassword) {
    const existing = await pool.query(
      "SELECT id FROM users WHERE phone = $1",
      [adminPhone]
    );

    if (existing.rowCount === 0) {
      const hash = await bcrypt.hash(adminPassword, 12);

      await pool.query(
        `INSERT INTO users (fullname, phone, password, role, status)
         VALUES ($1, $2, $3, 'superadmin', 'approved')`,
        [
          process.env.ADMIN_NAME || "Үндсэн админ",
          adminPhone,
          hash
        ]
      );
    }
  }
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: "Нэвтэрнэ үү." });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (
    !req.session.user ||
    !["admin", "superadmin"].includes(req.session.user.role)
  ) {
    return res.status(403).json({
      message: "Админы эрх шаардлагатай."
    });
  }
  next();
}

function requireSuperAdmin(req, res, next) {
  if (
    !req.session.user ||
    req.session.user.role !== "superadmin"
  ) {
    return res.status(403).json({
      message: "Үндсэн админы эрх шаардлагатай."
    });
  }
  next();
}

// Ажилтны бүртгэл
app.post("/api/register", async (req, res) => {
  try {
    const { fullname, phone, password } = req.body;

    if (!fullname || !phone || !password || password.length < 8) {
      return res.status(400).json({
        message: "Мэдээллээ бүрэн оруулна уу. Нууц үг 8-аас дээш тэмдэгт байна."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (fullname, phone, password)
       VALUES ($1, $2, $3)`,
      [fullname.trim(), phone.trim(), hash]
    );

    res.json({
      message: "Бүртгэл амжилттай. Админы зөвшөөрлийг хүлээнэ үү."
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        message: "Энэ утасны дугаар бүртгэлтэй байна."
      });
    }

    console.error(error);
    res.status(500).json({
      message: "Бүртгэл хийхэд алдаа гарлаа."
    });
  }
});

// Нэвтрэх
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE phone = $1",
      [phone]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        message: "Нэвтрэх мэдээлэл буруу байна."
      });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({
        message: "Нэвтрэх мэдээлэл буруу байна."
      });
    }

    if (user.status !== "approved") {
      return res.status(403).json({
        message: "Таны бүртгэлийг админ хараахан зөвшөөрөөгүй байна."
      });
    }

    req.session.user = {
      id: user.id,
      fullname: user.fullname,
      role: user.role
    };

    res.json({
      message: "Амжилттай нэвтэрлээ.",
      user: req.session.user
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Нэвтрэхэд алдаа гарлаа."
    });
  }
});

// Гарах
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Системээс гарлаа." });
  });
});

// Одоогийн хэрэглэгч
app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

// Админ хэрэглэгчдийн жагсаалт харах
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const result = await pool.query(
    `SELECT id, fullname, phone, role, status, created_at
     FROM users
     ORDER BY created_at DESC`
  );

  res.json(result.rows);
});

// Бүртгэл зөвшөөрөх / татгалзах
app.patch("/api/admin/users/:id", requireAdmin, async (req, res) => {
  const { status } = req.body;

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({
      message: "Төлөв буруу байна."
    });
  }

  await pool.query(
    "UPDATE users SET status = $1 WHERE id = $2 AND role = 'employee'",
    [status, req.params.id]
  );

  res.json({
    message: "Бүртгэлийн төлөв шинэчлэгдлээ."
  });
});

// Үндсэн админ админ томилох
app.patch("/api/superadmin/promote/:id", requireSuperAdmin, async (req, res) => {
  const result = await pool.query(
    `UPDATE users
     SET role = 'admin'
     WHERE id = $1 AND status = 'approved' AND role = 'employee'
     RETURNING id`,
    [req.params.id]
  );

  if (!result.rowCount) {
    return res.status(400).json({
      message: "Зөвшөөрөгдсөн ажилтны бүртгэл олдсонгүй."
    });
  }

  res.json({ message: "Админаар томиллоо." });
});

// Үндсэн админ админы эрх цуцлах
app.patch("/api/superadmin/demote/:id", requireSuperAdmin, async (req, res) => {
  const result = await pool.query(
    `UPDATE users
     SET role = 'employee'
     WHERE id = $1 AND role = 'admin'
     RETURNING id`,
    [req.params.id]
  );

  if (!result.rowCount) {
    return res.status(400).json({
      message: "Админ олдсонгүй."
    });
  }

  res.json({ message: "Админы эрхийг цуцаллаа." });
});

// Мэдээлэл оруулах
app.post("/api/posts", requireAdmin, async (req, res) => {
  const { category, title, content } = req.body;

  const allowed = [
    "ГТХАБ",
    "Техникийн мэдээлэл",
    "Цахилгаан тушаал",
    "ХАБЭА"
  ];

  if (!allowed.includes(category) || !title || !content) {
    return res.status(400).json({
      message: "Мэдээллээ бүрэн оруулна уу."
    });
  }

  const result = await pool.query(
    `INSERT INTO posts (category, title, content, author_id)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [category, title, content, req.session.user.id]
  );

  res.json(result.rows[0]);
});

// Мэдээлэл харах
app.get("/api/posts", requireLogin, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM posts ORDER BY created_at DESC"
  );

  res.json(result.rows);
});

// НҮҮР ХУУДАС НЭЭХ
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Сервер эхлүүлэх
async function start() {
  await setupDatabase();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("Server эхлэхэд алдаа:", error);
  process.exit(1);
});
