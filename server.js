const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");
const { randomUUID } = require("crypto");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const BUCKET = "vchd3-files";

if (
  !process.env.DATABASE_URL ||
  !process.env.SESSION_SECRET ||
  !process.env.SUPABASE_URL ||
  !process.env.SUPABASE_SERVICE_ROLE_KEY
) {
  console.error("Environment Variables дутуу байна.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
    files: 10
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      "application/pdf",
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(null, false);
      cb(new Error("Зөвхөн PDF болон зураг оруулна уу."));
    }
  }
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

  await pool.query(`
    ALTER TABLE posts
    ADD COLUMN IF NOT EXISTS attachments JSONB
    NOT NULL DEFAULT '[]'::jsonb
  `);

  const adminPhone = process.env.ADMIN_PHONE?.trim();
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminPhone || !adminPassword) {
    throw new Error("ADMIN_PHONE эсвэл ADMIN_PASSWORD тохируулаагүй байна.");
  }

  const hash = await bcrypt.hash(adminPassword, 12);

  const existing = await pool.query(
    "SELECT id FROM users WHERE phone = $1",
    [adminPhone]
  );

  if (existing.rowCount === 0) {
    await pool.query(
      `INSERT INTO users
       (fullname, phone, password, role, status)
       VALUES ($1, $2, $3, 'superadmin', 'approved')`,
      [
        process.env.ADMIN_NAME || "Үндсэн админ",
        adminPhone,
        hash
      ]
    );
  } else {
    await pool.query(
      `UPDATE users
       SET role = 'superadmin',
           status = 'approved',
           password = $1
       WHERE phone = $2`,
      [hash, adminPhone]
    );
  }

  console.log("Үндсэн админы эрх тохируулагдлаа.");
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      message: "Нэвтэрнэ үү."
    });
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

// БҮРТГЭЛ
app.post("/api/register", async (req, res) => {
  try {
    const { fullname, phone, password } = req.body;

    if (
      !fullname?.trim() ||
      !phone?.trim() ||
      !password ||
      password.length < 8
    ) {
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

// НЭВТРЭХ
app.post("/api/login", async (req, res) => {
  try {
    const phone = req.body.phone?.trim();
    const { password } = req.body;

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
    const valid = await bcrypt.compare(password || "", user.password);

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

    req.session.regenerate((error) => {
      if (error) {
        console.error(error);

        return res.status(500).json({
          message: "Нэвтрэхэд алдаа гарлаа."
        });
      }

      req.session.user = {
        id: user.id,
        fullname: user.fullname,
        role: user.role
      };

      req.session.save((saveError) => {
        if (saveError) {
          console.error(saveError);

          return res.status(500).json({
            message: "Нэвтрэхэд алдаа гарлаа."
          });
        }

        res.json({
          message: "Амжилттай нэвтэрлээ.",
          user: req.session.user
        });
      });
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Нэвтрэхэд алдаа гарлаа."
    });
  }
});

// СИСТЕМЭЭС ГАРАХ
app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        message: "Гарахад алдаа гарлаа."
      });
    }

    res.clearCookie("connect.sid");
    res.json({ message: "Системээс гарлаа." });
  });
});

// ОДОО НЭВТЭРСЭН ХЭРЭГЛЭГЧ
app.get("/api/me", (req, res) => {
  res.json({
    user: req.session.user || null
  });
});

// ХЭРЭГЛЭГЧДИЙН ЖАГСААЛТ
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, fullname, phone, role, status, created_at
       FROM users
       ORDER BY created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Хэрэглэгчдийн мэдээлэл авахад алдаа гарлаа."
    });
  }
});

// АЖИЛТНЫ БҮРТГЭЛ ЗӨВШӨӨРӨХ / ТАТГАЛЗАХ
app.patch("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({
        message: "Төлөв буруу байна."
      });
    }

    const result = await pool.query(
      `UPDATE users
       SET status = $1
       WHERE id = $2 AND role = 'employee'
       RETURNING id`,
      [status, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        message: "Ажилтны бүртгэл олдсонгүй."
      });
    }

    res.json({
      message: "Бүртгэлийн төлөв шинэчлэгдлээ."
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Төлөв шинэчлэхэд алдаа гарлаа."
    });
  }
});

// АДМИН ТОМИЛОХ
app.patch(
  "/api/superadmin/promote/:id",
  requireSuperAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `UPDATE users
         SET role = 'admin'
         WHERE id = $1
           AND status = 'approved'
           AND role = 'employee'
         RETURNING id`,
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(400).json({
          message: "Зөвшөөрөгдсөн ажилтны бүртгэл олдсонгүй."
        });
      }

      res.json({ message: "Админаар томиллоо." });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Админ томилоход алдаа гарлаа."
      });
    }
  }
);

// АДМИНЫ ЭРХ ЦУЦЛАХ
app.patch(
  "/api/superadmin/demote/:id",
  requireSuperAdmin,
  async (req, res) => {
    try {
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

      res.json({
        message: "Админы эрхийг цуцаллаа."
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Админы эрх цуцлахад алдаа гарлаа."
      });
    }
  }
);

// НИЙТЛЭЛ НИЙТЛЭХ
app.post(
  "/api/posts",
  requireAdmin,
  upload.array("files", 10),
  async (req, res) => {
    let postId = null;
    const uploadedPaths = [];

    try {
      const { category, title, content } = req.body;

      const allowed = [
        "ГТХАБ",
        "Техникийн мэдээлэл",
        "Цахилгаан тушаал",
        "ХАБЭА"
      ];

      if (
        !allowed.includes(category) ||
        !title?.trim() ||
        !content?.trim()
      ) {
        return res.status(400).json({
          message: "Мэдээллээ бүрэн оруулна уу."
        });
      }

      const result = await pool.query(
        `INSERT INTO posts
         (category, title, content, author_id)
         VALUES ($1, $2, $3, $4)
         RETURNING id`,
        [
          category,
          title.trim(),
          content.trim(),
          req.session.user.id
        ]
      );

      postId = result.rows[0].id;
      const attachments = [];

      for (const file of req.files || []) {
        const safeName = file.originalname
          .replace(/[^a-zA-Z0-9._-]/g, "_")
          .slice(-100);

        const filePath = `${randomUUID()}-${safeName}`;

        const { error } = await supabase.storage
          .from(BUCKET)
          .upload(filePath, file.buffer, {
            contentType: file.mimetype,
            upsert: false
          });

        if (error) throw error;

        uploadedPaths.push(filePath);

        attachments.push({
          name: file.originalname,
          path: filePath,
          type: file.mimetype,
          size: file.size
        });
      }

      await pool.query(
        "UPDATE posts SET attachments = $1 WHERE id = $2",
        [JSON.stringify(attachments), postId]
      );

      res.json({
        message: "Мэдээлэл амжилттай нийтлэгдлээ.",
        id: postId,
        attachments
      });
    } catch (error) {
      console.error("Post upload error:", error);

      if (uploadedPaths.length) {
        await supabase.storage
          .from(BUCKET)
          .remove(uploadedPaths)
          .catch(console.error);
      }

      if (postId) {
        await pool.query(
          "DELETE FROM posts WHERE id = $1",
          [postId]
        ).catch(console.error);
      }

      res.status(500).json({
        message: "Мэдээлэл оруулахад алдаа гарлаа."
      });
    }
  }
);

// НИЙТЛЭЛ УСТГАХ — ЗӨВХӨН АДМИН
app.delete("/api/posts/:id", requireAdmin, async (req, res) => {
  try {
    const postId = Number(req.params.id);

    if (!Number.isInteger(postId) || postId <= 0) {
      return res.status(400).json({
        message: "Нийтлэлийн дугаар буруу байна."
      });
    }

    const result = await pool.query(
      "SELECT attachments FROM posts WHERE id = $1",
      [postId]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        message: "Нийтлэл олдсонгүй."
      });
    }

    const attachments = result.rows[0].attachments || [];

    const filePaths = attachments
      .map(file => file.path)
      .filter(Boolean);

    // Supabase Storage-оос хавсаргасан файлуудыг устгах
    if (filePaths.length > 0) {
      const { error } = await supabase.storage
        .from(BUCKET)
        .remove(filePaths);

      if (error) throw error;
    }

    // Database-ээс нийтлэлийг устгах
    await pool.query(
      "DELETE FROM posts WHERE id = $1",
      [postId]
    );

    res.json({
      message: "Нийтлэл амжилттай устгагдлаа."
    });
  } catch (error) {
    console.error("Post delete error:", error);

    res.status(500).json({
      message: "Нийтлэл устгахад алдаа гарлаа."
    });
  }
});

// НИЙТЛЭЛҮҮДИЙГ ХАРАХ
app.get("/api/posts", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM posts ORDER BY created_at DESC"
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Мэдээлэл авахад алдаа гарлаа."
    });
  }
});

// ХАВСАРГАСАН ФАЙЛ НЭЭХ
app.get(
  "/api/posts/:id/attachments/:index",
  requireLogin,
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT attachments FROM posts WHERE id = $1",
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          message: "Мэдээлэл олдсонгүй."
        });
      }

      const attachments = result.rows[0].attachments || [];
      const index = Number(req.params.index);

      if (
        !Number.isInteger(index) ||
        index < 0 ||
        index >= attachments.length
      ) {
        return res.status(404).json({
          message: "Файл олдсонгүй."
        });
      }

      const file = attachments[index];

      const { data, error } = await supabase.storage
        .from(BUCKET)
        .createSignedUrl(file.path, 300);

      if (error) throw error;

      res.redirect(data.signedUrl);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Файл нээхэд алдаа гарлаа."
      });
    }
  }
);

// ҮНДСЭН ХУУДАС
app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// АЛДАА БОЛОВСРУУЛАХ
app.use((error, req, res, next) => {
  console.error(error);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      message: "Файл тус бүр 10MB-аас ихгүй, нийт 10 хүртэл файл оруулна уу."
    });
  }

  res.status(400).json({
    message: error.message || "Алдаа гарлаа."
  });
});

// SERVER АСААХ
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
