require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("Set SESSION_SECRET in .env to a random string of at least 32 characters.");
  process.exit(1);
}
if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD ||
    process.env.ADMIN_PASSWORD.length < 12) {
  console.error("Set ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters in .env.");
  process.exit(1);
}

const db = new Database(path.join(__dirname, "mr-r-coding.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const adminName = process.env.ADMIN_USERNAME.trim();
const existingAdmin = db.prepare("SELECT id FROM users WHERE username = ?").get(adminName);
if (!existingAdmin) {
  const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')")
    .run(adminName, adminHash);
}

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: __dirname }),
  name: "mr_r_session",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 4
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "محاولات كثيرة. انتظر 15 دقيقة وحاول مرة ثانية." }
});
app.use("/api/register", authLimiter);
app.use("/api/login", authLimiter);

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "سجّل الدخول أولاً." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "هذه الصفحة للمشرف فقط." });
  }
  next();
}

app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const consent = req.body.consent === true;

  if (!consent) return res.status(400).json({ error: "لازم توافق على إشعار الخصوصية حتى تنشئ الحساب." });
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: "اسم المستخدم لازم يكون 3–20 حرفاً أو رقماً أو _." });
  }
  if (password.length < 10 || password.length > 72) {
    return res.status(400).json({ error: "كلمة المرور لازم تكون من 10 إلى 72 حرفاً." });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
      .run(username, hash);
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "تعذر إنشاء الجلسة." });
      req.session.user = { id: Number(result.lastInsertRowid), username, role: "user" };
      res.json({ message: "تم إنشاء الحساب وتسجيل الدخول بنجاح.", user: { username, role: "user" } });
    });
  } catch (err) {
    if (String(err.code).includes("SQLITE_CONSTRAINT")) {
      return res.status(409).json({ error: "اسم المستخدم مستخدم مسبقاً." });
    }
    console.error(err);
    res.status(500).json({ error: "حدث خطأ داخلي." });
  }
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT id, username, password_hash, role FROM users WHERE username = ?")
    .get(username);

  const ok = user && await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة." });

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "تعذر إنشاء الجلسة." });
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ message: "تم تسجيل الدخول.", user: { username: user.username, role: user.role } });
  });
});

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("mr_r_session");
    res.json({ message: "تم تسجيل الخروج." });
  });
});

app.get("/api/admin/users", requireLogin, requireAdmin, (req, res) => {
  // Passwords and password hashes are deliberately never returned.
  const users = db.prepare(
    "SELECT id, username, role, created_at FROM users ORDER BY created_at DESC"
  ).all();
  res.json({ users });
});

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => {
  console.log(`Mr.R Coding is running at http://localhost:${PORT}`);
});
