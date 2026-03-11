require("dotenv").config();
const express  = require("express");
const Database = require("better-sqlite3");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const cors     = require("cors");
const QRCode   = require("qrcode");
const { v4: uuidv4 } = require("uuid");
const path     = require("path");

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || "tradex_jwt_secret_change_in_production";
const PORT       = process.env.PORT || 4000;
const UPI_ID     = process.env.UPI_ID  || "tradex@upi";

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());

// ─── Database ─────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, "tradex.db"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    uid           TEXT    UNIQUE NOT NULL,
    name          TEXT    NOT NULL,
    email         TEXT    UNIQUE NOT NULL,
    password      TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    real_balance  REAL    NOT NULL DEFAULT 0,
    demo_balance  REAL    NOT NULL DEFAULT 10000,
    account_type  TEXT    NOT NULL DEFAULT 'demo',
    is_verified   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    uid           TEXT    NOT NULL,
    txid          TEXT    UNIQUE NOT NULL,
    type          TEXT    NOT NULL,
    amount        REAL    NOT NULL,
    method        TEXT,
    method_detail TEXT,
    status        TEXT    NOT NULL DEFAULT 'pending',
    note          TEXT,
    utr           TEXT,
    qr_data       TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(uid) REFERENCES users(uid)
  );
  CREATE TABLE IF NOT EXISTS admin_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_uid   TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    target_uid  TEXT,
    details     TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// Auto-create admin
const adminExists = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
if (!adminExists) {
  const hashed = bcrypt.hashSync("admin123", 10);
  db.prepare(`INSERT INTO users (uid,name,email,password,role,real_balance,demo_balance,is_verified) VALUES (?,'Admin','admin@tradex.com',?,'admin',999999,0,1)`).run(uuidv4(), hashed);
  console.log("✅ Admin created: admin@tradex.com / admin123");
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return res.status(401).json({ error: "No token provided" });
  try { req.user = jwt.verify(header.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: "Token invalid or expired" }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  next();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
async function generateUpiQR(amount, txid) {
  const upiStr = `upi://pay?pa=${UPI_ID}&pn=TradeX&am=${amount}&tr=${txid}&tn=TradeXDeposit&cu=INR`;
  return await QRCode.toDataURL(upiStr, { width: 300, margin: 2, color: { dark:"#000000", light:"#ffffff" } });
}
function safeUser(u) {
  return {
    uid: u.uid, name: u.name, email: u.email, role: u.role,
    realBalance: u.real_balance, demoBalance: u.demo_balance,
    accountType: u.account_type, isVerified: u.is_verified,
    createdAt: u.created_at, lastLogin: u.last_login,
    initials: u.name.trim().split(" ").map(w => w[0]).join("").toUpperCase().slice(0,2),
  };
}

// ═════════════════════════════════════════════════════════════════════
//  ROOT — Health check (fixes blank page / 404 at localhost:4000)
// ═════════════════════════════════════════════════════════════════════
app.get("/", (req, res) => {
  res.json({
    status:   "✅ TradeX Backend is running!",
    frontend: "Open http://localhost:5173 to use the app",
    admin:    "admin@tradex.com / admin123",
    api_base: `http://localhost:${PORT}/api`,
    endpoints: [
      "POST /api/auth/register",
      "POST /api/auth/login",
      "GET  /api/auth/me",
      "POST /api/deposit/initiate",
      "POST /api/deposit/confirm",
      "POST /api/withdraw",
      "GET  /api/transactions",
      "GET  /api/admin/stats",
      "GET  /api/admin/users",
      "GET  /api/admin/transactions",
      "POST /api/admin/approve-deposit",
      "POST /api/admin/reject-deposit",
      "POST /api/admin/set-balance",
      "POST /api/admin/credit",
    ],
  });
});

// ═════════════════════════════════════════════════════════════════
//  AUTH
// ═════════════════════════════════════════════════════════════════
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Name, email and password are required" });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    const exists = db.prepare("SELECT id FROM users WHERE email=?").get(email.toLowerCase().trim());
    if (exists) return res.status(409).json({ error: "This email is already registered" });
    const hashed = await bcrypt.hash(password, 10);
    const uid    = uuidv4();
    db.prepare("INSERT INTO users (uid,name,email,password,demo_balance) VALUES (?,?,?,?,10000)")
      .run(uid, name.trim(), email.toLowerCase().trim(), hashed);
    const user  = db.prepare("SELECT * FROM users WHERE uid=?").get(uid);
    const token = jwt.sign({ uid: user.uid, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    console.log(`✅ Registered: ${user.email}`);
    res.status(201).json({ token, user: safeUser(user) });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error during registration" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
    const user = db.prepare("SELECT * FROM users WHERE email=?").get(email.toLowerCase().trim());
    if (!user) return res.status(401).json({ error: "Invalid email or password" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid email or password" });
    db.prepare("UPDATE users SET last_login=datetime('now') WHERE uid=?").run(user.uid);
    const token = jwt.sign({ uid: user.uid, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    console.log(`✅ Login: ${user.email} (${user.role})`);
    res.json({ token, user: safeUser(user) });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE uid=?").get(req.user.uid);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user: safeUser(user) });
});

// ═════════════════════════════════════════════════════════════════
//  DEPOSIT
// ═════════════════════════════════════════════════════════════════
app.post("/api/deposit/initiate", authMiddleware, async (req, res) => {
  try {
    const { amount, method } = req.body;
    if (!amount || Number(amount) < 100) return res.status(400).json({ error: "Minimum deposit is ₹100" });
    const txid   = "TXN" + Date.now() + Math.floor(Math.random() * 9000 + 1000);
    let   qrData = null;
    if (["upi","gpay","paytm","phonepe"].includes(method)) {
      qrData = await generateUpiQR(Number(amount), txid);
    }
    db.prepare("INSERT INTO transactions (uid,txid,type,amount,method,status,qr_data) VALUES (?,?,'deposit',?,?,?,?)")
      .run(req.user.uid, txid, Number(amount), method, "pending", qrData);
    res.json({ txid, qrData, upiId: UPI_ID, message: "Deposit initiated" });
  } catch (err) {
    console.error("Deposit initiate error:", err);
    res.status(500).json({ error: "Could not initiate deposit" });
  }
});

app.post("/api/deposit/confirm", authMiddleware, (req, res) => {
  const { txid, utr } = req.body;
  if (!txid || !utr) return res.status(400).json({ error: "txid and utr are required" });
  const tx = db.prepare("SELECT * FROM transactions WHERE txid=? AND uid=?").get(txid, req.user.uid);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });
  if (tx.status !== "pending") return res.status(400).json({ error: "Transaction already processed" });
  db.prepare("UPDATE transactions SET utr=?, status='processing', updated_at=datetime('now') WHERE txid=?").run(utr.trim(), txid);
  res.json({ message: "UTR submitted. Admin will verify and credit your account shortly." });
});

// ═════════════════════════════════════════════════════════════════
//  WITHDRAW
// ═════════════════════════════════════════════════════════════════
app.post("/api/withdraw", authMiddleware, (req, res) => {
  try {
    const { amount, method, methodDetail } = req.body;
    const amt  = Number(amount);
    const user = db.prepare("SELECT * FROM users WHERE uid=?").get(req.user.uid);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (amt < 200) return res.status(400).json({ error: "Minimum withdrawal is ₹200" });
    if (user.real_balance < amt) return res.status(400).json({ error: "Insufficient real balance" });
    const txid = "WD" + Date.now();
    db.prepare("UPDATE users SET real_balance=real_balance-? WHERE uid=?").run(amt, user.uid);
    db.prepare("INSERT INTO transactions (uid,txid,type,amount,method,method_detail,status) VALUES (?,?,'withdraw',?,?,?,'processing')")
      .run(user.uid, txid, amt, method, methodDetail || "");
    const updated = db.prepare("SELECT * FROM users WHERE uid=?").get(user.uid);
    res.json({ message: "Withdrawal requested", user: safeUser(updated) });
  } catch (err) {
    console.error("Withdraw error:", err);
    res.status(500).json({ error: "Could not process withdrawal" });
  }
});

// ═════════════════════════════════════════════════════════════════
//  TRANSACTIONS
// ═════════════════════════════════════════════════════════════════
app.get("/api/transactions", authMiddleware, (req, res) => {
  const txns = db.prepare("SELECT * FROM transactions WHERE uid=? ORDER BY created_at DESC LIMIT 50").all(req.user.uid);
  res.json({ transactions: txns });
});

// ═════════════════════════════════════════════════════════════════
//  ADMIN
// ═════════════════════════════════════════════════════════════════
app.get("/api/admin/stats", authMiddleware, adminOnly, (req, res) => {
  res.json({
    totalUsers:    db.prepare("SELECT COUNT(*) as c FROM users WHERE role='user'").get().c,
    totalDeposits: db.prepare("SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='deposit' AND status='success'").get().s,
    pending:       db.prepare("SELECT COUNT(*) as c FROM transactions WHERE status='processing'").get().c,
    todayUsers:    db.prepare("SELECT COUNT(*) as c FROM users WHERE date(created_at)=date('now')").get().c,
  });
});

app.get("/api/admin/users", authMiddleware, adminOnly, (req, res) => {
  const { search } = req.query;
  const users = search
    ? db.prepare("SELECT * FROM users WHERE (email LIKE ? OR name LIKE ?) ORDER BY created_at DESC").all(`%${search}%`, `%${search}%`)
    : db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
  res.json({ users: users.map(safeUser) });
});

app.get("/api/admin/transactions", authMiddleware, adminOnly, (req, res) => {
  const { status, type } = req.query;
  let query = "SELECT t.*, u.name as user_name, u.email as user_email FROM transactions t JOIN users u ON t.uid=u.uid WHERE 1=1";
  const params = [];
  if (status) { query += " AND t.status=?"; params.push(status); }
  if (type)   { query += " AND t.type=?";   params.push(type);   }
  query += " ORDER BY t.created_at DESC LIMIT 100";
  res.json({ transactions: db.prepare(query).all(...params) });
});

app.post("/api/admin/approve-deposit", authMiddleware, adminOnly, (req, res) => {
  const { txid } = req.body;
  if (!txid) return res.status(400).json({ error: "txid is required" });
  const tx = db.prepare("SELECT * FROM transactions WHERE txid=?").get(txid);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });
  if (tx.status === "success") return res.status(400).json({ error: "Already approved" });
  db.prepare("UPDATE transactions SET status='success', updated_at=datetime('now') WHERE txid=?").run(txid);
  db.prepare("UPDATE users SET real_balance=real_balance+?, account_type='real' WHERE uid=?").run(tx.amount, tx.uid);
  db.prepare("INSERT INTO admin_logs (admin_uid,action,target_uid,details) VALUES (?,?,?,?)").run(req.user.uid, "approve_deposit", tx.uid, `Approved ${txid} ₹${tx.amount}`);
  const user = db.prepare("SELECT * FROM users WHERE uid=?").get(tx.uid);
  console.log(`✅ Approved deposit ${txid} → ₹${tx.amount} to ${user.email}`);
  res.json({ message: "Deposit approved and balance credited", user: safeUser(user) });
});

app.post("/api/admin/reject-deposit", authMiddleware, adminOnly, (req, res) => {
  const { txid, reason } = req.body;
  const tx = db.prepare("SELECT * FROM transactions WHERE txid=?").get(txid);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });
  db.prepare("UPDATE transactions SET status='failed', note=?, updated_at=datetime('now') WHERE txid=?").run(reason || "Rejected by admin", txid);
  db.prepare("INSERT INTO admin_logs (admin_uid,action,target_uid,details) VALUES (?,?,?,?)").run(req.user.uid, "reject_deposit", tx.uid, `Rejected ${txid}: ${reason}`);
  res.json({ message: "Deposit rejected" });
});

app.post("/api/admin/set-balance", authMiddleware, adminOnly, (req, res) => {
  const { uid, real_balance, demo_balance, note } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE uid=?").get(uid);
  if (!user) return res.status(404).json({ error: "User not found" });
  const sets = []; const params = [];
  if (real_balance !== undefined) { sets.push("real_balance=?"); params.push(Number(real_balance)); }
  if (demo_balance !== undefined) { sets.push("demo_balance=?"); params.push(Number(demo_balance)); }
  if (!sets.length) return res.status(400).json({ error: "Provide real_balance or demo_balance" });
  params.push(uid);
  db.prepare(`UPDATE users SET ${sets.join(",")} WHERE uid=?`).run(...params);
  if (real_balance !== undefined) {
    const diff = Number(real_balance) - user.real_balance;
    if (diff !== 0) db.prepare("INSERT INTO transactions (uid,txid,type,amount,method,status,note) VALUES (?,?,?,?,'admin','success',?)").run(uid, "ADM"+Date.now(), diff>=0?"admin_credit":"admin_debit", Math.abs(diff), note||"Admin balance set");
  }
  db.prepare("INSERT INTO admin_logs (admin_uid,action,target_uid,details) VALUES (?,?,?,?)").run(req.user.uid, "set_balance", uid, `real=${real_balance} demo=${demo_balance}`);
  const updated = db.prepare("SELECT * FROM users WHERE uid=?").get(uid);
  console.log(`⚙️  Balance set for ${user.email}: real=${real_balance} demo=${demo_balance}`);
  res.json({ message: "Balance updated", user: safeUser(updated) });
});

app.post("/api/admin/credit", authMiddleware, adminOnly, (req, res) => {
  const { uid, amount, account, note } = req.body;
  const amt  = Number(amount);
  const user = db.prepare("SELECT * FROM users WHERE uid=?").get(uid);
  if (!user) return res.status(404).json({ error: "User not found" });
  if (!amt || amt <= 0) return res.status(400).json({ error: "Amount must be greater than 0" });
  const col = account === "demo" ? "demo_balance" : "real_balance";
  db.prepare(`UPDATE users SET ${col}=${col}+? WHERE uid=?`).run(amt, uid);
  db.prepare("INSERT INTO transactions (uid,txid,type,amount,method,status,note) VALUES (?,?,'admin_credit',?,'admin','success',?)").run(uid, "ADM"+Date.now(), amt, note||`Admin credited ₹${amt}`);
  db.prepare("INSERT INTO admin_logs (admin_uid,action,target_uid,details) VALUES (?,?,?,?)").run(req.user.uid, "credit", uid, `+₹${amt} to ${account}`);
  const updated = db.prepare("SELECT * FROM users WHERE uid=?").get(uid);
  console.log(`💰 Credited ₹${amt} to ${account} for ${user.email}`);
  res.json({ message: `₹${amt} credited to ${account} account`, user: safeUser(updated) });
});

// ─── 404 fallback ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

// ─── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════╗`);
  console.log(`║  🚀 TradeX Backend Running             ║`);
  console.log(`║  API  → http://localhost:${PORT}/api      ║`);
  console.log(`║  Open → http://localhost:5173           ║`);
  console.log(`╠════════════════════════════════════════╣`);
  console.log(`║  Admin  admin@tradex.com / admin123     ║`);
  console.log(`║  UPI ID: ${UPI_ID.padEnd(30)}║`);
  console.log(`╚════════════════════════════════════════╝\n`);
});
