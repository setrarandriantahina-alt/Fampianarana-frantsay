// ═══════════════════════════════════════════════════════
//  FrançaisMG PRO — Server Node.js/Express
//  Auth + Subscription 48h + Admin + Anthropic AI Chat
// ═══════════════════════════════════════════════════════
"use strict";

const express  = require("express");
const fs       = require("fs");
const path     = require("path");
const fetch    = require("node-fetch");
const { v4: uuidv4 } = require("uuid");
const bcrypt   = require("bcryptjs");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Anthropic API Key ──────────────────────────────────
// Mametraha ny API key eto, na ao amin'ny env variable:
//   ANTHROPIC_API_KEY=sk-ant-...
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || "METTRE_API_KEY_ICI";

// ── Admin config ───────────────────────────────────────
const ADMIN_CODE   = "5576";
const PAYMENT_TEL  = "+261 33 13 458 51";   // Hidden in frontend
const TRIAL_MS     = 48 * 60 * 60 * 1000;   // 48 heures
const PRICE_LABEL  = "20 000 Ar/mois";

// ── DB file paths ──────────────────────────────────────
const DB_USERS = path.join(__dirname, "data", "users.json");
const DB_MSGS  = path.join(__dirname, "data", "messages.json");

// ── Middlewares ────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── CORS (dev) ─────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Token");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ═══════════════════════════════════════════════════════
//  DB HELPERS
// ═══════════════════════════════════════════════════════
function ensureDir() {
  if (!fs.existsSync(path.join(__dirname, "data"))) {
    fs.mkdirSync(path.join(__dirname, "data"), { recursive: true });
  }
}

function readUsers() {
  ensureDir();
  if (!fs.existsSync(DB_USERS)) return [];
  try { return JSON.parse(fs.readFileSync(DB_USERS, "utf8")); }
  catch { return []; }
}

function writeUsers(users) {
  ensureDir();
  fs.writeFileSync(DB_USERS, JSON.stringify(users, null, 2));
}

function readMessages() {
  ensureDir();
  if (!fs.existsSync(DB_MSGS)) return [];
  try { return JSON.parse(fs.readFileSync(DB_MSGS, "utf8")); }
  catch { return []; }
}

function writeMessages(msgs) {
  ensureDir();
  fs.writeFileSync(DB_MSGS, JSON.stringify(msgs, null, 2));
}

function findUser(email) {
  return readUsers().find(u => u.email.toLowerCase() === email.toLowerCase());
}

function getSubStatus(user) {
  if (!user) return "none";
  if (user.subscribed) return "active";
  if (user.trialStart) {
    const elapsed = Date.now() - user.trialStart;
    if (elapsed < TRIAL_MS) return "trial";
    return "expired";
  }
  return "none";
}

function trialHoursLeft(user) {
  if (!user || !user.trialStart) return 0;
  const elapsed = (Date.now() - user.trialStart) / 3600000;
  return Math.max(0, 48 - elapsed);
}

// Simple token (UUID stored in user record)
function generateToken(user) {
  const users = readUsers();
  const idx = users.findIndex(u => u.email === user.email);
  const token = uuidv4();
  if (idx >= 0) { users[idx].token = token; writeUsers(users); }
  return token;
}

function getUserByToken(token) {
  if (!token) return null;
  return readUsers().find(u => u.token === token) || null;
}

// Middleware: auth required
function requireAuth(req, res, next) {
  const token = req.headers["x-token"];
  const user  = getUserByToken(token);
  if (!user) return res.status(401).json({ error: "Non autorisé" });
  req.user = user;
  next();
}

// Middleware: admin required
function requireAdmin(req, res, next) {
  const code = req.headers["x-admin-code"];
  if (code !== ADMIN_CODE) return res.status(403).json({ error: "Code admin incorrect" });
  next();
}

// Clean user for public response (no password, no raw token)
function publicUser(u) {
  const { passwordHash, token, ...safe } = u;
  safe.subStatus   = getSubStatus(u);
  safe.hoursLeft   = trialHoursLeft(u);
  return safe;
}

// ═══════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════

// POST /register
app.post("/register", async (req, res) => {
  const { name, email, password, level } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Champs manquants" });
  }

  const users = readUsers();
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: "Email déjà utilisé" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = {
    id:           uuidv4(),
    name,
    email:        email.toLowerCase(),
    passwordHash,
    level:        level || "A1",
    xp:           0,
    streak:       1,
    quizDone:     0,
    trialStart:   Date.now(),
    subscribed:   false,
    registeredAt: Date.now(),
    token:        uuidv4(),
  };
  users.push(newUser);
  writeUsers(users);

  res.json({
    success: true,
    token:   newUser.token,
    user:    publicUser(newUser),
  });
});

// POST /login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }

  const users = readUsers();
  const user  = users.find(u => u.email.toLowerCase() === email.toLowerCase());

  if (!user) return res.json({ success: false, error: "Email introuvable" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.json({ success: false, error: "Mot de passe incorrect" });

  // Refresh token
  user.token = uuidv4();
  writeUsers(users);

  res.json({
    success: true,
    token:   user.token,
    user:    publicUser(user),
  });
});

// GET /me  — get current user info
app.get("/me", requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// POST /logout
app.post("/logout", requireAuth, (req, res) => {
  const users = readUsers();
  const idx   = users.findIndex(u => u.email === req.user.email);
  if (idx >= 0) { users[idx].token = null; writeUsers(users); }
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════
//  XP ROUTE
// ═══════════════════════════════════════════════════════
app.post("/xp", requireAuth, (req, res) => {
  const { amount } = req.body;
  if (!amount || typeof amount !== "number") return res.status(400).json({ error: "amount requis" });
  const users = readUsers();
  const idx   = users.findIndex(u => u.email === req.user.email);
  if (idx < 0) return res.status(404).json({ error: "Utilisateur introuvable" });
  users[idx].xp = (users[idx].xp || 0) + amount;
  writeUsers(users);
  res.json({ success: true, xp: users[idx].xp });
});

// ═══════════════════════════════════════════════════════
//  CHAT AI ROUTE  (Anthropic Claude)
// ═══════════════════════════════════════════════════════
app.post("/chat", requireAuth, async (req, res) => {
  const { message, history = [], scenario = "libre" } = req.body;
  if (!message) return res.status(400).json({ error: "message requis" });

  // Check subscription
  const status = getSubStatus(req.user);
  if (status === "expired") {
    return res.status(402).json({
      error:    "subscription_expired",
      message:  "Votre essai de 48h est terminé. Abonnez-vous pour continuer.",
      price:    PRICE_LABEL,
    });
  }

  const SCENARIOS = {
    libre:       "Tu es un professeur de français bienveillant pour apprenants malgaches. Corriges les erreurs poliment. Réponds en français simple.",
    voyage:      "Tu joues le rôle d'un agent à la gare de Paris. L'apprenant veut acheter un billet. Corriges ses erreurs naturellement.",
    restaurant:  "Tu es serveur dans un café parisien. L'apprenant commande un repas. Parle simplement, corriges doucement les fautes.",
    entretien:   "Tu joues un recruteur faisant un entretien d'embauche en français. Sois professionnel, corriges les erreurs à la fin.",
    medecin:     "Tu es médecin généraliste. Le patient décrit ses symptômes. Corriges ses erreurs et réponds avec du vocabulaire médical simple.",
  };

  const systemPrompt = (SCENARIOS[scenario] || SCENARIOS.libre) +
    "\n\nAprès chaque réponse, si l'utilisateur a fait des erreurs, signale-les sous la forme : [CORRECTION: texte corrigé].\nMaximum 3-4 phrases par réponse.";

  // Build messages array (trim history to last 10)
  const messages = [
    ...history.slice(-10),
    { role: "user", content: message },
  ];

  try {
    const apiRes = await fetch("https://api.anthropic.com/v1/messages", {
      method:  "POST",
      headers: {
        "Content-Type":      "application/json",
        "x-api-key":         ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model:      "claude-sonnet-4-20250514",
        max_tokens: 1024,
        system:     systemPrompt,
        messages,
      }),
    });

    const data = await apiRes.json();

    if (!apiRes.ok) {
      console.error("Anthropic error:", data);
      return res.status(500).json({ error: "Erreur API IA", details: data });
    }

    const fullText   = data.content[0].text;
    const corrMatch  = fullText.match(/\[CORRECTION:\s*(.+?)\]/s);
    const reply      = fullText.replace(/\[CORRECTION:.+?\]/s, "").trim();
    const correction = corrMatch ? corrMatch[1].trim() : null;

    // Save message to DB
    const msgs = readMessages();
    msgs.push({
      userId:    req.user.id,
      userMsg:   message,
      aiReply:   reply,
      correction,
      scenario,
      at:        Date.now(),
    });
    // Keep last 1000 messages only
    if (msgs.length > 1000) msgs.splice(0, msgs.length - 1000);
    writeMessages(msgs);

    // Add XP for chatting
    const users = readUsers();
    const idx   = users.findIndex(u => u.email === req.user.email);
    if (idx >= 0) { users[idx].xp = (users[idx].xp || 0) + 5; writeUsers(users); }

    res.json({ reply, correction, xpGained: 5 });

  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ error: "Erreur serveur", details: err.message });
  }
});

// ═══════════════════════════════════════════════════════
//  PHRASE CORRECTION ROUTE
// ═══════════════════════════════════════════════════════
app.post("/correct", requireAuth, async (req, res) => {
  const { phrase } = req.body;
  if (!phrase) return res.status(400).json({ error: "phrase requise" });

  const status = getSubStatus(req.user);
  if (status === "expired") {
    return res.status(402).json({ error: "subscription_expired" });
  }

  try {
    const apiRes = await fetch("https://api.anthropic.com/v1/messages", {
      method:  "POST",
      headers: {
        "Content-Type":      "application/json",
        "x-api-key":         ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model:      "claude-sonnet-4-20250514",
        max_tokens: 600,
        system: `Tu es un professeur de français expert. Analyse la phrase donnée et réponds UNIQUEMENT en JSON:
{"correct":true/false,"corrected":"phrase corrigée","errors":["erreur1"],"explanation":"explication simple en français et malgasy","score":85}
Sois bienveillant et pédagogue.`,
        messages: [{ role: "user", content: `Phrase: "${phrase}"` }],
      }),
    });

    const data = await apiRes.json();
    const txt   = data.content[0].text;
    const clean = txt.replace(/```json|```/g, "").trim();
    const result = JSON.parse(clean);

    // XP
    const users = readUsers();
    const idx = users.findIndex(u => u.email === req.user.email);
    if (idx >= 0) { users[idx].xp = (users[idx].xp || 0) + 10; writeUsers(users); }

    res.json({ ...result, xpGained: 10 });
  } catch (err) {
    res.status(500).json({ error: "Erreur correction", details: err.message });
  }
});

// ═══════════════════════════════════════════════════════
//  SUBSCRIPTION INFO (payment number hidden here)
// ═══════════════════════════════════════════════════════
app.get("/subscription-info", requireAuth, (req, res) => {
  res.json({
    price:       PRICE_LABEL,
    trialHours:  48,
    status:      getSubStatus(req.user),
    hoursLeft:   trialHoursLeft(req.user),
    // Payment number only revealed here (server-side), not in frontend JS
    paymentTel:  PAYMENT_TEL,
    steps: [
      `Envoyez 20 000 Ar par MVola / Orange Money / Airtel`,
      `Numéro destinataire : ${PAYMENT_TEL}`,
      `Référence : votre email d'inscription`,
      `Accès activé sous 24h après confirmation`,
    ],
  });
});

// ═══════════════════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════════════════

// GET /admin/users
app.get("/admin/users", requireAdmin, (req, res) => {
  const users = readUsers().map(u => ({
    id:           u.id,
    name:         u.name,
    email:        u.email,
    level:        u.level,
    xp:           u.xp,
    streak:       u.streak,
    quizDone:     u.quizDone,
    subscribed:   u.subscribed,
    trialStart:   u.trialStart,
    registeredAt: u.registeredAt,
    subStatus:    getSubStatus(u),
    hoursLeft:    trialHoursLeft(u),
  }));

  const stats = {
    total:   users.length,
    trial:   users.filter(u => u.subStatus === "trial").length,
    active:  users.filter(u => u.subStatus === "active").length,
    expired: users.filter(u => u.subStatus === "expired").length,
  };

  res.json({ users, stats, paymentTel: PAYMENT_TEL });
});

// POST /admin/activate/:id
app.post("/admin/activate/:id", requireAdmin, (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: "Utilisateur introuvable" });
  users[idx].subscribed = true;
  writeUsers(users);
  res.json({ success: true, user: publicUser(users[idx]) });
});

// POST /admin/revoke/:id
app.post("/admin/revoke/:id", requireAdmin, (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: "Utilisateur introuvable" });
  users[idx].subscribed = false;
  writeUsers(users);
  res.json({ success: true, user: publicUser(users[idx]) });
});

// DELETE /admin/user/:id
app.delete("/admin/user/:id", requireAdmin, (req, res) => {
  let users = readUsers();
  users = users.filter(u => u.id !== req.params.id);
  writeUsers(users);
  res.json({ success: true });
});

// GET /admin/messages  — last N messages
app.get("/admin/messages", requireAdmin, (req, res) => {
  const msgs = readMessages().slice(-100).reverse();
  res.json({ messages: msgs });
});

// ═══════════════════════════════════════════════════════
//  SERVE FRONTEND
// ═══════════════════════════════════════════════════════
app.get("*", (req, res) => {
  const indexPath = path.join(__dirname, "public", "index.html");
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.send("FrançaisMG PRO — mettez index.html dans /public/");
});

// ═══════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`\n🇫🇷 FrançaisMG PRO server démarré`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Admin code : ${ADMIN_CODE}`);
  console.log(`   Trial      : 48 heures`);
  console.log(`   Prix       : ${PRICE_LABEL}`);
  console.log(`   Paiement   : ${PAYMENT_TEL}\n`);
});
