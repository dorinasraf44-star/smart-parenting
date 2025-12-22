const { Client } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

function getDbUrl() {
  // Netlify DB (Neon extension) בד"כ נותן את שניהם
  return (
    process.env.NETLIFY_DATABASE_URL_UNPOOLED ||
    process.env.NETLIFY_DATABASE_URL
  );
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  const JWT_SECRET = process.env.JWT_SECRET;
  if (!JWT_SECRET) {
    return json(500, { error: "Missing JWT_SECRET env var in Netlify" });
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { error: "Invalid JSON" });
  }

  const email = (payload.email || "").trim().toLowerCase();
  const password = payload.password || "";

  const fullName = (payload.fullName || "").trim();
  const userType = payload.userType; // 'pregnant' | 'parent'
  const childrenCount = Number.isFinite(Number(payload.childrenCount))
    ? Number(payload.childrenCount)
    : 0;

  const pregnancyWeek =
    payload.pregnancyWeek === "" || payload.pregnancyWeek === null || payload.pregnancyWeek === undefined
      ? null
      : Number(payload.pregnancyWeek);

  // childrenNames מגיע כ-array של מחרוזות
  const childrenNames = Array.isArray(payload.childrenNames)
    ? payload.childrenNames.map((x) => String(x || "").trim()).filter(Boolean)
    : [];

  if (!email || !email.includes("@")) return json(400, { error: "אימייל לא תקין." });
  if (!password || password.length < 6) return json(400, { error: "הסיסמה חייבת להיות לפחות 6 תווים." });
  if (!fullName) return json(400, { error: "חובה למלא שם." });
  if (userType !== "pregnant" && userType !== "parent") {
    return json(400, { error: "סוג משתמש לא תקין." });
  }

  if (userType === "pregnant") {
    if (!Number.isFinite(pregnancyWeek) || pregnancyWeek < 1 || pregnancyWeek > 45) {
      return json(400, { error: "שבוע הריון חייב להיות מספר בין 1 ל-45." });
    }
  }

  if (userType === "parent") {
    if (!Number.isFinite(childrenCount) || childrenCount < 0 || childrenCount > 20) {
      return json(400, { error: "מספר ילדים לא תקין." });
    }
    // לא חובה שמות, אבל אם נתנו—נשמור
    if (childrenCount === 0 && childrenNames.length > 0) {
      // לא נכשיל, רק ננקה
    }
  }

  const dbUrl = getDbUrl();
  if (!dbUrl) return json(500, { error: "Missing NETLIFY_DATABASE_URL env var" });

  const client = new Client({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false },
  });

  try {
    await client.connect();

    const existing = await client.query("SELECT id FROM users WHERE email=$1", [email]);
    if (existing.rows.length > 0) {
      return json(409, { error: "האימייל כבר רשום במערכת." });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const insert = await client.query(
      `
      INSERT INTO users (email, password_hash, full_name, user_type, children_count, pregnancy_week, children_names, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7, NOW())
      RETURNING id, email, full_name, user_type, children_count, pregnancy_week, children_names, created_at
      `,
      [
        email,
        passwordHash,
        fullName,
        userType,
        userType === "parent" ? childrenCount : 0,
        userType === "pregnant" ? pregnancyWeek : null,
        JSON.stringify(userType === "parent" ? childrenNames : []),
      ]
    );

    const user = insert.rows[0];

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return json(200, { token, user });
  } catch (err) {
    console.error(err);
    return json(500, { error: "Server error" });
  } finally {
    try { await client.end(); } catch {}
  }
};
