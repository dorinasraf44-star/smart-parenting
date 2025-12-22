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

  if (!email || !email.includes("@")) return json(400, { error: "אימייל לא תקין." });
  if (!password) return json(400, { error: "חסרה סיסמה." });

  const dbUrl = getDbUrl();
  if (!dbUrl) return json(500, { error: "Missing NETLIFY_DATABASE_URL env var" });

  const client = new Client({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false },
  });

  try {
    await client.connect();

    const result = await client.query(
      `SELECT id, email, password_hash, full_name, user_type, children_count, pregnancy_week, children_names, created_at
       FROM users
       WHERE email=$1`,
      [email]
    );

    if (result.rows.length === 0) {
      return json(401, { error: "פרטי התחברות לא תקינים." });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return json(401, { error: "פרטי התחברות לא תקינים." });

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // לא מחזירים hash
    delete user.password_hash;

    return json(200, { token, user });
  } catch (err) {
    console.error(err);
    return json(500, { error: "Server error" });
  } finally {
    try { await client.end(); } catch {}
  }
};
