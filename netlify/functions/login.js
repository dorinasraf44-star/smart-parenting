const { Client } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

function getDbUrl() {
  return process.env.NETLIFY_DATABASE_URL || process.env.NETLIFY_DATABASE_URL_UNPOOLED;
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: JSON.stringify({ error: "Method not allowed" }) };
    }

    const body = JSON.parse(event.body || "{}");
    const { email, password } = body;

    if (!email || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: "Missing email or password" }) };
    }

    const dbUrl = getDbUrl();
    if (!dbUrl) {
      return { statusCode: 500, body: JSON.stringify({ error: "Database URL missing in env" }) };
    }

    const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();

    const r = await client.query(
      `SELECT id, email, password_hash, full_name, user_type, children_count, pregnancy_week, created_at
       FROM users
       WHERE email = $1
       LIMIT 1;`,
      [email.toLowerCase()]
    );

    await client.end();

    if (!r.rows.length) {
      return { statusCode: 401, body: JSON.stringify({ error: "פרטי התחברות לא תקינים." }) };
    }

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return { statusCode: 401, body: JSON.stringify({ error: "פרטי התחברות לא תקינים." }) };
    }

    const token = jwt.sign(
      { user_id: user.id, email: user.email },
      process.env.JWT_SECRET || "dev_secret_change_me",
      { expiresIn: "7d" }
    );

    // לא מחזירים password_hash ללקוח
    delete user.password_hash;

    return {
      statusCode: 200,
      body: JSON.stringify({ token, user })
    };

  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: "Server error", details: String(err) }) };
  }
};
