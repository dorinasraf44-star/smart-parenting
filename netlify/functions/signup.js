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
    const { email, password, full_name, user_type, children_count, pregnancy_week } = body;

    if (!email || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: "Missing email or password" }) };
    }
    if (!full_name || !user_type) {
      return { statusCode: 400, body: JSON.stringify({ error: "Missing profile fields" }) };
    }

    const dbUrl = getDbUrl();
    if (!dbUrl) {
      return { statusCode: 500, body: JSON.stringify({ error: "Database URL missing in env" }) };
    }

    const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();

    const hashed = await bcrypt.hash(password, 10);

    // IMPORTANT: מניחים שיש לך עמודות: full_name, user_type, children_count, pregnancy_week
    const q = `
      INSERT INTO users (email, password_hash, full_name, user_type, children_count, pregnancy_week)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, email, full_name, user_type, children_count, pregnancy_week, created_at;
    `;

    const values = [
      email.toLowerCase(),
      hashed,
      full_name,
      user_type,
      Number.isFinite(children_count) ? children_count : 0,
      pregnancy_week === null || pregnancy_week === undefined ? null : pregnancy_week
    ];

    let row;
    try {
      const r = await client.query(q, values);
      row = r.rows[0];
    } catch (e) {
      // אם email ייחודי אצלך -> זה ייפול פה
      await client.end();
      return { statusCode: 400, body: JSON.stringify({ error: "אימייל כבר קיים במערכת." }) };
    }

    await client.end();

    const token = jwt.sign(
      { user_id: row.id, email: row.email },
      process.env.JWT_SECRET || "dev_secret_change_me",
      { expiresIn: "7d" }
    );

    return {
      statusCode: 200,
      body: JSON.stringify({ token, user: row })
    };

  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: "Server error", details: String(err) }) };
  }
};
