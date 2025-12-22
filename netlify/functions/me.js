const { Client } = require("pg");
const jwt = require("jsonwebtoken");

function getDbUrl() {
  return process.env.NETLIFY_DATABASE_URL || process.env.NETLIFY_DATABASE_URL_UNPOOLED;
}

function getToken(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== "GET") {
      return { statusCode: 405, body: JSON.stringify({ error: "Method not allowed" }) };
    }

    const token = getToken(event);
    if (!token) {
      return { statusCode: 401, body: JSON.stringify({ error: "Missing token" }) };
    }

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET || "dev_secret_change_me");
    } catch (e) {
      return { statusCode: 401, body: JSON.stringify({ error: "Invalid token" }) };
    }

    const dbUrl = getDbUrl();
    if (!dbUrl) {
      return { statusCode: 500, body: JSON.stringify({ error: "Database URL missing in env" }) };
    }

    const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();

    const r = await client.query(
      `SELECT id, email, full_name, user_type, children_count, pregnancy_week, created_at
       FROM users
       WHERE id = $1
       LIMIT 1;`,
      [payload.user_id]
    );

    await client.end();

    if (!r.rows.length) {
      return { statusCode: 404, body: JSON.stringify({ error: "User not found" }) };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ user: r.rows[0] })
    };

  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: "Server error", details: String(err) }) };
  }
};
