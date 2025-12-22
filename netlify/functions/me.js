const { Client } = require("pg");
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

function getToken(event) {
  const auth = event.headers.authorization || event.headers.Authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return "";
}

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return json(405, { error: "Method not allowed" });
  }

  const JWT_SECRET = process.env.JWT_SECRET;
  if (!JWT_SECRET) {
    return json(500, { error: "Missing JWT_SECRET env var in Netlify" });
  }

  const token = getToken(event);
  if (!token) return json(401, { error: "Missing token" });

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch {
    return json(401, { error: "Invalid token" });
  }

  const dbUrl = getDbUrl();
  if (!dbUrl) return json(500, { error: "Missing NETLIFY_DATABASE_URL env var" });

  const client = new Client({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false },
  });

  try {
    await client.connect();

    const result = await client.query(
      `SELECT id, email, full_name, user_type, children_count, pregnancy_week, children_names, created_at
       FROM users WHERE id=$1`,
      [decoded.userId]
    );

    if (result.rows.length === 0) return json(404, { error: "User not found" });

    return json(200, { user: result.rows[0] });
  } catch (err) {
    console.error(err);
    return json(500, { error: "Server error" });
  } finally {
    try { await client.end(); } catch {}
  }
};
