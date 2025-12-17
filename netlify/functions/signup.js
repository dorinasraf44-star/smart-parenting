import { neon } from "@netlify/neon";
import crypto from "crypto";

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

export async function handler(event) {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  let data;
  try { data = JSON.parse(event.body || "{}"); }
  catch { return json(400, { error: "Invalid JSON" }); }

  const email = (data.email || "").trim().toLowerCase();
  const password = data.password || "";

  if (!email || password.length < 6) {
    return json(400, { error: "Email required + password min 6 chars" });
  }

  const sql = neon(); // uses NETLIFY_DATABASE_URL automatically

  try {
    const password_hash = hashPassword(password);

    const [user] = await sql`
      INSERT INTO users (email, password_hash)
      VALUES (${email}, ${password_hash})
      RETURNING id, email, created_at;
    `;

    // create session token
    const [session] = await sql`
      INSERT INTO sessions (user_id)
      VALUES (${user.id})
      RETURNING token, expires_at;
    `;

    return json(200, { ok: true, token: session.token, user: { id: user.id, email: user.email } });
  } catch (e) {
    const msg = String(e?.message || e);
    if (msg.includes("users_email_key") || msg.includes("duplicate key")) {
      return json(409, { error: "Email already exists" });
    }
    return json(500, { error: "Server error", details: msg });
  }
}
