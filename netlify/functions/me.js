import { neon } from "@netlify/neon";

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

export async function handler(event) {
  const auth = event.headers.authorization || event.headers.Authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!token) return json(401, { error: "Missing token" });

  const sql = neon();

  try {
    const [row] = await sql`
      SELECT u.id, u.email
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ${token}::uuid
        AND s.expires_at > now();
    `;
    if (!row) return json(401, { error: "Invalid/expired token" });

    return json(200, { ok: true, user: row });
  } catch (e) {
    return json(500, { error: "Server error", details: String(e?.message || e) });
  }
}
