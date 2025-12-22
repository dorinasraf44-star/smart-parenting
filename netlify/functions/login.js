import { neon } from "@netlify/neon";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const sql = neon();

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(body),
  };
}

export async function handler(event) {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  try {
    const { email, password } = JSON.parse(event.body || "{}");

    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanPassword = String(password || "");

    if (!cleanEmail || !cleanPassword) {
      return json(400, { error: "חסרים פרטים." });
    }

    const rows =
      await sql`SELECT id, email, password_hash
               FROM users
               WHERE email = ${cleanEmail}
               LIMIT 1;`;

    if (rows.length === 0) {
      return json(401, { error: "פרטי התחברות לא תקינים." });
    }

    const user = rows[0];
    const ok = await bcrypt.compare(cleanPassword, user.password_hash);
    if (!ok) {
      return json(401, { error: "פרטי התחברות לא תקינים." });
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return json(500, { error: "חסר JWT_SECRET ב-Netlify Environment Variables." });
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email },
      secret,
      { expiresIn: "7d" }
    );

    return json(200, { token, user: { id: user.id, email: user.email } });
  } catch (err) {
    return json(500, { error: "שגיאה בשרת (login)." });
  }
}
