import { neon } from "@netlify/neon";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const sql = neon(); // משתמש אוטומטית ב-NETLIFY_DATABASE_URL

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

    if (!cleanEmail || !cleanEmail.includes("@")) {
      return json(400, { error: "אימייל לא תקין." });
    }
    if (cleanPassword.length < 6) {
      return json(400, { error: "הסיסמה חייבת להיות לפחות 6 תווים." });
    }

    // האם משתמש קיים?
    const existing = await sql`SELECT id FROM users WHERE email = ${cleanEmail} LIMIT 1;`;
    if (existing.length > 0) {
      return json(409, { error: "המשתמש כבר קיים. נסי להתחבר." });
    }

    const password_hash = await bcrypt.hash(cleanPassword, 10);

    const inserted =
      await sql`INSERT INTO users (email, password_hash)
               VALUES (${cleanEmail}, ${password_hash})
               RETURNING id, email, created_at;`;

    const user = inserted[0];

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return json(500, { error: "חסר JWT_SECRET ב-Netlify Environment Variables." });
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email },
      secret,
      { expiresIn: "7d" }
    );

    return json(200, { token, user: { id: user.id, email: user.email, created_at: user.created_at } });
  } catch (err) {
    return json(500, { error: "שגיאה בשרת (signup)." });
  }
}
