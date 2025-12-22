import { neon } from "@netlify/neon";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const sql = neon();

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  };
}

function isInt(n) {
  return Number.isInteger(n) && n >= 0;
}

export async function handler(event) {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  try {
    const body = JSON.parse(event.body || "{}");

    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    const full_name = String(body.full_name || "").trim();
    const user_type = String(body.user_type || "").trim(); // 'pregnant' | 'parent'

    // אופציונלי לפי סוג
    const pregnancy_week_raw = body.pregnancy_week;
    const children_names_raw = Array.isArray(body.children_names) ? body.children_names : [];

    if (!email || !email.includes("@")) return json(400, { error: "אימייל לא תקין." });
    if (password.length < 6) return json(400, { error: "הסיסמה חייבת להיות לפחות 6 תווים." });
    if (!full_name) return json(400, { error: "חסר שם." });
    if (user_type !== "pregnant" && user_type !== "parent") {
      return json(400, { error: "סוג משתמש לא תקין." });
    }

    // בדיקת משתמש קיים
    const existing = await sql`SELECT id FROM users WHERE email = ${email} LIMIT 1;`;
    if (existing.length > 0) return json(409, { error: "המשתמש כבר קיים. נסי להתחבר." });

    // ולידציה לפי סוג
    let pregnancy_week = null;
    let children_names = [];

    if (user_type === "pregnant") {
      const pw = Number(pregnancy_week_raw);
      if (!Number.isFinite(pw) || !Number.isInteger(pw) || pw < 1 || pw > 45) {
        return json(400, { error: "שבוע הריון חייב להיות מספר בין 1 ל-45." });
      }
      pregnancy_week = pw;
    }

    if (user_type === "parent") {
      children_names = children_names_raw
        .map((x) => String(x || "").trim())
        .filter((x) => x.length > 0);

      if (children_names.length === 0) {
        return json(400, { error: "להורה לילדים צריך להזין לפחות שם ילד אחד." });
      }
      if (children_names.length > 10) {
        return json(400, { error: "אפשר עד 10 ילדים בשלב הזה." });
      }
    }

    const password_hash = await bcrypt.hash(password, 10);

    // יוצרים משתמש עם שדות פרופיל בסיסיים
    const inserted = await sql`
      INSERT INTO users (email, password_hash, full_name, user_type, pregnancy_week, children_count)
      VALUES (
        ${email},
        ${password_hash},
        ${full_name},
        ${user_type},
        ${pregnancy_week},
        ${user_type === "parent" ? children_names.length : null}
      )
      RETURNING id, email, full_name, user_type, pregnancy_week, children_count, created_at;
    `;

    const user = inserted[0];

    // אם parent – מוסיפים ילדים לטבלת children
    if (user_type === "parent") {
      for (const name of children_names) {
        await sql`INSERT INTO children (user_id, child_name) VALUES (${user.id}, ${name});`;
      }
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) return json(500, { error: "חסר JWT_SECRET ב-Netlify Environment Variables." });

    const token = jwt.sign({ sub: user.id, email: user.email }, secret, { expiresIn: "7d" });

    return json(200, {
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        user_type: user.user_type,
        pregnancy_week: user.pregnancy_week,
        children_count: user.children_count,
        created_at: user.created_at,
      },
    });
  } catch (e) {
    return json(500, { error: "שגיאה בשרת (signup)." });
  }
}
