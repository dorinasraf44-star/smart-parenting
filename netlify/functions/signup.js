import { neon } from "@netlify/neon";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export default async (req, context) => {
  try {
    if (req.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405,
        headers: { "Content-Type": "application/json" },
      });
    }

    const { email, password } = await req.json();
    const cleanEmail = (email || "").trim().toLowerCase();

    if (!cleanEmail || !password || password.length < 6) {
      return new Response(JSON.stringify({ error: "Invalid input" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const sql = neon(); // uses NETLIFY_DATABASE_URL automatically

    // create table if not exists
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `;

    // check existing
    const existing = await sql`SELECT id FROM users WHERE email = ${cleanEmail} LIMIT 1;`;
    if (existing.length) {
      return new Response(JSON.stringify({ error: "Email already registered" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      });
    }

    const hash = await bcrypt.hash(password, 10);
    const inserted = await sql`
      INSERT INTO users (email, password_hash)
      VALUES (${cleanEmail}, ${hash})
      RETURNING id, email, created_at;
    `;

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return new Response(JSON.stringify({ error: "Missing JWT_SECRET env var" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    const token = jwt.sign(
      { userId: inserted[0].id, email: inserted[0].email },
      secret,
      { expiresIn: "7d" }
    );

    return new Response(JSON.stringify({ token, user: inserted[0] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: "Server error", details: String(e?.message || e) }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
};
