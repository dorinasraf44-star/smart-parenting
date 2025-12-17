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

    if (!cleanEmail || !password) {
      return new Response(JSON.stringify({ error: "Invalid input" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const sql = neon();

    const rows = await sql`
      SELECT id, email, password_hash, created_at
      FROM users
      WHERE email = ${cleanEmail}
      LIMIT 1;
    `;

    if (!rows.length) {
      return new Response(JSON.stringify({ error: "Email or password incorrect" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) {
      return new Response(JSON.stringify({ error: "Email or password incorrect" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return new Response(JSON.stringify({ error: "Missing JWT_SECRET env var" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    const token = jwt.sign(
      { userId: rows[0].id, email: rows[0].email },
      secret,
      { expiresIn: "7d" }
    );

    return new Response(JSON.stringify({
      token,
      user: { id: rows[0].id, email: rows[0].email, created_at: rows[0].created_at }
    }), {
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
