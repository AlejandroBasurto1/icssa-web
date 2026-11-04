import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405, headers: cors });

  const url = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const authHeader = req.headers.get("Authorization") || "";
  const admin = createClient(url, serviceKey, { auth: { persistSession: false } });
  const token = authHeader.replace(/^Bearer\s+/i, "");
  const { data: { user }, error: authError } = await admin.auth.getUser(token);
  if (authError || !user) return Response.json({ error: "No autorizado" }, { status: 401, headers: cors });

  const { data: profile } = await admin.from("profiles").select("role,active").eq("id", user.id).maybeSingle();
  if (!profile || profile.role !== "admin" || !profile.active) {
    return Response.json({ error: "Solo el administrador puede crear usuarios" }, { status: 403, headers: cors });
  }

  const body = await req.json().catch(() => ({}));
  const fullName = String(body.full_name || "").trim();
  const username = String(body.username || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "");
  const role = ["editor", "viewer"].includes(body.role) ? body.role : "viewer";
  if (!fullName || !username || username.length < 3) {
    return Response.json({ error: "Indica nombre y usuario (mínimo 3 caracteres)" }, { status: 400, headers: cors });
  }

  // Contraseña temporal de 8 caracteres: Supabase normalmente exige al menos 6.
  // El usuario deberá cambiarla al entrar por primera vez.
  const email = username + "@usuarios.icssa.local";
  const { data, error } = await admin.auth.admin.createUser({
    email, password: "1234ICSSA", email_confirm: true,
    user_metadata: { full_name: fullName, username, must_change_password: true }
  });
  if (error) return Response.json({ error: error.message }, { status: 400, headers: cors });

  const { error: profileError } = await admin.from("profiles").upsert({
    id: data.user.id, full_name: fullName, username, role, active: true, must_change_password: true
  });
  if (profileError) {
    await admin.auth.admin.deleteUser(data.user.id);
    return Response.json({ error: profileError.message }, { status: 400, headers: cors });
  }
  return Response.json({ id: data.user.id, username, role, temporary_password: "1234ICSSA" }, { headers: cors });
});
