const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

const error = (message, status = 400) =>
  json({ success: false, error: message }, status);

const nowISO = () => new Date().toISOString();

const makeId = () => crypto.randomUUID();

const hex = (buffer) =>
  Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const fromHex = (value) =>
  new Uint8Array(value.match(/.{1,2}/g).map((b) => parseInt(b, 16)));

async function sha256(value) {
  return hex(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(value)
    )
  );
}

async function hashPassword(password, saltHex) {
  const salt = fromHex(saltHex);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return hex(result);
}

async function createPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = hex(salt);

  return {
    salt: saltHex,
    hash: await hashPassword(password, saltHex)
  };
}

function sameString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;

  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);

  if (x.length !== y.length) return false;

  let diff = 0;

  for (let i = 0; i < x.length; i++) {
    diff |= x[i] ^ y[i];
  }

  return diff === 0;
}

function validText(value, max = 120) {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.trim().length <= max;
}

function validCoordinates(lat, lng) {
  return Number.isFinite(lat) &&
    Number.isFinite(lng) &&
    lat >= -90 &&
    lat <= 90 &&
    lng >= -180 &&
    lng <= 180;
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin");

  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };

  // Replace this with your exact production website origin
  // before enabling cross-origin requests.
  if (origin && origin === "https://lubri-fieldtrack.pages.dev") {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

function responseWithCors(response, request) {
  const headers = new Headers(response.headers);

  for (const [key, value] of Object.entries(corsHeaders(request))) {
    headers.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    headers
  });
}

async function readBody(request) {
  try {
    const body = await request.json();

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return null;
    }

    return body;
  } catch {
    return null;
  }
}

async function getSession(request, env) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);

  if (!match) return null;

  const token = match[1];

  if (token.length < 32 || token.length > 200) return null;

  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  const session = await env.DB.prepare(`
    SELECT s.role, s.employee_id, e.name, e.username
    FROM sessions s
    LEFT JOIN employees e ON e.id = s.employee_id
    WHERE s.token_hash = ?
      AND s.expires_at > ?
  `).bind(tokenHash, now).first();

  if (!session) return null;

  if (session.role === "employee" && !session.employee_id) {
    return null;
  }

  return {
    tokenHash,
    role: session.role,
    employeeId: session.employee_id,
    name: session.name,
    username: session.username
  };
}

async function createSession(env, role, employeeId = null) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = hex(tokenBytes);
  const tokenHash = await sha256(token);

  const expiresAt = Math.floor(Date.now() / 1000) + 60 * 60 * 12;

  await env.DB.prepare(`
    INSERT INTO sessions (token_hash, employee_id, role, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(tokenHash, employeeId, role, expiresAt).run();

  return {
    token,
    expiresAt
  };
}

async function requireSession(request, env) {
  const session = await getSession(request, env);

  if (!session) {
    return {
      response: error("Please log in again.", 401)
    };
  }

  return { session };
}

async function requireAdmin(request, env) {
  const result = await requireSession(request, env);

  if (result.response) return result;

  if (result.session.role !== "admin") {
    return {
      response: error("Admin access required.", 403)
    };
  }

  return result;
}

async function handle(request, env) {
  if (!env.DB) {
    return error("Database is not configured.", 500);
  }

  if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) {
    return error("Admin credentials are not configured.", 500);
  }

  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;

  if (method === "GET" && path === "/api/health") {
    return json({
      success: true,
      service: "LUBRI FieldTrack",
      time: nowISO()
    });
  }

  // EMPLOYEE REGISTRATION
  if (method === "POST" && path === "/api/register") {
    const body = await readBody(request);

    if (!body) return error("Invalid request body.");

    const name = typeof body.name === "string" ? body.name.trim() : "";
    const phone = typeof body.phone === "string" ? body.phone.trim() : "";
    const employeeId = typeof body.employeeId === "string"
      ? body.employeeId.trim()
      : "";
    const username = typeof body.username === "string"
      ? body.username.trim().toLowerCase()
      : "";
    const password = body.password;

    if (!validText(name, 100)) {
      return error("Enter a valid employee name.");
    }

    if (!/^[0-9+\-\s()]{7,20}$/.test(phone)) {
      return error("Enter a valid phone number.");
    }

    if (!/^[A-Za-z0-9_-]{2,40}$/.test(employeeId)) {
      return error("Employee ID must be 2-40 letters, numbers, _ or -.");
    }

    if (!/^[a-z0-9_.-]{3,40}$/.test(username)) {
      return error("Username must be 3-40 characters.");
    }

    if (typeof password !== "string" || password.length < 10 || password.length > 128) {
      return error("Password must be 10-128 characters.");
    }

    const existing = await env.DB.prepare(`
      SELECT id FROM employees
      WHERE username = ? OR employee_id = ?
    `).bind(username, employeeId).first();

    if (existing) {
      return error("Username or Employee ID already exists.", 409);
    }

    const passwordData = await createPassword(password);
    const id = makeId();

    await env.DB.prepare(`
      INSERT INTO employees
        (id, name, phone, employee_id, username, password_hash, password_salt)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      name,
      phone,
      employeeId,
      username,
      passwordData.hash,
      passwordData.salt
    ).run();

    return json({
      success: true,
      message: "Registration successful. You can now log in."
    }, 201);
  }

  // LOGIN: EMPLOYEE OR ADMIN
  if (method === "POST" && path === "/api/login") {
    const body = await readBody(request);

    if (!body) return error("Invalid request body.");

    const username = typeof body.username === "string"
      ? body.username.trim()
      : "";
    const password = body.password;

    if (!username || typeof password !== "string" ||
        username.length > 120 || password.length > 128) {
      return error("Enter your username and password.", 400);
    }

    if (
      sameString(username, env.ADMIN_USERNAME) &&
      sameString(password, env.ADMIN_PASSWORD)
    ) {
      const session = await createSession(env, "admin");

      return json({
        success: true,
        role: "admin",
        token: session.token,
        expiresAt: session.expiresAt
      });
    }

    const employee = await env.DB.prepare(`
      SELECT id, name, phone, employee_id, username,
             password_hash, password_salt
      FROM employees
      WHERE username = ?
    `).bind(username.toLowerCase()).first();

    if (!employee) {
      return error("Invalid username or password.", 401);
    }

    const candidateHash = await hashPassword(
      password,
      employee.password_salt
    );

    if (!sameString(candidateHash, employee.password_hash)) {
      return error("Invalid username or password.", 401);
    }

    const session = await createSession(env, "employee", employee.id);

    return json({
      success: true,
      role: "employee",
      token: session.token,
      expiresAt: session.expiresAt,
      employee: {
        id: employee.id,
        name: employee.name,
        phone: employee.phone,
        employeeId: employee.employee_id,
        username: employee.username
      }
    });
  }

  // ALL ROUTES BELOW REQUIRE LOGIN
  const auth = await requireSession(request, env);

  if (auth.response) return auth.response;

  const session = auth.session;

  // LOGOUT
  if (method === "POST" && path === "/api/logout") {
    await env.DB.prepare(`
      DELETE FROM sessions WHERE token_hash = ?
    `).bind(session.tokenHash).run();

    return json({ success: true });
  }

  // GET OWN PROFILE
  if (method === "GET" && path === "/api/profile") {
    if (session.role !== "employee") {
      return error("Employee login required.", 403);
    }

    const employee = await env.DB.prepare(`
      SELECT id, name, phone, employee_id, username
      FROM employees WHERE id = ?
    `).bind(session.employeeId).first();

    if (!employee) return error("Employee not found.", 404);

    return json({ success: true, employee });
  }

  // UPDATE OWN PROFILE
  if (method === "PATCH" && path === "/api/profile") {
    if (session.role !== "employee") {
      return error("Employee login required.", 403);
    }

    const body = await readBody(request);

    if (!body) return error("Invalid request body.");

    const name = typeof body.name === "string" ? body.name.trim() : "";
    const phone = typeof body.phone === "string" ? body.phone.trim() : "";

    if (!validText(name, 100)) return error("Enter a valid name.");
    if (!/^[0-9+\-\s()]{7,20}$/.test(phone)) {
      return error("Enter a valid phone number.");
    }

    await env.DB.prepare(`
      UPDATE employees SET name = ?, phone = ?
      WHERE id = ?
    `).bind(name, phone, session.employeeId).run();

    return json({ success: true, message: "Profile updated." });
  }

  // EMPLOYEE CHECK-IN
  if (method === "POST" && path === "/api/visits/check-in") {
    if (session.role !== "employee") {
      return error("Employee login required.", 403);
    }

    const body = await readBody(request);

    if (!body) return error("Invalid request body.");

    const companyName = typeof body.companyName === "string"
      ? body.companyName.trim()
      : "";
    const lat = Number(body.latitude);
    const lng = Number(body.longitude);

    if (!validText(companyName, 150)) {
      return error("Enter a company name.");
    }

    if (!validCoordinates(lat, lng)) {
      return error("Valid GPS coordinates are required.");
    }

    const openVisit = await env.DB.prepare(`
      SELECT id FROM visits
      WHERE employee_id = ? AND check_out_time IS NULL
      LIMIT 1
    `).bind(session.employeeId).first();

    if (openVisit) {
      return error("Please check out of your current visit first.", 409);
    }

    const id = makeId();
    const timestamp = nowISO();
    const date = timestamp.slice(0, 10);

    await env.DB.prepare(`
      INSERT INTO visits
        (id, employee_id, company_name, check_in_time,
         check_in_lat, check_in_lng, visit_date)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      session.employeeId,
      companyName,
      timestamp,
      lat,
      lng,
      date
    ).run();

    return json({
      success: true,
      message: "Check-in recorded.",
      visitId: id,
      checkInTime: timestamp,
      latitude: lat,
      longitude: lng
    }, 201);
  }

  // EMPLOYEE CHECK-OUT
  if (method === "POST" && path === "/api/visits/check-out") {
    if (session.role !== "employee") {
      return error("Employee login required.", 403);
    }

    const body = await readBody(request);

    if (!body) return error("Invalid request body.");

    const lat = Number(body.latitude);
    const lng = Number(body.longitude);

    if (!validCoordinates(lat, lng)) {
      return error("Valid GPS coordinates are required.");
    }

    const visit = await env.DB.prepare(`
      SELECT id FROM visits
      WHERE employee_id = ? AND check_out_time IS NULL
      ORDER BY check_in_time DESC
      LIMIT 1
    `).bind(session.employeeId).first();

    if (!visit) {
      return error("No active visit found.", 404);
    }

    const timestamp = nowISO();

    await env.DB.prepare(`
      UPDATE visits
      SET check_out_time = ?, check_out_lat = ?, check_out_lng = ?
      WHERE id = ? AND employee_id = ? AND check_out_time IS NULL
    `).bind(
      timestamp,
      lat,
      lng,
      visit.id,
      session.employeeId
    ).run();

    return json({
      success: true,
      message: "Check-out recorded.",
      checkOutTime: timestamp,
      latitude: lat,
      longitude: lng
    });
  }

  // EMPLOYEE: VIEW OWN VISITS
  if (method === "GET" && path === "/api/visits") {
    if (session.role !== "employee") {
      return error("Employee login required.", 403);
    }

    const date = url.searchParams.get("date");

    let result;

    if (date && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
      result = await env.DB.prepare(`
        SELECT id, company_name, check_in_time,
               check_in_lat, check_in_lng, check_out_time,
               check_out_lat, check_out_lng, visit_date
        FROM visits
        WHERE employee_id = ? AND visit_date = ?
        ORDER BY check_in_time DESC
        LIMIT 500
      `).bind(session.employeeId, date).all();
    } else {
      result = await env.DB.prepare(`
        SELECT id, company_name, check_in_time,
               check_in_lat, check_in_lng, check_out_time,
               check_out_lat, check_out_lng, visit_date
        FROM visits
        WHERE employee_id = ?
        ORDER BY check_in_time DESC
        LIMIT 500
      `).bind(session.employeeId).all();
    }

    return json({ success: true, visits: result.results });
  }

  // ADMIN: LIST EMPLOYEES
  if (method === "GET" && path === "/api/admin/employees") {
    if (session.role !== "admin") {
      return error("Admin access required.", 403);
    }

    const result = await env.DB.prepare(`
      SELECT e.id, e.name, e.phone, e.employee_id, e.username,
        (
          SELECT v.company_name FROM visits v
          WHERE v.employee_id = e.id AND v.check_out_time IS NULL
          ORDER BY v.check_in_time DESC LIMIT 1
        ) AS current_company,
        (
          SELECT v.check_in_time FROM visits v
          WHERE v.employee_id = e.id AND v.check_out_time IS NULL
          ORDER BY v.check_in_time DESC LIMIT 1
        ) AS current_check_in
      FROM employees e
      ORDER BY e.name
      LIMIT 1000
    `).all();

    return json({ success: true, employees: result.results });
  }

  // ADMIN: VIEW ALL VISITS
  if (method === "GET" && path === "/api/admin/visits") {
    if (session.role !== "admin") {
      return error("Admin access required.", 403);
    }

    const date = url.searchParams.get("date");

    let result;

    if (date && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
      result = await env.DB.prepare(`
        SELECT v.*, e.name AS employee_name,
               e.employee_id AS employee_code
        FROM visits v
        JOIN employees e ON e.id = v.employee_id
        WHERE v.visit_date = ?
        ORDER BY v.check_in_time DESC
        LIMIT 2000
      `).bind(date).all();
    } else {
      result = await env.DB.prepare(`
        SELECT v.*, e.name AS employee_name,
               e.employee_id AS employee_code
        FROM visits v
        JOIN employees e ON e.id = v.employee_id
        ORDER BY v.check_in_time DESC
        LIMIT 2000
      `).all();
    }

    return json({ success: true, visits: result.results });
  }

  // ADMIN: UPDATE EMPLOYEE DETAILS
  const editMatch = path.match(/^\/api\/admin\/employees\/([^/]+)$/);

  if (editMatch && method === "PATCH") {
    const admin = await requireAdmin(request, env);
    if (admin.response) return admin.response;

    const employeeId = decodeURIComponent(editMatch[1]);
    const body = await readBody(request);

    if (!body) return error("Invalid request body.");

    const name = typeof body.name === "string" ? body.name.trim() : "";
    const phone = typeof body.phone === "string" ? body.phone.trim() : "";

    if (!validText(name, 100)) return error("Enter a valid name.");
    if (!/^[0-9+\-\s()]{7,20}$/.test(phone)) {
      return error("Enter a valid phone number.");
    }

    const result = await env.DB.prepare(`
      UPDATE employees SET name = ?, phone = ?
      WHERE id = ?
    `).bind(name, phone, employeeId).run();

    if (!result.meta.changes) {
      return error("Employee not found.", 404);
    }

    return json({ success: true, message: "Employee updated." });
  }

  // ADMIN: PERMANENTLY DELETE EMPLOYEE + VISITS + SESSIONS
  if (editMatch && method === "DELETE") {
    const admin = await requireAdmin(request, env);
    if (admin.response) return admin.response;

    const employeeId = decodeURIComponent(editMatch[1]);

    await env.DB.prepare(`
      DELETE FROM sessions WHERE employee_id = ?
    `).bind(employeeId).run();

    const result = await env.DB.prepare(`
      DELETE FROM employees WHERE id = ?
    `).bind(employeeId).run();

    if (!result.meta.changes) {
      return error("Employee not found.", 404);
    }

    // Visits are deleted automatically through ON DELETE CASCADE.
    return json({
      success: true,
      message: "Employee and associated records permanently deleted."
    });
  }

  return error("Route not found.", 404);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request)
      });
    }

    try {
      const response = await handle(request, env);
      return responseWithCors(response, request);
    } catch (err) {
      console.error("FieldTrack request failed:", err);
      return responseWithCors(
        error("An internal server error occurred.", 500),
        request
      );
    }
  }
};
