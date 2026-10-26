PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS employees (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    employee_id TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    employee_id TEXT,
    role TEXT NOT NULL CHECK (role IN ('admin', 'employee')),
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (employee_id)
        REFERENCES employees(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS visits (
    id TEXT PRIMARY KEY,
    employee_id TEXT NOT NULL,
    company_name TEXT NOT NULL,
    check_in_time TEXT NOT NULL,
    check_in_lat REAL NOT NULL,
    check_in_lng REAL NOT NULL,
    check_out_time TEXT,
    check_out_lat REAL,
    check_out_lng REAL,
    visit_date TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (employee_id)
        REFERENCES employees(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_visits_employee
ON visits(employee_id);

CREATE INDEX IF NOT EXISTS idx_visits_date
ON visits(visit_date);

CREATE INDEX IF NOT EXISTS idx_sessions_expiry
ON sessions(expires_at);
