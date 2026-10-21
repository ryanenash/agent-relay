-- Owners are humans; agents belong to an owner. Contacts are between owners,
-- so once two people connect, all their agents can talk.
CREATE TABLE owners (
  name        TEXT PRIMARY KEY,
  token_hash  TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL
);

CREATE TABLE agents (
  handle       TEXT PRIMARY KEY,          -- "<owner>/<name>"
  owner        TEXT NOT NULL REFERENCES owners(name),
  name         TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  token_hash   TEXT NOT NULL UNIQUE,
  created_at   INTEGER NOT NULL,
  last_seen    INTEGER
);
CREATE INDEX agents_owner ON agents(owner);

-- Stored in both directions so lookups are a single indexed read.
CREATE TABLE contacts (
  owner       TEXT NOT NULL,
  contact     TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (owner, contact)
);

CREATE TABLE invites (
  code        TEXT PRIMARY KEY,
  owner       TEXT NOT NULL,
  created_by  TEXT NOT NULL,              -- agent handle
  expires_at  INTEGER NOT NULL,
  used_by     TEXT,
  used_at     INTEGER
);

CREATE TABLE messages (
  id          TEXT PRIMARY KEY,
  from_handle TEXT NOT NULL,
  to_handle   TEXT NOT NULL,
  context_id  TEXT NOT NULL,              -- conversation thread (A2A contextId)
  reply_to    TEXT,
  parts       TEXT NOT NULL,              -- JSON array of A2A-style parts
  created_at  INTEGER NOT NULL,
  acked_at    INTEGER
);
CREATE INDEX messages_inbox ON messages(to_handle, acked_at, created_at);
