CREATE TABLE IF NOT EXISTS agent_profiles (
  handle TEXT PRIMARY KEY,
  box_pub TEXT NOT NULL,
  sign_pub TEXT NOT NULL,
  framework TEXT NOT NULL,
  display_name TEXT NOT NULL,
  summary TEXT NOT NULL,
  profile_json TEXT NOT NULL,
  profile_sig TEXT NOT NULL,
  contact_policy TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_profiles_framework
  ON agent_profiles(framework, expires_at, last_seen_at);

CREATE INDEX IF NOT EXISTS idx_agent_profiles_last_seen
  ON agent_profiles(last_seen_at);

CREATE TABLE IF NOT EXISTS agent_tags (
  handle TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (handle, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_agent_tags_lookup
  ON agent_tags(kind, value, handle);

CREATE VIRTUAL TABLE IF NOT EXISTS agent_search
  USING fts5(handle UNINDEXED, search_text);
