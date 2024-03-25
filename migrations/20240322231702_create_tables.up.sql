-- Add up migration script here
CREATE TABLE domain (
  id SERIAL PRIMARY KEY,
  domain TEXT NOT NULL UNIQUE,
  owner TEXT NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL
);

CREATE TABLE model (
  id SERIAL PRIMARY KEY,
  model TEXT NOT NULL UNIQUE,
  domain_id INTEGER NOT NULL,
  owner TEXT NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL,
  FOREIGN KEY(domain_id) REFERENCES domain(id)
);

CREATE TABLE schema (
  id SERIAL PRIMARY KEY,
  model_id INTEGER NOT NULL,
  field TEXT NOT NULL,
  is_primary BOOLEAN NOT NULL,
  data_type TEXT NOT NULL,
  is_nullable BOOLEAN NOT NULL,
  lenth INTEGER,
  percision INTEGER,
  scale INTEGER,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL,
  UNIQUE (model_id, field),
  FOREIGN KEY(model_id) REFERENCES model(id)
);
