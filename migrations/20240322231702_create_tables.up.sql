-- Add up migration script here
CREATE TABLE domain (
  id SERIAL PRIMARY KEY,
  domain TEXT NOT NULL UNIQUE,
  notes JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMP NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMP NOT NULL
);

CREATE TABLE model (
  id SERIAL PRIMARY KEY,
  model TEXT NOT NULL UNIQUE,
  domain TEXT NOT NULL,
  notes JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMP NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMP NOT NULL,
  FOREIGN KEY(domain) REFERENCES domain(domain)
);

CREATE TABLE schema (
  id SERIAL PRIMARY KEY,
  model TEXT NOT NULL,
  field TEXT NOT NULL,
  is_primary BOOLEAN NOT NULL,
  data_type TEXT NOT NULL,
  is_nullable BOOLEAN NOT NULL,
  lenth INTEGER,
  percision INTEGER,
  scale INTEGER,
  notes JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMP NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMP NOT NULL,
  UNIQUE (model, field),
  FOREIGN KEY(model) REFERENCES model(model)
);
