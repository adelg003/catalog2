-- Add up migration script here
CREATE TABLE domain (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  owner TEXT NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL
);

CREATE TABLE model (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  domain_id INTEGER NOT NULL,
  owner TEXT NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL,
  FOREIGN KEY(domain_id) REFERENCES domain(id)
);


-- Databricks Datatypes
-- https://learn.microsoft.com/en-us/azure/databricks/sql/language-manual/sql-ref-datatypes
CREATE TYPE dbx_data_type AS ENUM (
  'bigint',
  'binary',
  'boolean',
  'date',
  'decimal',
  'double',
  'float',
  'int',
  'interval',
  'void',
  'smallint',
  'string',
  'timestamp',
  'timestampntz',
  'tinyint'
);

CREATE TABLE field (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  model_id INTEGER NOT NULL,
  is_primary BOOLEAN NOT NULL,
  data_type dbx_data_type NOT NULL,
  is_nullable BOOLEAN NOT NULL,
  precision INTEGER,
  scale INTEGER,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL,
  UNIQUE (model_id, name),
  FOREIGN KEY(model_id) REFERENCES model(id)
);
