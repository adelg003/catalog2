-- Add up migration script here

-- Domain Table
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

-- Schema Table
CREATE TABLE schema (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  owner TEXT NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL
);

-- Model Table
CREATE TABLE model (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  domain_id INTEGER NOT NULL,
  schema_id INTEGER NOT NULL,
  owner TEXT NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL,
  FOREIGN KEY(domain_id) REFERENCES domain(id),
  FOREIGN KEY(schema_id) REFERENCES schema(id)
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

-- Fields that make up a Model
CREATE TABLE field (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  schema_id INTEGER NOT NULL,
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
  UNIQUE (schema_id, name),
  FOREIGN KEY(schema_id) REFERENCES schema(id)
);

-- Where the pack runs?
CREATE TYPE runtime_type AS ENUM (
  'docker',
  'dbxjob',
  'dbt',
  'dag'
);

-- What compute does the pack use?
CREATE TYPE compute_type AS ENUM (
  'docker',
  'dbx',
  'memsql'
);

-- Compute Pack to be run to create the needed Models
CREATE TABLE pack (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  domain_id INTEGER NOT NULL,
  runtime runtime_type NOT NULL,
  compute compute_type NOT NULL,
  repo TEXT NOT NULL,
  owner TEXT NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL,
  FOREIGN KEY(domain_id) REFERENCES domain(id)
);

-- Pack needed to create a model
CREATE TABLE model_dependency (
  id SERIAL PRIMARY KEY,
  model_id INTEGER NOT NULL UNIQUE,
  pack_id INTEGER NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL,
  UNIQUE (model_id, pack_id),
  FOREIGN KEY(model_id) REFERENCES model(id),
  FOREIGN KEY(pack_id) REFERENCES pack(id)
);

-- Models needed to run the pack
CREATE TABLE pack_dependency (
  id SERIAL PRIMARY KEY,
  pack_id INTEGER NOT NULL,
  model_id INTEGER NOT NULL,
  extra JSONB,
  created_by TEXT NOT NULL,
  created_date TIMESTAMPTZ NOT NULL,
  modified_by TEXT NOT NULL,
  modified_date TIMESTAMPTZ NOT NULL,
  UNIQUE (model_id, pack_id),
  FOREIGN KEY(pack_id) REFERENCES pack(id),
  FOREIGN KEY(model_id) REFERENCES model(id)
);
