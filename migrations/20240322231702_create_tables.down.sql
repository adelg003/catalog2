-- Add down migration script here

-- Drop Dependency Tables
DROP TABLE IF EXISTS pack_dependencies;
DROP TABLE IF EXISTS model_dependencies;

-- Drop Pack Table and types
DROP TABLE IF EXISTS pack;
DROP TYPE IF EXISTS compute_type;
DROP TYPE IF EXISTS runtime_type;

-- Drop Field table and types
DROP TABLE IF EXISTS field;
DROP TYPE IF EXISTS dbx_data_type;

-- Drop Model table
DROP TABLE IF EXISTS model;

-- Drop Domain table and types
DROP TABLE IF EXISTS domain;
