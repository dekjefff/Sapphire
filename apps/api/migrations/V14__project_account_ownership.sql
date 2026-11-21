ALTER TABLE projects ADD COLUMN owner_account_id UUID;
CREATE INDEX projects_owner_account_id_idx ON projects (owner_account_id);
