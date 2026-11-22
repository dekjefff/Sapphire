ALTER TABLE projects ADD COLUMN source_languages JSONB
  CHECK (source_languages IS NULL OR jsonb_typeof(source_languages) = 'array');