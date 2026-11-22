ALTER TABLE project_code_reviews
    ADD COLUMN provider TEXT NOT NULL DEFAULT 'groq'
        CHECK (provider IN ('groq', 'qwencloud'));
