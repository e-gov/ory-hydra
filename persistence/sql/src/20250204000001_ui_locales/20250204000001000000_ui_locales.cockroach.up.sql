ALTER TABLE hydra_oauth2_logout_request ADD COLUMN "ui_locales" jsonb DEFAULT ('[]') NOT NULL;
