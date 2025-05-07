ALTER TABLE hydra_oauth2_logout_request RENAME COLUMN redir_url TO _redir_url_ignore;
ALTER TABLE hydra_oauth2_logout_request ADD COLUMN redir_url TEXT NULL;
UPDATE hydra_oauth2_logout_request SET redir_url = _redir_url_ignore;
ALTER TABLE hydra_oauth2_logout_request DROP COLUMN _redir_url_ignore;

