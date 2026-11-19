--liquibase formatted sql

--changeset system:007-user-status-and-deletion
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ;

UPDATE users SET status = UPPER(status) WHERE status <> UPPER(status);
ALTER TABLE users ALTER COLUMN status SET DEFAULT 'ACTIVE';

UPDATE user_roles SET role = 'ROLE_FAN' WHERE role = 'ROLE_USER';

--rollback UPDATE user_roles SET role = 'ROLE_USER' WHERE role = 'ROLE_FAN';
--rollback ALTER TABLE users ALTER COLUMN status SET DEFAULT 'active';
--rollback UPDATE users SET status = LOWER(status);
--rollback ALTER TABLE users DROP COLUMN deleted_at;
