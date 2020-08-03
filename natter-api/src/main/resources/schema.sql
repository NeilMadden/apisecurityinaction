CREATE TABLE users(
    user_id VARCHAR(30) PRIMARY KEY,
    pw_hash VARCHAR(255) NOT NULL
);
INSERT INTO users(user_id, pw_hash)
    VALUES('demo', '$s0$f0801$FNT5t8/4B9xV2uMUxBg4Bg==$Xlok7jXqS6Y1IE97KCzwCmoTFUakDp1UfTY5aEV545k=');
CREATE TABLE group_members(
    group_id VARCHAR(30),
    user_id VARCHAR(30) REFERENCES users(user_id)
);
CREATE INDEX group_member_user_idx ON group_members(user_id);

CREATE TABLE spaces(
    space_id INT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner VARCHAR(30) NOT NULL
);
CREATE SEQUENCE space_id_seq;
CREATE TABLE messages(
    space_id INT NOT NULL REFERENCES spaces(space_id),
    msg_id INT PRIMARY KEY,
    author VARCHAR(30) NOT NULL,
    msg_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    msg_text VARCHAR(1024) NOT NULL
);
CREATE SEQUENCE msg_id_seq;
CREATE INDEX msg_timestamp_idx ON messages(msg_time);
CREATE UNIQUE INDEX space_name_idx ON spaces(name);

CREATE TABLE audit_log(
    audit_id INT NULL,
    method VARCHAR(10) NOT NULL,
    path VARCHAR(100) NOT NULL,
    user_id VARCHAR(30) NULL,
    status INT NULL,
    audit_time TIMESTAMP NOT NULL
);
CREATE SEQUENCE audit_id_seq;

CREATE TABLE role_permissions(
    role_id VARCHAR(30) NOT NULL PRIMARY KEY,
    perms VARCHAR(3) NOT NULL
);
INSERT INTO role_permissions(role_id, perms)
    VALUES ('owner', 'rwd'),
           ('moderator', 'rd'),
           ('member', 'rw'),
           ('observer', 'r');

CREATE TABLE user_roles(
    space_id INT NOT NULL REFERENCES spaces(space_id),
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id),
    role_id VARCHAR(30) NOT NULL REFERENCES role_permissions(role_id)
);
CREATE INDEX user_roles_idx ON user_roles(space_id, user_id);

CREATE TABLE tokens(
    token_id VARCHAR(100) PRIMARY KEY,
    user_id VARCHAR(30),
    expiry TIMESTAMP NOT NULL,
    attributes VARCHAR(4096) NOT NULL
);
CREATE INDEX expired_token_idx ON tokens(expiry);

CREATE USER natter_api_user PASSWORD 'password';
GRANT SELECT, INSERT ON spaces, messages TO natter_api_user;
GRANT DELETE ON messages TO natter_api_user;
GRANT SELECT, INSERT ON users TO natter_api_user;
GRANT SELECT, INSERT ON audit_log TO natter_api_user;
GRANT SELECT, INSERT, DELETE ON tokens TO natter_api_user;
GRANT SELECT, INSERT, DELETE ON group_members TO natter_api_user;
GRANT SELECT, INSERT, DELETE ON user_roles TO natter_api_user;
GRANT SELECT ON role_permissions TO natter_api_user;