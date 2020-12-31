CREATE TABLE IF NOT EXISTS 'users' ('id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'username' TEXT NOT NULL, 'hash' TEXT NOT NULL, 'cash' NUMERIC NOT NULL DEFAULT 10000.00 );
CREATE TABLE sqlite_sequence(name,seq);
CREATE UNIQUE INDEX 'username' ON "users" ("username");
CREATE TABLE transactions (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
user_id INTEGER,
symbol VARCHAR,
shares INT,
price FLOAT,
timestamp DATETIME,
FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE shares (
user_id INTEGER NOT NULL,
symbol VARCHAR NOT NULL,
shares INT NOT NULL,
FOREIGN KEY(user_id) REFERENCES users(id),
PRIMARY KEY(user_id, symbol)
);
