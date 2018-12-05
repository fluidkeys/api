package datastore

var migrateDatabaseStatements = []string{
	`CREATE TABLE IF NOT EXISTS keys (
                id BIGSERIAL PRIMARY KEY,
              
                -- fingerprint is the uppercase hex version of the fingerprint,
		-- prepended by the version number and a colon, e.g.
                -- 4:A999B7498D1A8DC473E53C92309F635DAD1B5517
                fingerprint VARCHAR UNIQUE NOT NULL,
                armored_public_key TEXT NOT NULL
         )`,

	`CREATE TABLE IF NOT EXISTS email_key_link (
                -- The email -> key mapping is many-to-one, e.g. an email will always resolve
                -- to a single key, and multiple emails can point to the same key.
                --
                -- If the key is deleted, the email should be deleted too since it's not used
                -- for anything but mapping to a key.
                
                id BIGSERIAL PRIMARY KEY,
                email VARCHAR UNIQUE NOT NULL,
    
                key_id INT UNIQUE NOT NULL REFERENCES keys(id) ON DELETE CASCADE
         )`,

	`CREATE TABLE IF NOT EXISTS secrets (
                id BIGSERIAL PRIMARY KEY,
                uuid UUID UNIQUE NOT NULL,
                created_at TIMESTAMP NOT NULL,
                recipient_key_id INT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
                armored_encrypted_secret TEXT NOT NULL
    )`,
}
