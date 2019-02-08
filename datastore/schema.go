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

	// allow multiple key_id in email_key_link (many email -> 1 key)
	`ALTER TABLE email_key_link DROP CONSTRAINT IF EXISTS email_key_link_key_id_key`,

	`CREATE TABLE IF NOT EXISTS single_use_uuids (
                uuid UUID PRIMARY KEY,
                created_at TIMESTAMP NOT NULL
    )`,

	`CREATE TABLE IF NOT EXISTS email_verifications (
		-- email_verifications tracks claims that a public key is
		-- associated with an email address.
		--
		-- if the claim is verified (by opening a link sent to the
		-- email address), an email_key_link row is added.
		--
		-- email_verifications are not immediately deleted as they
		-- are a useful audit trail to use in the event of fake key
		-- pretending to be associated with an email address

                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMP NOT NULL,
                valid_until TIMESTAMP NOT NULL,
                secret_uuid UUID UNIQUE NOT NULL,

                key_id INT REFERENCES keys(id) ON DELETE SET NULL,

                key_fingerprint VARCHAR NOT NULL,

                email_sent_to VARCHAR NOT NULL,
                upsert_user_agent TEXT,
                upsert_ip_address INET,
                verify_user_agent TEXT,
                verify_ip_address INET
    )`,

	`CREATE EXTENSION IF NOT EXISTS citext`,

	`ALTER TABLE email_key_link ALTER COLUMN email TYPE citext`,
}
