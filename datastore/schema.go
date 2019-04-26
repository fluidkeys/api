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

	`CREATE TABLE IF NOT EXISTS teams (
                uuid UUID PRIMARY KEY,
                created_at TIMESTAMP NOT NULL,
                roster TEXT,
                roster_signature TEXT
    )`,

	`CREATE TABLE IF NOT EXISTS team_join_requests (
                uuid UUID PRIMARY KEY,
                created_at TIMESTAMP NOT NULL,

                email citext NOT NULL,
                fingerprint VARCHAR NOT NULL,

                team_uuid UUID NOT NULL REFERENCES teams(uuid) ON DELETE CASCADE,

                UNIQUE (team_uuid, email)
	)`,

	`DO $$
	BEGIN
		IF EXISTS(SELECT *
				FROM information_schema.columns
				WHERE table_name='email_verifications' and column_name='secret_uuid')
		THEN
				ALTER TABLE email_verifications DROP CONSTRAINT IF EXISTS
					email_verifications_secret_uuid_key;
				ALTER TABLE email_verifications RENAME secret_uuid TO uuid;
				ALTER TABLE email_verifications DROP CONSTRAINT email_verifications_pkey;
				ALTER TABLE email_verifications ADD PRIMARY KEY(uuid);
				ALTER TABLE email_verifications DROP COLUMN IF EXISTS id;
		END IF;
	END $$`,

	`ALTER TABLE email_key_link
	     ADD COLUMN IF NOT EXISTS email_verification_uuid UUID
		     REFERENCES email_verifications(uuid)
		     ON DELETE SET NULL`,

	`UPDATE
	  email_key_link
	SET
	  email_verification_uuid=B.email_verification_uuid
	FROM
	  (
	    SELECT email_key_link.id AS email_key_link_id,
	           email_verifications.uuid AS email_verification_uuid
	    FROM email_key_link
	    JOIN email_verifications ON email_key_link.key_id = email_verifications.key_id
	    WHERE email_key_link.email = email_verifications.email_sent_to
	    AND email_verifications.verify_ip_address IS NOT NULL
	  ) B
	WHERE email_key_link.id = B.email_key_link_id AND
          email_key_link.email_verification_uuid IS NULL`,

	`CREATE TABLE IF NOT EXISTS user_profiles (
                uuid UUID PRIMARY KEY,

                optout_emails_expiry_warnings       BOOL NOT NULL DEFAULT FALSE,

                -- if the key is deleted, delete the user profile too
                key_id INT UNIQUE NOT NULL REFERENCES keys(id) ON DELETE CASCADE
    )`,

	`CREATE TABLE IF NOT EXISTS emails_sent (
                sent_at TIMESTAMP NOT NULL,

                -- email_template_id refers to a specific predefined email
                -- for example 'help_create_join_team_1'
                -- if empty, it's a custom email
                email_template_id TEXT NOT NULL default '',

                user_profile_uuid UUID NOT NULL REFERENCES user_profiles(uuid) ON DELETE CASCADE
	)`,
}

// allTables is used by the test helper DropAllTheTables to keep track of what tables to
// tear down after running tests
var allTables = []string{
	"single_use_uuids",
	"email_key_link",
	"email_verifications",
	"secrets",
	"emails_sent",
	"user_profiles",
	"keys",
	"team_join_requests",
	"teams",
}
