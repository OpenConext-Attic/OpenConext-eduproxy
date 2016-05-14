INSERT INTO `users` (`unspecified_id`, `username`, `email`, `central_idp`, `mapped`, `confirmed`, `affiliations`, `invite_hash`, `institution`)
VALUES
	('urn:collab:person:idin.nl:confirmed', 'J. Doe', 'jdoe@example.com', 'https://idin.surfconext.nl/saml2/idp/metadata.php', 1, 1, 'researcher, student', 'http://localhost:8080/confirmation?inviteHash=hash', 'example.com');

INSERT INTO `users` (`unspecified_id`, `username`, `email`, `central_idp`, `mapped`, `confirmed`, `affiliations`, `invite_hash`, `institution`)
VALUES
	('urn:collab:person:idin.nl:mapped', 'J. Doe', 'jdoe@example.com', 'https://idin.surfconext.nl/saml2/idp/metadata.php', 1, 0, 'researcher, student', 'http://localhost:8080/confirmation?inviteHash=hash', 'example.com');
