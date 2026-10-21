-- GitHub sign-in for the OAuth flow. github_id is the stable link; github_login lets an
-- existing owner pre-claim their GitHub account (linked to github_id on first sign-in),
-- since matching owners by name alone would let a same-named GitHub user take them over.
ALTER TABLE owners ADD COLUMN github_id INTEGER;
ALTER TABLE owners ADD COLUMN github_login TEXT;
CREATE UNIQUE INDEX owners_github_id ON owners(github_id) WHERE github_id IS NOT NULL;
CREATE UNIQUE INDEX owners_github_login ON owners(github_login) WHERE github_login IS NOT NULL;
