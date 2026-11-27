-- Version of netcrawl-agent each crawler runs (from its job polls).
ALTER TABLE crawlers ADD COLUMN agent_version TEXT NOT NULL DEFAULT '';
