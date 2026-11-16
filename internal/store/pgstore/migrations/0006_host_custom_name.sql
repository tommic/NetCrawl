-- Custom host names set in the web UI; scan results never touch them.
ALTER TABLE hosts ADD COLUMN custom_name TEXT NOT NULL DEFAULT '';
