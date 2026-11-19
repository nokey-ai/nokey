# Files

- [CLI command reference](cli-commands.md) - Every nokey CLI command, grouped by job, with its key flags and the gate it goes through (human-presence dialog, PIN, policy). Also covers the global --backend flag and NOKEY_BACKEND.
- [Configuration and on-disk layout](configuration.md) - The config.yaml schema and its defaults, lenient versus strict loading (`nokey config validate`), the config directory on each OS, and which nokey state lives in files and which in the OS keyring. Also notes the security consequence that config can only add gates.
