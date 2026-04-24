# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x   | Yes       |
| < 1.5   | No        |

## Reporting a Vulnerability

Please report security vulnerabilities to the project maintainer via GitHub private vulnerability reporting or by opening a draft security advisory.

Do not open public issues for security bugs.

## Threat Model

- This application is a **single-user desktop utility** for managing Linux system security.
- It trusts the local system D-Bus, firewalld, and systemd.
- It does **not** trust the contents of user-writable configuration files (`~/.config/security-center/port_metadata.json` or `settings.json`). These files are validated and sanitized at load time.
- It makes outbound HTTPS requests **only** to `api.github.com` for version checking.
- Privileged operations are executed via `pkexec` + `systemctl` or D-Bus, with parameter allowlisting.

## Environment Variables

- `RUST_LOG` — Controls tracing log level. Defaults to `info`. Setting `RUST_LOG=trace` may log sensitive system information (firewall rules, service states, network topology) to the console.

## Security Features

- Configuration files are created with `0o600` permissions.
- Firewalld rich rules are validated against an allowlist before construction.
- `pkexec` parameters are validated against allowlists before execution.
- JSON deserialization rejects unknown fields and discards invalid entries.
- Outbound update checks validate URL scheme (`https`) and host (`api.github.com`).
