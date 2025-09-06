Intar Agent

Small in-VM agent that collects system and SSHD metrics and exposes them as Prometheus text and ships selected data via OTLP/HTTP.

Usage

- Binary: `intar-agent`
- Flags: `--interval <secs>`, `--otlp-endpoint <url>`

Defaults

- Interval: 1 second (override with `--interval` or `INTAR_AGENT_INTERVAL_SEC`)

This crate is internal to the Intar workspace and not intended for standalone publication.
