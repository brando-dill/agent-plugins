# Ping Identity Migration Plugin

Agent-focused guidance for application-level identity migration — extracting, classifying, applying, and validating applications from PingFederate, or PingOne for Enterprise into PingOne, plus everything a migration run leaves behind.

## What this plugin is for

- Assessing migration readiness and previewing what would migrate before changing anything
- Classifying applications as direct migration, redesign-required, or out of scope
- Planning migration waves with sequencing, acceptance criteria, and validation gates
- Running migrations with a bundled orchestrator (live admin API or pre-exported source file)
- Handling client secrets that cannot be exported, and the post-migration manual follow-up list
- Designing cutover and rolling back a completed migration run

## Requirements

The bundled orchestrator requires Node.js 18+ and `pingcli` on PATH, authenticated at least once so `~/.pingcli/config.yaml` exists. Destination operations mutate the target PingOne environment except under `--dry-run`. Always preview with `--dry-run` first.

## Skills

| Skill | Path | Use when |
|---|---|---|
| `ping-migration` | `skills/ping-migration/` | Migrating identity applications off PingFederate or P14E to PingOne — running a migration, assessing readiness, planning waves, classifying apps, mapping grant types, handling post-migration secrets, or rolling back |
