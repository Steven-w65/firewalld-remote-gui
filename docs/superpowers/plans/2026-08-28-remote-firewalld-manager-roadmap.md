# Remote firewalld Manager Implementation Roadmap

**Goal:** Deliver the approved Remote firewalld Manager MVP through four independently testable implementation plans.

**Spec:** `docs/superpowers/specs/2026-08-28-remote-firewalld-manager-design.md`

Execute these plans in order:

1. `2026-08-28-foundation-configuration-plan.md` — portable paths, configuration, shared models, validation, and safe logging.
2. `2026-08-28-ssh-firewalld-backend-plan.md` — host-key-aware Paramiko sessions, sudo, allowlisted commands, parsers, and verified firewall operations.
3. `2026-08-28-session-ports-gui-plan.md` — per-server scheduling and state, the application shell, Overview, and complete Ports management.
4. `2026-08-28-management-ui-hardening-plan.md` — Zones, Services, Interfaces, Rich Rules, reload, logs, documentation, and acceptance hardening.

Each plan assumes all earlier plans have passed their full test suites and been committed. Shared public interfaces introduced by an earlier plan must remain stable unless the later plan updates both callers and tests in the same task.

