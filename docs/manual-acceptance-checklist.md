# Disposable-host manual acceptance checklist

This checklist is opt-in. Run it only from the primary Windows client against
three disposable Linux hosts running firewalld 2.x. Do not use production
servers. Before starting, create restorable firewall backups and verify direct
console or out-of-band access to every host. Record screenshots, timestamps,
the application log name, the remote verification command/output, and the
operator initials for each item in an evidence folder outside `logs/`.

Use three portable profiles named Production Web Server (`web01`), Database
Server (`db01`), and Test Server (`test01`). Give them distinct hosts and SSH
credentials; use at least one root profile, one passwordless-sudo profile, and
one password-prompt sudo profile. Keep sudo passwords out of `config.yaml`.
For every firewall mutation below, capture the before state, confirmation,
runtime and permanent command outcomes, refreshed GUI state, and independent
console verification. **Every item labeled UNSAFE FOR PRODUCTION may alter
remote firewall access and must be run only on these disposable hosts.**

## Exact 38-step flow

1. [ ] Start the application from the repository directory with `python main.py`; record the Windows and Python versions and capture the initial window. Confirm no server connects automatically.
2. [ ] Load at least three servers from the portable `config.yaml`; confirm it contains only the intended SSH passwords and no sudo-password field.
3. [ ] Display all three profiles in the sidebar and capture their independent Disconnected states.
4. [ ] Select Production Web Server (`web01`) and record its name, host, SSH port, and username as displayed.
5. [ ] Click Connect and capture the Connecting state while confirming the GUI can still switch tabs and select another server.
6. [ ] Authenticate over SSH. For the password-prompt sudo profile, enter the sudo password only in the masked prompt and confirm reconnect/disconnect clears it from live-session memory.
   - [ ] Repeat once with an intentionally wrong SSH password and once with an intentionally wrong sudo password; restore the correct SSH configuration afterward.
7. [ ] Verify firewalld is running and is modern 2.x in both Overview and an independent console check.
8. [ ] Display active and default zones; compare both with independent runtime queries.
   - [ ] Test an unknown host key on a freshly isolated app `known_hosts`: verify the fingerprint is shown, Cancel is the default, and no trust is saved until explicit acceptance.
   - [ ] On a disposable host with console recovery, deliberately substitute its key: verify the changed-key connection is blocked with a serious warning and is never silently trusted; restore the original key/trust state.
9. [ ] Open Ports and record that the selected-server view, zone filter, presence filter, and search controls are available.
10. [ ] Display current ports in the table and compare Port, Protocol, Zone, Runtime, and Permanent columns with independent queries.
11. [ ] Select the `public` zone and capture the filtered table.
12. [ ] Click Add Port and confirm the typed dialog is cancel-default and has no command, shell, or terminal field.
13. [ ] Enter `8080`; also validate a port range such as `8100-8102` in a separate disposable-only cycle.
14. [ ] Select TCP; in a separate disposable-only cycle verify UDP uses the same bounded workflow.
15. [ ] Select Runtime + Permanent and capture the exact target selection.
16. [ ] Display the change confirmation and verify server, host, operation, zone, `8080/tcp`, and Runtime + Permanent are exact; cancel once and prove no remote state changed.
17. [ ] **UNSAFE FOR PRODUCTION — disposable host only:** Apply the confirmed `8080/tcp` change.
18. [ ] Confirm exactly one permanent mutation runs first and exactly one runtime mutation runs second; verify no automatic reload and no write retry.
19. [ ] Confirm the application queries permanent and runtime firewalld state again exactly once after the returned composite result.
20. [ ] Verify `8080/tcp` independently in both runtime and permanent configuration.
21. [ ] Confirm the refreshed ports table shows `8080/tcp` with both Runtime and Permanent present.
   - [ ] **UNSAFE FOR PRODUCTION — disposable host only:** Repeat add/remove for Runtime only and Permanent only, independently verify each target, and restore the baseline after each case.
22. [ ] Select the exact `8080/tcp` row and confirm the Remove action repeats the selected immutable resource.
23. [ ] Click Remove Port and verify no removal can be submitted without a selected row.
24. [ ] Confirm the exact removal preview; cancel once and prove both targets remain present.
25. [ ] **UNSAFE FOR PRODUCTION — disposable host only:** Remove the runtime and permanent `8080/tcp` entries, recording separate target outcomes.
26. [ ] Verify the removal with independent runtime and permanent queries and confirm the refreshed table no longer contains the row.
27. [ ] **UNSAFE FOR PRODUCTION — disposable host only:** Add and remove an available remote service in Runtime, Permanent, and Runtime + Permanent modes; confirm exact previews, independent outcomes, one refresh, no automatic reload, and restored baseline.
28. [ ] Display runtime and permanent zone information, including activity, interfaces, sources, services, ports, protocols, masquerade, forwarding, and rich-rule count.
   - [ ] **UNSAFE FOR PRODUCTION — disposable host only:** Change the default zone after exact current/new confirmation, independently verify it, then restore the original default zone.
   - [ ] **UNSAFE FOR PRODUCTION — disposable host only:** Move a disposable active interface to another zone only with console access; verify the warning names the management port and incomplete route detection, independently verify both targets, then restore the interface assignment.
   - [ ] **UNSAFE FOR PRODUCTION — disposable host only:** Add and remove one supported structured rich rule in all target modes; verify there is no raw/free-form editor, confirm exact structured removal, independently verify, and restore baseline.
   - [ ] Simulate a partial Runtime + Permanent result in a controlled disposable adapter/host setup; capture the separate success/failure phases, refreshed state, no rollback, no retry, and no automatic reload.
   - [ ] **UNSAFE FOR PRODUCTION — disposable host only:** Request firewalld reload, verify the runtime-only-loss warning and cancel-default confirmation, apply only after backup/console checks, and capture the refreshed verified outcome.
29. [ ] Switch to Database Server (`db01`) while `web01` state remains cached and confirm no `web01` credential, log, error, or firewall row appears in the selected view.
30. [ ] Connect to `db01` and capture its independent status transition and Overview identity.
31. [ ] Display `db01` firewall state and compare it with independent queries; confirm `web01`'s temporary test resources are absent.
32. [ ] Switch back to `web01` without restarting the application.
33. [ ] Confirm `web01`'s state, logs, errors, and status were not mixed with `db01`; repeat selection with `test01` and capture evidence for all three profiles.
34. [ ] Simulate a refused connection, timeout, or authentication failure on one disposable profile while another remains usable; also simulate a command timeout and verify the affected channel/session recovery behavior.
35. [ ] Verify each failure produces a readable fixed error, the application does not crash, and unrelated server tabs remain responsive.
36. [ ] Search the rotating log files, visible Logs tab, copied clipboard text, error dialogs, screenshots/evidence, and exported console capture for every distinct SSH and sudo test password; record zero matches. Clear View must not delete the rotating log, and Copy must include only the selected visible server log.
37. [ ] **UNSAFE FOR PRODUCTION if applied — warning test should normally be canceled:** Attempt to remove the configured SSH management port, remove the `ssh` service, move the active management interface, and remove a structured SSH-permit rule. Verify every exact preview names the server and management port, states detection is incomplete, uses **Apply Anyway**, and defaults to Cancel. Apply only on a disposable host with verified console recovery, then immediately restore access.
38. [ ] Display and capture the strong lockout warning, then complete final recovery and artifact review: cancel any unneeded change, restore all three firewall baselines and host keys, verify SSH reconnects, preserve evidence, confirm no credentials in artifacts, run the full automated suite plus compile/import/diff/status checks, and record that no live-host step is claimed unless its evidence is attached.

## Completion record

- [ ] All 38 numbered items have attached evidence or are explicitly marked not run.
- [ ] Every disposable host matches its saved baseline and accepts an SSH reconnect.
- [ ] No manual result has been inferred from the offline automated suite.
- [ ] Reviewer/operator names and completion date are recorded with the evidence.
