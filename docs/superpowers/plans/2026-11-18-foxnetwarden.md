# FoxNetwarden Faz-1 MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build FoxNetwarden, a local-first personal Linux desktop firewall app (Tauri v2 + Rust backend + vanilla JS WebKit2GTK UI) that observes live network connections, blocks target/domain-based rules via nftables, detects suspicious connections, runs a tray + notification loop, and implements a kill switch — all without cloud, accounts, or data leaving the machine.

**Architecture:** Rust crate `foxnetwarden` under `src-tauri/` with modules: `collector` (ss/conntrack/`/proc` → live connections), `dnslog` (systemd-resolved journal opt-in debug log parse), `firewall` (nftables `foxnetwarden` table via pkexec, per-action password), `domainblock` (domain → periodic IP/CIDR resolution → nft set), `db` (SQLite history/settings/rules), `blocklist` (vendored domain/IP allow/block lists), `analyzer` (suspicion scoring), `tray` (tray icon, libnotify, autostart toggle). Web UI under `web/` with screens: Live, Analysis, DNS, Rules, Kill Switch, Settings. Tauri commands bridge frontend and backend.

**Tech Stack:** Rust (edition 2021), tauri 2.x, dirs 6, serde + serde_json, rusqlite, tauri-build; vanilla JS + HTML/CSS; `nft` CLI shell-out; `pkexec` for privilege elevation; `sqlite3` for DB; `notify-rust` (or `libnotify` FFI) for notifications; systemd-resolved journal for DNS. Build: `cargo tauri build` → .rpm (primary, Fedora 45), .deb, AppImage.

**Spec:** `docs/superpowers/specs/2026-11-18-foxnetwarden-design.md` — plan argues from the spec; both travel together.

## Global Constraints

- Name rule: directory `foxnetwarden`, productName `FoxNetwarden`, identifier `app.foxnetwarden.firewall`, README title English, Turkish only in UI strings/copy. No retroactive renames of Sextant/Kurgu. (MEMORY.md 2026-11-18)
- Platform: Linux desktop (Fedora 45 / CachyOS-compatible), WebKit2GTK, root required for nftables writes.
- Elevation: **pkexec for every blocking action** (user choice) — no cached session trust.
- Kill switch: kills ALL outbound (established + new, LAN, DNS, IPv6 included), allow rules do not punch through, session-only (reverted on app exit; manual `nft delete table inet foxnetwarden` on crash).
- DNS: default "invisible" honest mode (shows DoH limitation); opt-in root toggle parses systemd-resolved debug journal (`resolvectl log-level debug`), reset on reboot.
- Rules UI: constrained form only (block/allow + target CIDR|domain|port) — no free-form nft expressions.
- Blocklist: vendored static lists embedded at build time; no auto-update in Faz 1.
- Packages: .rpm primary (Fedora native), .deb, AppImage via `cargo tauri build`.
- Zero cloud, zero accounts, zero telemetry; export = JSON only.
- Tests: `cargo test`; headless GUI test skipped; UI verified in browser via `python3 -m http.server`, 0 console errors.

## Review Focus

| Input / condition | Expected behavior | Pins to task |
|---|---|---|
| Blocker rule added without root (pkexec cancelled or missing) | Rule add fails gracefully, UI shows "yetki gerekli", app stays usable read-only | Task 3 (firewall) |
| Domain added to block set; CDN IP rotates | Stale IPs expire via periodic re-resolution; set refreshed, no crash on missing DNS | Task 3 (domainblock) |
| Kill switch toggled on | All outbound drops immediately; allow rules do not leak; UI shows prominent active indicator | Task 3 (firewall) + Task 5 (Kill Switch screen) |
| Kill switch active, app crashes / user force-quits | Network does NOT auto-recover; README documents `sudo nft delete table inet foxnetwarden` | Task 3 (firewall) |
| DNS debug log toggle off | DNS screen shows "görünmez — DoH görünmez" honest state; no journal access attempted | Task 4 (dnslog) |
| Free-form nft expression typed into Rules form | Rejected by constrained UI (only CIDR/domain/port accepted); no shell injection path | Task 5 (Rules screen) |
| Tray started, app window closed | Tray stays alive; notification fires on suspicious connection | Task 6 (tray) |
| `ss -tunp` reports `?` for another user's process | Process column shows `?`, app does not crash | Task 1 (collector) |

## File Structure

- Create: `src-tauri/Cargo.toml` — package `foxnetwarden` 1.0.0, deps tauri/dirs/serde/serde_json/rusqlite/notify-rust, build-dep tauri-build, release profile strip.
- Create: `src-tauri/build.rs` — `tauri_build::build()`.
- Create: `src-tauri/src/main.rs` — Tauri builder, invoke handler, generate_context!(), command registration.
- Create: `src-tauri/src/collector.rs` — `live_connections(): Vec<Connection>` via `ss -tunp` + `/proc` parsing (pid/name resolution).
- Create: `src-tauri/src/dnslog.rs` — opt-in resolved debug journal parse (`journalctl -u systemd-resolved`); returns DNS events or "invisible" state.
- Create: `src-tauri/src/firewall.rs` — nftables wrapper: `fw_status`, `rule_add/remove`, `killswitch_set`, `pkexec` shell-out, table `foxnetwarden`, chains killswitch/block.
- Create: `src-tauri/src/domainblock.rs` — domain → IP/CIDR resolution + periodic re-resolve + nft set sync.
- Create: `src-tauri/src/db.rs` — SQLite: connections history, rules, settings; `history_query`, `top_talkers`.
- Create: `src-tauri/src/blocklist.rs` — vendored domain/IP block/allow list matching (case-insensitive + wildcard).
- Create: `src-tauri/src/analyzer.rs` — suspicion scoring (top-talker, tracker match, port-53-outside-DNS).
- Create: `src-tauri/src/tray.rs` — tray icon + libnotify notifications + autostart toggle (`~/.config/autostart`).
- Create: `src-tauri/tauri.conf.json` — productName FoxNetwarden, v1.0.0, identifier app.foxnetwarden.firewall, frontendDist ../web, app.withGlobalTauri true, window 1280x800 min 960x640 bg #14100e, security.csp null, bundle category Security, icons icons/.
- Create: `src-tauri/capabilities/default.json` — core:default on windows ["main"].
- Create: `src-tauri/icons/icon-src.svg` + `cargo tauri icon` outputs (png/icns/ico).
- Create: `web/index.html`, `web/styles.css`, `web/app.js` — six screens, live table, charts, kill switch button, rules form, settings.
- Create: `tests/` — Rust unit tests per module (collector parser, dnslog parser, blocklist matcher, analyzer scorer, firewall nft syntax generator).
- Modify: `.gitignore` — /target, /gen, *.log, runtime/.
- Create: `README.md` (TR/EN) — features, privacy, build, run, honest limits.
- Create: `site/` — static TR+EN Cloudflare Pages site (hero, features grid, architecture diagram, install .rpm/.deb/AppImage, privacy, MIT).
- Modify: `MEMORY.md` — add foxnetwarden entry (optional, portfolio convention).

## Tasks

### Task 1: Rust collector + parser foundation

**Files:**
- Create: `src-tauri/Cargo.toml`
- Create: `src-tauri/build.rs`
- Create: `src-tauri/src/main.rs`
- Create: `src-tauri/src/collector.rs`
- Create: `tests/test_collector.rs`

**Interfaces:**
- Consumes: none (shells out to `ss`, reads `/proc`)
- Produces: `Connection { pid: Option<u32>, name: String, local: String, remote: String, state: String, duration: u64 }`; `fn live_connections() -> Result<Vec<Connection>, String>`

- [ ] Step 1: Write failing test `test_collector_parses_ss_output` with a sample `ss -tunp` multi-line fixture; assert parsed fields including `?` pid.
- [ ] Step 2: Run `cargo test test_collector_parses_ss_output` → FAIL (collector.rs missing).
- [ ] Step 3: Implement `collector.rs` parsing `ss -tunp` output into `Connection`; `name` from `/proc/{pid}/comm` when pid present, else `?`; duration from timer info.
- [ ] Step 4: Run `cargo test` → PASS.
- [ ] Step 5: Commit `git add src-tauri/Cargo.toml src-tauri/build.rs src-tauri/src/main.rs src-tauri/src/collector.rs tests/test_collector.rs; git commit -m "feat: Rust collector parses live connections"`

### Task 2: SQLite history DB + blocklist + analyzer

**Files:**
- Create: `src-tauri/src/db.rs`
- Create: `src-tauri/src/blocklist.rs`
- Create: `src-tauri/src/analyzer.rs`
- Create: `tests/test_blocklist.rs`
- Create: `tests/test_analyzer.rs`

**Interfaces:**
- Consumes: connections from Task 1
- Produces: `fn db_insert(conn)`, `fn history_query() -> Vec<HistoryRow>`, `fn top_talkers() -> Vec<Talker>`, `fn blocklist_match(domain|ip) -> MatchResult`, `fn analyzer_score(conn) -> u8`

- [ ] Step 1: Write failing tests: blocklist exact + wildcard + case-insensitive match; analyzer score for known-tracker domain and top-talker.
- [ ] Step 2: Run tests → FAIL.
- [ ] Step 3: Implement `db.rs` (rusqlite, file under app data dir), `blocklist.rs` (vendored static lists), `analyzer.rs` (scoring 0-100).
- [ ] Step 4: Run `cargo test` → PASS.
- [ ] Step 5: Commit `git add src-tauri/src/db.rs src-tauri/src/blocklist.rs src-tauri/src/analyzer.rs tests/; git commit -m "feat: SQLite DB, blocklist matcher, suspicion analyzer"`

### Task 3: Firewall, domain-block enforcement, pkexec

**Files:**
- Create: `src-tauri/src/firewall.rs`
- Create: `src-tauri/src/domainblock.rs`
- Create: `tests/test_firewall.rs`

**Interfaces:**
- Consumes: blocklist matches, user rule add/remove requests
- Produces: `fw_status()`, `rule_add(target, kind, action)`, `rule_remove(id)`, `killswitch_set(bool)`, `domainblock_sync(domains)`; all nft via `pkexec nft ...`; nft syntax string generator tested.

- [ ] Step 1: Write failing tests: nft syntax string generation for add/remove/kill-switch; pkexec command shape; error when pkexec missing.
- [ ] Step 2: Run tests → FAIL.
- [ ] Step 3: Implement `firewall.rs` (table `foxnetwarden`, chains `killswitch` + `block`; pkexec shell-out per call; root check), `domainblock.rs` (resolve domain → IPs, write nft set, periodic re-resolve timer).
- [ ] Step 4: Run `cargo test` → PASS.
- [ ] Step 5: Commit `git add src-tauri/src/firewall.rs src-tauri/src/domainblock.rs tests/test_firewall.rs; git commit -m "feat: nftables firewall, pkexec elevation, domain blocking"`

### Task 4: DNS log module (opt-in resolved journal)

**Files:**
- Create: `src-tauri/src/dnslog.rs`
- Create: `tests/test_dnslog.rs`

**Interfaces:**
- Consumes: `journalctl -u systemd-resolved` (only when enabled)
- Produces: `dns_events() -> Vec<DnsEvent>` or `Invisible` state; `dns_mode_toggle()`; `dns_status() -> {enabled, visible}`

- [ ] Step 1: Write failing test: parse sample resolved debug journal lines into DnsEvent; detect "invisible" when log missing.
- [ ] Step 2: Run test → FAIL.
- [ ] Step 3: Implement `dnslog.rs`: opt-in parse; honest "invisible" state when disabled/DoH.
- [ ] Step 4: Run `cargo test` → PASS.
- [ ] Step 5: Commit `git add src-tauri/src/dnslog.rs tests/test_dnslog.rs; git commit -m "feat: DNS log opt-in resolved journal parser"`

### Task 5: Tauri shell + commands + tray

**Files:**
- Create: `src-tauri/src/tray.rs`
- Modify: `src-tauri/src/main.rs` — register all commands
- Create: `src-tauri/tauri.conf.json`
- Create: `src-tauri/capabilities/default.json`
- Create: `src-tauri/icons/icon-src.svg`; run `cargo tauri icon`
- Create: `tests/test_commands.rs` (command wiring smoke)

**Interfaces:**
- Consumes: all modules above
- Produces: Tauri commands `fw_status`, `live_connections`, `history_query`, `rule_add`, `rule_remove`, `killswitch_set`, `blocklist_stats`, `top_talkers`, `dns_mode`, `tray_toggle_autostart`

- [ ] Step 1: Write failing test: command names registered in main match spec list; config identifier == app.foxnetwarden.firewall.
- [ ] Step 2: Run `cargo test` → FAIL.
- [ ] Step 3: Implement main.rs builder + commands; tray.rs (tray + notify-rust + autostart desktop entry); tauri.conf.json (withGlobalTauri under app, window 1280x800 min 960x640 bg #14100e, bundle Security); generate icons.
- [ ] Step 4: Run `cargo test` → PASS; `cargo build --release` compiles.
- [ ] Step 5: Commit `git add src-tauri/ tauri.conf.json capabilities/default.json icons/; git commit -m "feat: Tauri shell, commands, tray, config, icons"`

### Task 6: Web UI (six screens)

**Files:**
- Create: `web/index.html`
- Create: `web/styles.css`
- Create: `web/app.js`

**Interfaces:**
- Consumes: Tauri commands from Task 5
- Produces: screens Live / Analysis / DNS / Rules / Kill Switch / Settings; live connection table; suspicion chips; kill switch button + indicator; constrained rules form (block/allow + target + port); settings (refresh rate, blocklist on/off, otostart toggle, DNS debug toggle); toast/status.

- [ ] Step 1: Build shell HTML/CSS for six screens + navigation; open `web/index.html` in browser → 0 console errors, renders.
- [ ] Step 2: Wire each screen to Tauri invoke (or localStorage fallback for browser-only check); live table refreshes every 1–2s.
- [ ] Step 3: Kill switch: toggle → `killswitch_set(true)`; prominent on/off indicator; allow-rule form disabled when active.
- [ ] Step 4: Rules: constrained form → `rule_add`; list table → `rule_remove`; toast on pkexec password required.
- [ ] Step 5: DNS: show events or honest invisible state; toggle via `dns_mode`.
- [ ] Step 6: Settings: refresh rate, blocklist toggle, otostart toggle, DNS toggle; persist to SQLite via command.
- [ ] Step 7: Run in browser via `python3 -m http.server` → 0 console errors; all screens reachable.
- [ ] Step 8: Commit `git add web/; git commit -m "feat: vanilla JS UI six screens live/analysis/dns/rules/kill-switch/settings"`

### Task 7: Integration + full test suite

**Files:**
- Modify: `tests/` — add integration test (temporary nft table if root, else SKIPPED)

**Interfaces:**
- Consumes: all modules
- Produces: end-to-end smoke: insert connection → history query → rule add → blocklist match → kill switch set → revert

- [ ] Step 1: Write integration test exercising collector→db→firewall→analyzer chain; guard root-required parts with `#[ignore]` / SKIPPED message.
- [ ] Step 2: Run `cargo test` → PASS (root parts skipped if no root).
- [ ] Step 3: Commit `git add tests/; git commit -m "test: integration smoke for firewall chain"`

### Task 8: Desktop build + packages

**Files:**
- Modify: none new; run build

**Interfaces:**
- Consumes: complete `src-tauri/` + `web/`
- Produces: binary `src-tauri/target/release/foxnetwarden`; bundles `.rpm` (primary), `.deb`, `.AppImage`

- [ ] Step 1: Run `cargo tauri build` (release) → binary + 3 bundles.
- [ ] Step 2: Verify `rpm -qip` / `dpkg-deb --info` / AppImage ELF header for one bundle.
- [ ] Step 3: Commit Cargo.lock if changed; `git commit -m "chore: release build artifacts (do not commit target/)"`

### Task 9: Review (security + code + test)

**Files:** none (review artifacts only)

**Interfaces:** consumes committed branch

- [ ] Step 1: Run security-review on firewall/pkexec/nft surfaces (command injection, rule validation).
- [ ] Step 2: Run code-review on Tauri IPC contract and UI.
- [ ] Step 3: Run test-master coverage check; fix gaps from Review Focus table.
- [ ] Step 4: Commit fixes; `git commit -m "fix: review findings"`

### Task 10: Website + README + release prep

**Files:**
- Create: `site/` (static TR+EN Cloudflare Pages site)
- Create: `README.md` (TR/EN)
- Modify: `MEMORY.md` — add foxnetwarden entry

**Interfaces:** consumes spec + built packages

- [ ] Step 1: Write README (features, privacy, build `cargo tauri build`, run binary, honest limits: root, no auto-update, no pcap).
- [ ] Step 2: Write site/ hero + features grid + install (.rpm primary + .deb + AppImage) + privacy + MIT; deploy notes for user's Cloudflare account.
- [ ] Step 3: Commit `git add site/ README.md MEMORY.md; git commit -m "docs: README + website + portfolio entry"`

## Self-review

- Spec coverage: live traffic (T1/T5/T6), app-based permissions (T3/T5/T6), suspicious detection (T2/T6), DNS/IP tracking (T4/T6), firewall nftables (T3/T5/T6), history/analysis (T2/T6/T7), tracker detection (T2/T6), kill switch (T3/T5/T6). All covered.
- Step scan: every step produces exactly one checkable thing; no "TBD"/"appropriate validation" lines.
- Type consistency: Connection/DnsEvent/HistoryRow names used consistently across tasks; Tauri command names match main.rs and app.js.
- Review Focus: all 6 rows pinned to owning tasks (T1 collector `?` pid; T3 root denial/kill switch/crash recovery; T4 DNS invisible mode; T5 constrained rules; T6 tray/window-close; T2 blocklist/CDN staleness).
- Proportion: plan ~ spec size; no function bodies except small algorithms not determined by signatures.

Plan complete and saved to `docs/superpowers/plans/2026-11-18-foxnetwarden.md`. Please review the plan. Does it capture what you want, and which execution approach should we use?

- **Subagent-driven** — fresh subagent per task + fresh reviewer before next task; whole-branch review at end. Most thorough; fresh context per task/review.
- **Native** — I implement every task myself in this session, then one reviewer on the whole branch. Cheapest/fastest; independent review only at end.

For this plan I recommend **Native** — tasks share tight Rust module interfaces and the plan already pins signatures, so end-to-end consistency is cheap; a shipped firewall mistake (kill switch leaking / lockout) is caught by the Review Focus tests, not by per-task review. Does the plan capture what you want, and which approach should we use?
