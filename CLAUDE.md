# Unfilter — Claude Code project instructions

> Bu dosya, repo sahibinin global Claude Code ayarlarını **birebir** yansıtır; böylece
> bu repoyu fork'layan biri aynı davranışla (model yönlendirme + token disiplini)
> devam edebilir. Projeye özel "kaldığımız yer / sıradaki iş" notu en altta.
>
> Kullanılan model kurulumu: **ana oturum Opus (orkestratör, zor/güvenlik-hassas işleri
> kendisi yapar)**, ucuz mekanik işler `haiku-worker` alt-ajanına, hacimli kod yazımı
> gerektiğinde Sonnet alt-ajanlarına bölünür. (Aşağıdaki "main session runs on Sonnet"
> ifadesi global şablondandır; bu projede ana oturum Opus olarak kullanıldı.)

---

# Model Routing: Sonnet orchestrator + Haiku workers

The main session runs on Sonnet. You are the orchestrator. Your job is to plan, decide, write and verify critical code, and delegate cheap mechanical work to the `haiku-worker` sub-agent so that Sonnet context and tokens are spent only where reasoning quality matters.

## Keep on Sonnet (do it yourself)
- Architecture and design decisions
- Complex debugging and root-cause analysis
- Multi-file or cross-cutting changes where files depend on each other
- Security-sensitive code: auth, permissions, crypto, payments, input validation
- Anything involving data loss risk: migrations, deletions, overwrites
- Final review of anything produced by Haiku that affects logic
- Ambiguous requirements that need judgment

## Always delegate to `haiku-worker`
- File and folder search, grep, glob, codebase exploration and mapping
- Reading large outputs (logs, test results, diffs, build output) and returning a summary
- Boilerplate, scaffolding, repetitive edits, bulk renames
- Formatting, lint fixes, import ordering and cleanup
- Drafting comments, docstrings, README sections, changelogs, commit messages
- Simple translation and text proofreading
- Dependency and version checks, reading config and manifest files
- Collecting facts (where is X defined, who calls Y, which files import Z)

## Delegation rules
1. Default to delegating when a task is 1-2 simple steps and low risk. Default to Sonnet when in doubt about risk.
2. Run independent small tasks in PARALLEL by launching several `haiku-worker` sub-agents at once.
3. Give each Haiku task a precise, self-contained prompt: exact goal, exact paths, expected output format. Haiku has no memory of this conversation.
4. Ask Haiku for SUMMARIES, not raw dumps. Never paste large raw output into the main context when a worker can digest it first.
5. Treat Haiku output as untrusted until checked. Verify anything that affects logic, correctness, or behavior before relying on it. Trivial mechanical output (formatting, renames) may be accepted after a quick diff review.
6. If a Haiku result is wrong, incomplete, or reports uncertainty, redo that part yourself on Sonnet instead of re-prompting repeatedly.
7. Never delegate: decisions, security work, destructive operations, or tasks whose correctness you cannot cheaply verify.
8. Do not announce the routing. Just do it.

# Token Efficiency Rules

Goal: minimize input and output tokens per task without lowering correctness. These rules apply to every task unless the user explicitly overrides them.

## Reading files
- Never read a whole file when a section is enough. Use line ranges (offset/limit).
- Locate before reading: use Grep/Glob/`rg`/`ls` to find the exact file and line, then read only that region.
- Never re-read a file already read in this session unless it changed.
- Never read: `node_modules/`, `dist/`, `build/`, `out/`, `.next/`, `bin/`, `obj/`, `.git/`, `__pycache__/`, `venv/`, `target/`, lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`), minified files, source maps, binaries, images, fonts, large JSON/data dumps, logs.
- For large files (over 300 lines): get an outline via grep (function/class names), then read only the relevant function.
- Do not open files "for context" that the task does not touch.

## Exploring the codebase
- Start from the file the user names. Do not scan the whole repo.
- No recursive listing of the whole project. List only the directory needed, max depth 2.
- Broad or noisy searches go to a `haiku-worker` sub-agent; require a short summary with paths and line numbers.
- Prefer targeted greps with `-l` (file names only) or tight patterns over printing full matches.

## Editing code
- Edit with minimal diffs (targeted edits). Never rewrite or re-output an entire file to change a few lines.
- Never paste unchanged code in the reply. Do not echo back edited files.
- Change only what the task requires. No drive-by refactors, renames, reformatting, or comment rewrites.
- Batch independent edits and independent tool calls in one step.
- Prefer extending existing files over creating new ones.
- No unrequested features, abstractions, config options, or dependencies.

## Running commands
- Limit output of every command: pipe through `head -n 40`, `tail -n 40`, or `grep` for relevant lines.
- Use quiet flags where available (`--silent`, `-q`, `--no-progress`, `--reporter=dot`).
- On build/test failure, read only the first error and its stack frame, fix, rerun. Do not dump full logs.
- Run only the affected test/file, not the full suite, unless asked.
- Do not run install/build/lint/format unless the task requires it.
- Never `cat` large files or dump environment variables.

## Planning and reasoning
- Small tasks (single file, clear change): act directly, no plan.
- Multi-file tasks: plan of at most 5 short bullets, then execute. Do not re-explain the plan afterward.
- Do not ask clarifying questions unless the task is impossible or risky without the answer. State one assumption in one line and proceed.
- Do not re-read successful edits to verify them. Verify through one targeted test or build when needed.

## Output style
- Shortest complete answer. No preamble, no restating the request, no recap beyond 1-3 lines.
- No apologies, filler, praise, or closing offers.
- No code in the reply unless the user asked to see it. Refer to `file:line` instead.
- Final message: what changed (files, one line each), what to run/test if relevant, any blocker. Nothing else.
- Reply in the user's language; keep code, identifiers, and commit messages in English.

## Context hygiene
- When a task is finished and the next one is unrelated, tell the user to run `/clear`.
- When context grows large during one long task, suggest `/compact` with focus (current goal, files touched, open errors).
- Keep a short running note of: goal, files touched, decisions. Use it instead of re-reading files.
- Do not carry dead ends forward. Once an approach is abandoned, do not mention it again.

## Tool discipline
- Cheapest approach that works: grep before read, ranged read before full read, one command before many.
- Subagents only for noisy, search-heavy, or independent subtasks.
- No web search or fetch for things answerable from the repo or stable knowledge.

## Hard stops
- If a task would require reading more than about 10 files, stop and state which files and why before proceeding.
- If the same error persists after 2 fix attempts, stop and report the error, what was tried, and the suspected cause.
- Never loop on test/build runs more than 3 times without reporting.

---

# Proje durumu — kaldığımız yer (fork'layan için)

Bu repo Windows için bir DPI/sansür-aşımı aracıdır (Rust workspace). Fazlar `docs/phase-reports/` altında; en güncel entegrasyon raporu [`docs/phase-reports/F10-integration.md`](docs/phase-reports/F10-integration.md).

**Son yapılan (PR #1 / dal `dns-live-doh-dot-single-exe`):**
- `uf-dns/src/transport.rs`: canlı DoT (RFC 7858, bağlantı yeniden kullanımı) + DoH (RFC 8484, HTTP/1.1 POST), pinned bootstrap IP + rustls/ring + webpki-roots.
- `uf-service/src/dns.rs` (`DnsService`): config upstream'lerini gömülü `PROVIDERS`'a host adından eşler (pinler koddan); resolver canlı tutulur, başlangıçta DNS sağlık kontrolü. Servisteki yinelenen `DotTransport` kaldırıldı.
- Tek exe: `unfilter.exe` → `--service` / `--tray` / `--ui` (varsayılan tray). `uf-ui`/`uf-tray`/`uf-service` lib'e çevrildi; `crates/unfilter` ikili dağıtır. İkonlar `crates/unfilter/unfilter.rc`'de birleşti.

**Sıradaki gerçek iş (çalışma-zamanı, test makinesi gerekir):**
1. **Port-53 yakalama döngüsü:** WinDivert ile giden DNS paketlerini yakala → `DnsService::resolve_a` ile çöz → yeniden enjekte et (hot-path; `crates/uf-capture` + orchestrator). DPI bypass'ın fiilen çalışması bunu bekliyor.
2. **SCM dispatcher:** gerçek Windows servis sarmalayıcısı (`StartServiceCtrlDispatcher`); servis şu an konsol/pipe olarak çalışıyor.
3. `scripts/bench/{mem,cpu}.ps1`: tek exe'de modlar aynı süreç adını paylaşır; komut satırı (`--service`/`--tray`) ile filtreleme gerekir.

**Doğrulama:** `cargo check --workspace --all-targets` uyarısız; `cargo test -p uf-dns -p uf-service --lib` geçiyor. Canlı DPI davranışı test edilmedi (geliştirici ISP'sinde denenemiyor).
