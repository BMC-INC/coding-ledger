# Expanded Open Product Design

## Decision

Coding Ledger will expand as an open-core product without locking features in
this release. The scanner, normalized local ledger, analytics, reports, and
dashboard remain open and local-first. Monetization boundaries will be chosen
only after real users show which workflows and analyses they value.

The initial customer is an individual builder who wants a credible portfolio of
how they build. The product may later support consent-based team performance
analytics, particularly for organizations that value effective AI adoption,
verification habits, and delivery consistency.

## Product promise

> Prove how you build without exposing what you build.

Coding Ledger measures activity and provides evidence about performance through
outcomes. Hours and agent usage are not treated as quality by themselves.
Reports connect work receipts to commits, tests, reviews, releases, project
focus, and sustained delivery wherever the available evidence supports it.

## Source architecture

All sources normalize into the existing SQLite event model. Every adapter:

1. discovers only documented local locations;
2. extracts timestamps, project identity, event counts, and safe aggregates;
3. never stores prompts, responses, source code, tool arguments, tool output,
   credentials, or environment values;
4. upserts growing sessions by stable path or session identifier;
5. reports unavailable, partial, and malformed sources without aborting the
   overall scan.

New adapters:

- **Gemini:** `~/.gemini/tmp/*/chats/session-*.json[l]`
- **Antigravity:** application logs and VS Code-compatible local edit history
  under the Antigravity and Antigravity IDE application-support directories
- **Grok Build:** `$GROK_HOME/sessions/**/events.jsonl`, falling back to
  `~/.grok/sessions/**/events.jsonl`

Gemini and Antigravity receipts remain separate sources even when they use the
same model. Grok model identifiers are metadata, not separate hour sources.

## Analytics

The expanded report adds transparent, reproducible analytics:

- Your Coding versus AI Coding and AI leverage over time
- project portfolio by hours, commits, sessions, and active days
- project focus and neutrally labeled portfolio diversity
- multi-project versus single-project momentum comparisons
- tool and agent mix
- verification-loop density
- session-to-commit conversion and lag where timestamps support matching
- timestamp-qualified overlap accounting that preserves independent AI runtime
- parallel-agent utilization
- shipping cadence and streaks
- evidence coverage and confidence by source

Every metric includes a plain-language definition. Unsupported metrics are
omitted or labeled unavailable rather than inferred.

## Product experience

The generated local site gains a product overview that explains the promise,
supported sources, privacy boundary, use cases, and analytics. The existing
field report remains the authenticated-by-possession personal experience.
Everything works without a hosted account or network connection after source
installation.

Potential future hosted verification will accept only user-approved aggregates
and cryptographic receipt hashes. It is explicitly outside this release.

## Verification

Each adapter receives fixture-based parser tests plus an idempotent rescan test.
Live scans must prove discovery against the installed Gemini and Antigravity
data without exposing stored content. Grok support is verified against the
open-source event schema and remains discoverable-but-empty until Grok Build is
used locally.

The final release requires the complete Python test suite, syntax validation,
dashboard generation, browser console and visual checks, a clean tracked
worktree, matching local/remote commits, and passing CI.
