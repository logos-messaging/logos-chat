# Review

Review the target the user names: a PR number, a branch, or the working tree
diff by default. Read `docs/guidelines/` first. The findings are measured
against those rules.

## Pass 1: read the change

1. Get the diff (`gh pr diff N`, `git diff main...HEAD`, or `git diff`).
2. For each touched file, read the surrounding code and the doc comments, not
   only the hunk.
3. For protocol paths, open the spec the code implements: the LIP or the
   RFC/draft section in `docs/guidelines/mls-and-specs.md`.

## Pass 2: hunt

Check in this order. Stop at real issues, not style preferences.

1. **Untrusted input:** size before decode, key gating, `try_from`, bounded
   stores and work.
2. **Authentication:** does unverified data decide anything? Are ties broken on
   attacker-chosen values?
3. **Convergence:** do members decide from shared state? What happens on a
   duplicate, a replay, or a rival commit at the same epoch?
4. **Failure:** is old state kept until new state is installed? Is anything
   recorded as done before it succeeds?
5. **Panics:** `unwrap`/`expect`/indexing reachable from remote input.
6. **Docs vs code:** every doc comment and claim in the diff checked against
   what the code does.
7. **Tests:** real outcome asserted, counts asserted where duplicates are a
   bug, "every X" covers every X, the new test can fail.
8. **Scope and shape:** minimal diff, names, boundaries, no speculative
   abstractions, comment length.

## Verify

For each candidate finding, trace it in the code or reproduce it. Mark it
**Confirmed** or **Plausible**. Drop anything you can't support. Never repeat
a claim from another reviewer or tool without checking it.

For a change to a protocol path, also get an independent pass from a fresh
agent session or a colleague. Give it the diff and the spec only, not your
findings, then merge its results.

## Report

Rank the findings by severity, then present this table:

| # | Issue | Ladder | Why | Fix | Comment to post | Line |
|---|---|---|---|---|---|---|

- **Ladder:** `Dust` < `Sand` < `Pebble` < `Boulder`. A doc that contradicts
  its code, or a security flaw, is at least `Boulder`.
- **Comment to post:** one or two sentences, ready to paste, starting with the
  tag, for example `[Pebble] …`. Write it plainly, as a colleague would.
- **Line:** a markdown link `[file.rs:42](path/file.rs:42)`.
- Add a Confirmed/Plausible marker after the issue.
- For a general pass, list `Pebble` and above only.

Output the table. Posting comments is left to the person who asked.
