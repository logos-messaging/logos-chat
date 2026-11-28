# Reviews and PRs

## Severity ladder

Every review comment starts with a tag:

| Tag | Meaning |
|---|---|
| `[Dust]` | Trivial; ignore freely |
| `[Sand]` | Nice to have; may be deferred |
| `[Pebble]` | Must be addressed, by a change or an answer |
| `[Boulder]` | Blocks merge |
| `[?]` | Question |
| `[!]` | Praise, or an alarm |
| `[Future]` | Out of scope; worth a follow-up |

## Giving a review

- **Verify a claim against the code before posting it.** That includes claims
  from another reviewer or an agent.
- **Mark each finding Confirmed** (traced in the code or reproduced) **or
  Plausible**.
- **For a general pass, report Pebble and above only.**
- **For protocol changes, get a second, independent pass**: someone given the
  code and the spec, not the first reviewer's conclusions.
- **Check the doc comments against the code.** A contradiction is a Boulder.

The [review procedure](../procedures/review.md) produces this table:

| # | Issue | Ladder | Why | Fix | Comment to post | Line |
|---|---|---|---|---|---|---|

## Commits and PR titles

- Use conventional commits, phrased as the behaviour:
  `fix(core): check a GroupV3 key package's init key length`.
- Types: `feat`, `fix`, `refactor`, `chore`, `docs`, `ci`. For an advisory,
  use `chore(deps): bump X to Y for RUSTSEC-…`.
- Mark breaking changes with `!`: `feat(core)!: …`.
- Scopes: `core`, `client`, `group-v3`, `group-v2`, `delivery`, `storage`,
  `sqlite`, `identity`, `account`, `auth`, `adr`. Use one name per area:
  `group-v3`, not also `GV3`.

## Shaping a PR

- **One question per PR.** Split unrelated changes, or ask reviewers to review
  commit by commit.
- **Ship an API together with its caller.**
- **Stacked PRs:** crash fixes and plumbing go first. A fix that a later PR
  would remove is removed at the base.
- **Large features land in steps:** the design doc first, then a scaffold, then
  the behaviour.
- **Leave other people's modules alone** unless the PR is about them.
- **The body follows `.github/pull_request_template.md`:** Problem, Solution,
  and Notes or "Not in this PR". Say which decisions are temporary.
- **On re-review, reply to each comment with what changed**, for example
  "renamed to `record_epoch_data`".
