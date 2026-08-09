# Contributing

FMD uses trunk-based development with `main` as the only permanent branch. Changes are made on
short-lived branches, reviewed through a pull request, and squash-merged.

## Branches

Use `hrxdev/<kind>/<kebab-case-summary>`, where kind is one of `feat`, `fix`, `docs`, `refactor`,
`chore`, `release`, or `hotfix`.

Examples:

```text
hrxdev/feat/job-scheduler
hrxdev/fix/sftp-host-verification
hrxdev/refactor/engine-adapters
```

## Commits and pull request titles

Use Conventional Commits 1.0.0 in English:

```text
<type>(<scope>)!: <imperative description>

<optional body>

<optional footers>
```

Allowed types are `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`,
`chore`, and `revert`.

Allowed scopes are `app`, `core`, `ui`, `engine`, `download`, `update`, `i18n`, `security`,
`build`, `release`, `deps`, and `docs`. A scope is optional.

- Start the subject description with a lowercase imperative verb.
- Keep the complete subject at or below 72 characters and omit the final period.
- Keep each commit focused on one intent.
- Use the body for motivation and behavior changes, not a file inventory.
- Keep non-URL body lines at or below 100 characters.
- Add a `BREAKING CHANGE:` footer whenever the subject contains `!`.
- Reference an issue with `Refs: #123`.
- Do not push `fixup!`, `squash!`, `WIP`, or merge commits.

Examples:

```text
feat(core): add resumable job scheduler
fix(engine): preserve partial file after cancellation
docs: clarify protected media limitations
chore(deps): update tauri dependencies
```

The pull request title follows the same format because it becomes the squash commit subject.
The pull request body uses the sections `Summary`, `Why`, `Testing`, `Risks`, and `Checklist`.

## Verification

Run these checks before requesting review:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
pnpm install --frozen-lockfile
pnpm check
pnpm build
```
