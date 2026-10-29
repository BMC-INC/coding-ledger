# Releasing Coding Ledger

1. Update `project.version` in `pyproject.toml` and review the README's channel notes.
2. Run unit tests, build the wheel and source distribution, and run
   `python scripts/smoke-installed.py /absolute/path/to/installed/coding-ledger`
   against a clean installation outside the checkout. The smoke test creates
   temporary synthetic Git history and never scans the user's projects or logs.
3. Merge the reviewed change, then tag that exact commit as `v<version>` and push
   the tag. The Release workflow repeats validation and publishes GitHub release
   artifacts with SHA-256 checksums. It also accepts a manual rerun against the tag.
4. Update the Homebrew tap's tag, checksum and installed asset directory. Verify
   the checksum against the downloaded archive, and test the formula before merging.

## Optional PyPI publication

GitHub release downloads work without a PyPI account. To enable PyPI publication,
register a trusted publisher in the existing `coding-ledger` PyPI project:

- Owner: `BMC-INC`
- Repository: `coding-ledger`
- Workflow: `pypi.yml`
- Environment: `pypi`

Create the matching GitHub environment with appropriate release protection, and
run the separate **Publish to PyPI** workflow with the already published release
tag only after registration. It downloads the validated GitHub release packages.
The workflow requests a short-lived OIDC credential; do not add a PyPI token to
source control. GitHub releases never trigger PyPI publication automatically. Verify the
published version and a clean installation from PyPI before claiming availability
on that channel. If a release already exists on PyPI, do not overwrite its files.
