Pull requests are opened against `main`.

Before opening one, please read [`AUDIT_SCOPE_RUST.md`](../AUDIT_SCOPE_RUST.md) if
your change touches `crypto-rs/`: that file lists the cryptographic invariants the
project treats as frozen, and a change that moves one needs to say so explicitly.

Adversarial review is the most valuable contribution this project can receive.
If you found a vulnerability, please report it privately through GitHub private
vulnerability reporting rather than in a public pull request or issue.

## Type of change

**Description:**


**Select the type of change(s) made in this pull request:**
- [ ] Bug fix *(fixes an issue)*
- [ ] New feature *(adds functionality)*
- [ ] Documentation *(fix or addition to documentation)*
- [ ] Security *(changes a security property, or the reasoning behind one)*

----------------------------------------------------------------------------------------

Fixes #issue-number


## Proposed changes
<!-- Describe the changes the PR makes. -->

*
*
*

## Checks
<!-- Delete the lines that do not apply. -->

- [ ] `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` pass
- [ ] The Android build passes (`./gradlew :mobile:assembleDebug`)
- [ ] If a documented guarantee changed, the document that carries it changed too
