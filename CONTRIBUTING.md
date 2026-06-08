# Contributing to the Cognis Neural Suite

Thanks for your interest in collaborating. This project runs a **collaboration-pull**
model: we develop in the open, and we actively want your pull requests, issues, and
ideas. This guide explains how to contribute and what happens to your contribution.

> **License at a glance.** This project is **source-available** under the
> [Cognis Open Collaboration License (COCL) v1.0](LICENSE). It is free for
> **personal, internal-evaluation, research, and educational** use. **Commercial /
> production use requires a license** — email `licensing@cognis.digital`.

---

## Ways to contribute

- **Bug reports** — open an issue with steps to reproduce, expected vs. actual.
- **Feature requests** — open an issue describing the problem first, then the proposal.
- **Pull requests** — fixes, new detections/rules/probes, docs, demo scenarios.
- **Demo scenarios** — every tool ships `demos/NN-<name>/SCENARIO.md`; new realistic
  scenarios (with expected findings) are some of the most valuable PRs we receive.
- **Upstream credits** — if we compose or fork an OSS project and missed crediting it,
  send a PR adding it to the README "Credits / Built on" section.

## Developer workflow

```bash
git clone https://github.com/cognis-digital/<tool>.git
cd <tool>
pip install -e ".[dev]"      # editable install + dev extras
pytest -q                    # run the test suite
<tool> scan demos/           # smoke-check against the bundled demo
```

- Keep PRs focused; one logical change per PR.
- Match the surrounding code style; add/adjust tests for behavior changes.
- Run `pytest` and the demo smoke check before pushing.
- Update the README and any affected `SCENARIO.md` when behavior changes.

## Contribution terms (please read)

By submitting a contribution you agree to the terms in **Section 4 of the
[COCL](LICENSE)**:

1. **Inbound = outbound.** Your contribution is licensed to the project and its
   users under the COCL.
2. **Relicensing grant.** You grant Cognis Digital LLC the right to relicense your
   contribution (including commercially) as part of the Suite. This is what makes the
   dual-licensing model possible and keeps the project sustainable.
3. **Sign-off (DCO).** Add a `Signed-off-by:` line to each commit certifying you have
   the right to submit it:
   ```bash
   git commit -s -m "your message"
   ```

Accepted contributions are credited in the project history and, where appropriate, in
a `CONTRIBUTORS` / `NOTICE` file.

## Responsible use

Many Suite tools are **dual-use security software**. Only run them against systems,
data, and identities you own or are explicitly authorized in writing to test, and in
compliance with applicable law. Security-sensitive reports should be sent privately to
`security@cognis.digital` rather than filed as public issues — see `SECURITY.md`.

## Code of conduct

Be respectful and constructive. Harassment or abuse is not tolerated. Maintainers may
remove comments, commits, and contributions that violate these norms.

---

**Cognis Digital** — *Making Tomorrow Better Today.* · https://cognis.digital
