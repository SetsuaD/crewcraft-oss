# Security policy

CrewCraft's design depends on a few hard guarantees: the staff entrance does not answer a device it has not enrolled, device
keys never leave the device, every person signs in with a time-based one-time code, and the server never trusts a name
a client claims. Planned public entrances (guest meeting links, website visitors) are separate listeners with their own
limits. [docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md) describes them. A way around any of them is a
security bug.

## Reporting a vulnerability

Please report privately, not in a public issue or pull request:

- Use GitHub's **Report a vulnerability** button on this repository's **Security** tab (private vulnerability
  reporting).

Include what you found, how to reproduce it, and what an attacker could do with it. You will get an acknowledgement
within a few days and a plan for a fix. Please give us a reasonable time to release a fix before you publish details;
we will credit you in the release notes unless you ask us not to.

## Supported versions

CrewCraft is in early development and has no stable release yet. Fixes go to `main`; once releases exist, the latest
release will receive security fixes.

## Out of scope

Weaknesses that need an attacker who already controls the server host, or a device that is enrolled and unlocked, are
generally out of scope, though we still want to hear about defense-in-depth improvements.
