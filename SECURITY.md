# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**[Report a vulnerability](https://github.com/SetsuaD/crewcraft-oss/security/advisories/new)**
(Security tab › Advisories › Report a vulnerability).

Don't open a public issue or pull request for a vulnerability until a fix is released.

Useful to include:
- the CrewCraft commit or version, and where it runs (server OS, client platform);
- what an attacker can do, and what they need (network access only, an enrolled device, an account, a crafted file…);
- steps or a sample that reproduce it.

We'll acknowledge the report within a few days, keep you updated while we work on a fix, and credit you in the advisory
unless you'd rather not be named.

## Security contributor

[@SetsuaD](https://github.com/SetsuaD) is CrewCraft's security contributor: they triage private reports, coordinate
fixes and advisories, and review changes to the security-sensitive code (see
[`.github/CODEOWNERS`](.github/CODEOWNERS)).

## Supported versions

CrewCraft is in early development and has no release yet. Fixes go into `main`; once releases exist, fixes ship in the
next release and older releases don't get backported fixes.

## Scope

CrewCraft's design depends on a few hard guarantees, described in
[docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md):

- the staff entrance does not answer a device it has not enrolled;
- device keys never leave the device;
- every person signs in with a time-based one-time code;
- the server never trusts a name a client claims.

A way around any of them is in scope, as is anything that lets a message, file, request or network response read or
write data it shouldn't, run code, leak data, or crash the server. Crashes from hostile input count: CrewCraft treats
every panic on untrusted input as a bug. Planned public entrances (guest meeting links, website visitors) are separate
listeners with their own limits.

Weaknesses that need an attacker who already controls the server host, or a device that is enrolled and unlocked, are
generally out of scope, though we still want to hear about defense-in-depth improvements.
