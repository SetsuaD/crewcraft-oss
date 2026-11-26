//! Authorization decisions from an external authorizer (REQUIREMENTS.md section 4; contract: docs/AUTHORIZER.md).
//! Task T600.
//!
//! Owns: the capabilities, the authorizer's answers as CrewCraft sees them, and the rules that turn answers over time
//! into access: a fresh `allow` with `use` to sign in, a re-check after 10 minutes (or sooner if asked), a retry after
//! 60 seconds when a check fails, at most 24 hours of grace from the last confirmation while the authorizer cannot be
//! reached (none for the visitor module), denials that stay until a newer `allow`, and stale answers ignored.
//! `commit_decision` refuses access when the decision cannot be stored and read back unchanged.
//! Called by: the server's session layer (next task: the HTTP transport and wiring). Calls: nothing; time is passed
//! in as whole seconds, so every rule is tested without a clock.

use std::collections::BTreeSet;
use std::fmt;

/// How long a good answer is trusted before CrewCraft asks again, at most.
pub const RECHECK_AFTER_GOOD_SECS: u64 = 600;
/// How long CrewCraft waits before asking again after a check that got no answer.
pub const RETRY_AFTER_FAILURE_SECS: u64 = 60;
/// The longest a grant is kept, from its last confirmation, while the authorizer cannot be reached.
pub const MAX_GRACE_SECS: u64 = 24 * 60 * 60;

/// Something a person may do (docs/AUTHORIZER.md, Capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    Use,
    Moderate,
    Respond,
    Dispatch,
}

impl Capability {
    /// The capability an authorizer names, or `None` for a name CrewCraft does not know (ignored, never an error).
    pub fn parse(name: &str) -> Option<Capability> {
        match name {
            "use" => Some(Capability::Use),
            "moderate" => Some(Capability::Moderate),
            "respond" => Some(Capability::Respond),
            "dispatch" => Some(Capability::Dispatch),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Capability::Use => "use",
            Capability::Moderate => "moderate",
            Capability::Respond => "respond",
            Capability::Dispatch => "dispatch",
        }
    }
}

/// A set of capabilities. Without `use`, it allows nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities(BTreeSet<Capability>);

impl Capabilities {
    /// The known capabilities among `names`; unknown names are dropped.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        Self(names.into_iter().filter_map(Capability::parse).collect())
    }

    pub fn has(&self, capability: Capability) -> bool {
        self.0.contains(&Capability::Use) && self.0.contains(&capability)
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.0.iter().map(|c| c.name()).collect()
    }
}

/// What the authorizer said, as CrewCraft understood it. Anything that is not a well-formed `allow` or `deny` is
/// `NoAnswer` (docs/AUTHORIZER.md): never a denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Allow { capabilities: Capabilities, revision: u64, recheck_after_secs: Option<u64> },
    Deny { revision: u64 },
    NoAnswer,
}

/// Where the grace rule applies. The visitor module keeps no grace at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    Staff,
    Visitor,
}

/// The last confirmed grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub capabilities: Capabilities,
    pub revision: u64,
    /// When the authorizer last confirmed it, in seconds.
    pub confirmed_at: u64,
    /// Until when it counts as fresh (the confirmation plus the re-check interval). After that it stands only inside
    /// the grace window, measured from `confirmed_at`, never from when CrewCraft last tried to ask.
    pub fresh_until: u64,
}

/// Everything CrewCraft keeps about one identity's authorization. Stored durably (`Ledger`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    pub grant: Option<Grant>,
    /// The revision of the newest denial; lifted only by an `allow` with a higher revision.
    pub denied_revision: Option<u64>,
    /// The highest revision seen in any answer, so an older answer is recognised as stale.
    pub highest_revision: u64,
    /// When to ask the authorizer next, in seconds.
    pub next_check_at: u64,
}

/// Why access was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The authorizer denied this identity (now or earlier, and no newer `allow` lifted it).
    Denied,
    /// The authorizer's answer does not include `use`.
    NoUse,
    /// No good answer, and no grant inside the grace window (or none allowed here).
    AuthorizerUnreachable,
    /// The decision could not be stored and read back unchanged.
    NotDurable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::Denied => "access was denied by the authorizer",
            Refusal::NoUse => "the authorizer did not grant use",
            Refusal::AuthorizerUnreachable => "the authorizer could not be reached and no recent grant is held",
            Refusal::NotDurable => "the authorization decision could not be stored",
        })
    }
}

/// The outcome for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Allowed(Capabilities),
    Refused(Refusal),
}

impl Record {
    /// Whether it is time to ask the authorizer again.
    pub fn check_due(&self, now: u64) -> bool {
        now >= self.next_check_at
    }

    /// Access between checks: the held grant while it is current or inside the grace window, else a refusal.
    pub fn current(&self, area: Area, now: u64) -> Access {
        if self.denied_revision.is_some() {
            return Access::Refused(Refusal::Denied);
        }
        let Some(grant) = &self.grant else { return Access::Refused(Refusal::AuthorizerUnreachable) };
        if !grant.capabilities.has(Capability::Use) {
            return Access::Refused(Refusal::NoUse);
        }
        // Past its fresh period, a grant only stands inside the grace window, and only where grace applies.
        if now >= grant.fresh_until && !within_grace(grant, area, now) {
            return Access::Refused(Refusal::AuthorizerUnreachable);
        }
        Access::Allowed(grant.capabilities.clone())
    }

    /// Apply the answer to a sign-in. Sign-in needs a fresh `allow` with `use` and never uses grace.
    pub fn sign_in(&self, answer: &Answer, now: u64) -> (Record, Access) {
        let (next, outcome) = self.apply(answer, now);
        let access = match outcome {
            // The grant was confirmed just now, so no grace is involved.
            Outcome::Fresh => next.current(Area::Visitor, now),
            Outcome::Denied => Access::Refused(Refusal::Denied),
            Outcome::Stale if next.denied_revision.is_some() => Access::Refused(Refusal::Denied),
            Outcome::Stale | Outcome::NoAnswer => Access::Refused(Refusal::AuthorizerUnreachable),
        };
        (next, access)
    }

    /// Apply the answer to a re-check of a signed-in session.
    pub fn recheck(&self, answer: &Answer, area: Area, now: u64) -> (Record, Access) {
        let (next, _) = self.apply(answer, now);
        let access = next.current(area, now);
        (next, access)
    }

    /// The record after an answer at `now`, and what kind of answer it was.
    fn apply(&self, answer: &Answer, now: u64) -> (Record, Outcome) {
        let mut next = self.clone();
        let outcome = match answer {
            Answer::Allow { capabilities, revision, recheck_after_secs } => {
                let stale = *revision < self.highest_revision || self.denied_revision.is_some_and(|denied| *revision <= denied);
                if stale {
                    next.next_check_at = now + RETRY_AFTER_FAILURE_SECS;
                    return (next, Outcome::Stale);
                }
                let wait = recheck_after_secs.unwrap_or(RECHECK_AFTER_GOOD_SECS).clamp(1, RECHECK_AFTER_GOOD_SECS);
                next.denied_revision = None;
                next.highest_revision = *revision;
                next.grant = Some(Grant { capabilities: capabilities.clone(), revision: *revision, confirmed_at: now, fresh_until: now + wait });
                next.next_check_at = now + wait;
                Outcome::Fresh
            }
            Answer::Deny { revision } => {
                if *revision >= self.highest_revision {
                    next.highest_revision = *revision;
                }
                // A denial always takes effect, even one older than a grant: refusing is the safe direction.
                next.denied_revision = Some(self.denied_revision.map_or(*revision, |d| d.max(*revision)));
                next.grant = None;
                next.next_check_at = now + RECHECK_AFTER_GOOD_SECS;
                Outcome::Denied
            }
            Answer::NoAnswer => {
                next.next_check_at = now + RETRY_AFTER_FAILURE_SECS;
                Outcome::NoAnswer
            }
        };
        (next, outcome)
    }
}

/// What kind of answer `apply` saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Fresh,
    Stale,
    Denied,
    NoAnswer,
}

fn within_grace(grant: &Grant, area: Area, now: u64) -> bool {
    area == Area::Staff && now.saturating_sub(grant.confirmed_at) < MAX_GRACE_SECS
}

/// Where records live. The server's store implements it; `commit` must be durable before it returns.
pub trait Ledger {
    type Error;
    fn commit(&mut self, identity: &str, record: &Record) -> Result<(), Self::Error>;
    fn read_back(&self, identity: &str) -> Result<Option<Record>, Self::Error>;
}

/// Store `record` for `identity` and return `access`, unless the record cannot be committed and read back unchanged,
/// in which case access is refused (docs/AUTHORIZER.md: a decision that is not durable grants nothing).
pub fn commit_decision<L: Ledger>(ledger: &mut L, identity: &str, record: &Record, access: Access) -> Access {
    if ledger.commit(identity, record).is_err() {
        return Access::Refused(Refusal::NotDurable);
    }
    match ledger.read_back(identity) {
        Ok(Some(stored)) if &stored == record => access,
        _ => Access::Refused(Refusal::NotDurable),
    }
}
