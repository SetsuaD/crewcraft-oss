//! T600: the external authorizer's answers turned into access, by the rules in docs/AUTHORIZER.md and REQUIREMENTS.md
//! section 4. Time is whole seconds from 0; no clock, no network.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;

use crewcraft_authz::{
    Access, Answer, Area, Capabilities, Capability, Ledger, MAX_GRACE_SECS, RECHECK_AFTER_GOOD_SECS, RETRY_AFTER_FAILURE_SECS, Record, Refusal,
    commit_decision,
};

fn allow(names: &[&str], revision: u64) -> Answer {
    Answer::Allow { capabilities: Capabilities::from_names(names.iter().copied()), revision, recheck_after_secs: None }
}

fn allowed(access: &Access) -> bool {
    matches!(access, Access::Allowed(_))
}

#[test]
fn capabilities_ignore_unknown_names_and_need_use() {
    let caps = Capabilities::from_names(["use", "moderate", "fly"]);
    assert_eq!(caps.names(), ["use", "moderate"]);
    assert!(caps.has(Capability::Moderate));
    let without_use = Capabilities::from_names(["moderate", "respond"]);
    assert!(!without_use.has(Capability::Moderate), "nothing counts without use");
    assert!(!Capabilities::from_names([]).has(Capability::Use));
}

#[test]
fn sign_in_needs_a_fresh_allow_with_use() {
    let record = Record::default();
    let (_, access) = record.sign_in(&allow(&["use", "moderate"], 1), 100);
    match access {
        Access::Allowed(caps) => assert!(caps.has(Capability::Moderate)),
        other => panic!("{other:?}"),
    }
    assert_eq!(record.sign_in(&allow(&["moderate"], 1), 100).1, Access::Refused(Refusal::NoUse));
    assert_eq!(record.sign_in(&Answer::Deny { revision: 1 }, 100).1, Access::Refused(Refusal::Denied));
    assert_eq!(record.sign_in(&Answer::NoAnswer, 100).1, Access::Refused(Refusal::AuthorizerUnreachable));

    // A good grant from earlier does not carry a sign-in through an outage: sign-in never uses grace.
    let (signed, _) = record.sign_in(&allow(&["use"], 1), 100);
    assert_eq!(signed.sign_in(&Answer::NoAnswer, 200).1, Access::Refused(Refusal::AuthorizerUnreachable));
}

#[test]
fn rechecks_are_scheduled_by_the_rules() {
    let (record, _) = Record::default().sign_in(&allow(&["use"], 1), 1000);
    assert_eq!(record.next_check_at, 1000 + RECHECK_AFTER_GOOD_SECS);
    assert!(!record.check_due(1599) && record.check_due(1600));
    let sooner = Answer::Allow { capabilities: Capabilities::from_names(["use"]), revision: 1, recheck_after_secs: Some(300) };
    assert_eq!(Record::default().sign_in(&sooner, 0).0.next_check_at, 300);
    let later = Answer::Allow { capabilities: Capabilities::from_names(["use"]), revision: 1, recheck_after_secs: Some(5000) };
    assert_eq!(Record::default().sign_in(&later, 0).0.next_check_at, RECHECK_AFTER_GOOD_SECS, "never longer than 10 minutes");
    let zero = Answer::Allow { capabilities: Capabilities::from_names(["use"]), revision: 1, recheck_after_secs: Some(0) };
    assert_eq!(Record::default().sign_in(&zero, 0).0.next_check_at, 1);
    let (failed, _) = record.recheck(&Answer::NoAnswer, Area::Staff, 1600);
    assert_eq!(failed.next_check_at, 1600 + RETRY_AFTER_FAILURE_SECS);
}

#[test]
fn grace_lasts_24_hours_from_the_last_confirmation_for_staff_only() {
    let (mut record, _) = Record::default().sign_in(&allow(&["use"], 1), 0);
    // The authorizer goes quiet; every retry fails. Retrying must never stretch the grace window.
    let mut now = RECHECK_AFTER_GOOD_SECS;
    while now < MAX_GRACE_SECS {
        let (next, access) = record.recheck(&Answer::NoAnswer, Area::Staff, now);
        assert!(allowed(&access), "still inside grace at {now}");
        record = next;
        now += RETRY_AFTER_FAILURE_SECS;
    }
    let (_, access) = record.recheck(&Answer::NoAnswer, Area::Staff, MAX_GRACE_SECS);
    assert_eq!(access, Access::Refused(Refusal::AuthorizerUnreachable));
    assert_eq!(record.current(Area::Staff, MAX_GRACE_SECS + 5), Access::Refused(Refusal::AuthorizerUnreachable));
    // Between checks, too: a grant past its fresh period and past grace is refused even if the next check is not due.
    assert!(!record.check_due(record.next_check_at - 1));
    assert_eq!(record.current(Area::Staff, MAX_GRACE_SECS + 1), Access::Refused(Refusal::AuthorizerUnreachable));

    // The visitor module keeps no grace: once the grant is no longer fresh, a missing answer refuses.
    let (fresh, _) = Record::default().sign_in(&allow(&["use", "respond"], 1), 0);
    assert!(allowed(&fresh.current(Area::Visitor, 10)));
    let (_, access) = fresh.recheck(&Answer::NoAnswer, Area::Visitor, RECHECK_AFTER_GOOD_SECS);
    assert_eq!(access, Access::Refused(Refusal::AuthorizerUnreachable));
}

#[test]
fn a_denial_sticks_until_a_newer_allow() {
    let (record, _) = Record::default().sign_in(&allow(&["use"], 4), 0);
    let (denied, access) = record.recheck(&Answer::Deny { revision: 5 }, Area::Staff, 600);
    assert_eq!(access, Access::Refused(Refusal::Denied));
    assert!(denied.grant.is_none());
    // Outages and restarts do not lift it: the record is what is stored.
    assert_eq!(denied.recheck(&Answer::NoAnswer, Area::Staff, 1200).1, Access::Refused(Refusal::Denied));
    // An allow at or below the denial's revision is stale (an old token, a lagging replica).
    assert_eq!(denied.recheck(&allow(&["use"], 5), Area::Staff, 1300).1, Access::Refused(Refusal::Denied));
    assert_eq!(denied.recheck(&allow(&["use"], 3), Area::Staff, 1300).1, Access::Refused(Refusal::Denied));
    assert_eq!(denied.sign_in(&allow(&["use"], 4), 1300).1, Access::Refused(Refusal::Denied));
    // A newer allow lifts it.
    let (lifted, access) = denied.sign_in(&allow(&["use"], 6), 1400);
    assert!(allowed(&access));
    assert!(lifted.denied_revision.is_none());
    // An old denial arriving late still takes effect: refusing is the safe direction.
    assert_eq!(lifted.recheck(&Answer::Deny { revision: 2 }, Area::Staff, 1500).1, Access::Refused(Refusal::Denied));
}

#[test]
fn a_stale_allow_never_changes_a_grant() {
    let (record, _) = Record::default().sign_in(&allow(&["use"], 10), 0);
    let (after, access) = record.recheck(&allow(&["use", "moderate"], 9), Area::Staff, 600);
    assert_eq!(after.grant, record.grant, "an older answer is ignored, even one that grants more");
    assert_eq!(after.next_check_at, 600 + RETRY_AFTER_FAILURE_SECS);
    match access {
        Access::Allowed(caps) => assert!(!caps.has(Capability::Moderate)),
        other => panic!("{other:?}"),
    }
    // The same revision again is a normal re-confirmation.
    let (again, _) = record.recheck(&allow(&["use"], 10), Area::Staff, 600);
    assert_eq!(again.grant.as_ref().unwrap().confirmed_at, 600);
}

#[derive(Default)]
struct MemoryLedger {
    rows: HashMap<String, Record>,
    fail_commit: bool,
    corrupt_on_read: bool,
}

impl Ledger for MemoryLedger {
    type Error = &'static str;

    fn commit(&mut self, identity: &str, record: &Record) -> Result<(), Self::Error> {
        if self.fail_commit {
            return Err("disk full");
        }
        self.rows.insert(identity.to_owned(), record.clone());
        Ok(())
    }

    fn read_back(&self, identity: &str) -> Result<Option<Record>, Self::Error> {
        let mut row = self.rows.get(identity).cloned();
        if self.corrupt_on_read
            && let Some(r) = row.as_mut()
        {
            r.highest_revision += 1;
        }
        Ok(row)
    }
}

#[test]
fn a_decision_that_is_not_durable_grants_nothing() {
    let (record, access) = Record::default().sign_in(&allow(&["use"], 1), 0);
    let mut ledger = MemoryLedger::default();
    assert!(allowed(&commit_decision(&mut ledger, "https://id.example.org|42", &record, access.clone())));
    assert_eq!(ledger.read_back("https://id.example.org|42").unwrap(), Some(record.clone()));

    let mut failing = MemoryLedger { fail_commit: true, ..Default::default() };
    assert_eq!(commit_decision(&mut failing, "x", &record, access.clone()), Access::Refused(Refusal::NotDurable));
    let mut corrupt = MemoryLedger { corrupt_on_read: true, ..Default::default() };
    assert_eq!(commit_decision(&mut corrupt, "x", &record, access), Access::Refused(Refusal::NotDurable));
}

#[test]
fn no_grant_means_no_access() {
    assert_eq!(Record::default().current(Area::Staff, 0), Access::Refused(Refusal::AuthorizerUnreachable));
}
