// T104: @mention extraction.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::mentions::mentions;

fn v(x: &[&str]) -> Vec<String> {
    x.iter().map(|s| s.to_string()).collect()
}

#[test]
fn plain_mentions() {
    assert_eq!(mentions("hi @Ana and @bo."), v(&["ana", "bo"]));
    assert_eq!(mentions("@cy"), v(&["cy"]));
    assert_eq!(mentions("(@dee) ok"), v(&["dee"]));
}

#[test]
fn names_may_hold_dots_dashes_and_underscores() {
    assert_eq!(mentions("@a.b-c_d"), v(&["a.b-c_d"]));
    assert_eq!(mentions("ping @x--."), v(&["x"]));
}

#[test]
fn emails_and_bare_at_signs_are_not_mentions() {
    assert_eq!(mentions("mail ana@example.org"), v(&[]));
    assert_eq!(mentions("@ alone"), v(&[]));
    assert_eq!(mentions("@."), v(&[]));
    assert_eq!(mentions("a@@b"), v(&[]));
}

#[test]
fn duplicates_collapse_case_insensitively_in_first_seen_order() {
    assert_eq!(mentions("@Bo @ana @BO @bo"), v(&["bo", "ana"]));
}

#[test]
fn code_spans_are_ignored() {
    assert_eq!(mentions("`@ana` @bo"), v(&["bo"]));
    assert_eq!(mentions("@cy `unclosed @dee"), v(&["cy"]));
    assert_eq!(mentions("`a` @ee `b`"), v(&["ee"]));
}

#[test]
fn names_longer_than_32_are_not_mentions() {
    let ok = "a".repeat(32);
    assert_eq!(mentions(&format!("@{ok}")), v(&[ok.as_str()]));
    assert_eq!(mentions(&format!("@{}", "a".repeat(33))), v(&[]));
}

#[test]
fn a_non_ascii_character_ends_the_name() {
    assert_eq!(mentions("@zoë"), v(&["zo"]));
}

#[test]
fn an_at_sign_right_after_a_mention_is_not_a_new_mention() {
    // Review regression (2026-11-08): the first passing patch treated the character after a mention as start-of-text.
    assert_eq!(mentions("@ana@bo"), v(&["ana"]));
    assert_eq!(mentions("@ana.@bo"), v(&["ana"]));
    assert_eq!(mentions("@ana (@bo)"), v(&["ana", "bo"]));
}
