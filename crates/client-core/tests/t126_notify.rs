#![allow(clippy::unwrap_used)]

use crewcraft_client_core::notify::{Incoming, Level, Notify, Quiet, Settings};

#[test]
fn quiet_new_rejects_1440_or_greater() {
    assert!(Quiet::new(0, 1440).is_none());
    assert!(Quiet::new(1440, 0).is_none());
    assert!(Quiet::new(600, 1440).is_none());
    assert!(Quiet::new(1440, 600).is_none());
    assert!(Quiet::new(2880, 0).is_none());
}

#[test]
fn quiet_new_accepts_valid_values() {
    assert!(Quiet::new(0, 1439).is_some());
    assert!(Quiet::new(60, 60).is_some());
    assert!(Quiet::new(1320, 420).is_some());
    assert!(Quiet::new(0, 1).is_some());
}

#[test]
fn quiet_contains_standard_window() {
    let q = Quiet::new(60, 120).unwrap();
    assert!(q.contains(60));
    assert!(q.contains(90));
    assert!(q.contains(119));
    assert!(!q.contains(59));
    assert!(!q.contains(120));
    assert!(!q.contains(0));
    assert!(!q.contains(720));
}

#[test]
fn quiet_contains_past_midnight_window() {
    // 22:00 (1320) to 07:00 (420)
    let q = Quiet::new(1320, 420).unwrap();
    assert!(q.contains(1320));
    assert!(q.contains(1400));
    assert!(q.contains(1439));
    assert!(q.contains(0));
    assert!(q.contains(300));
    assert!(q.contains(419));
    assert!(!q.contains(1319));
    assert!(!q.contains(420));
    assert!(!q.contains(720));
}

#[test]
fn quiet_contains_zero_width_is_always_false() {
    let q = Quiet::new(60, 60).unwrap();
    assert!(!q.contains(60));
    assert!(!q.contains(0));
    assert!(!q.contains(720));
    assert!(!q.contains(1439));
}

#[test]
fn quiet_contains_applies_modulo_1440() {
    let q = Quiet::new(60, 120).unwrap();
    // 1500 % 1440 = 60  → in window
    assert!(q.contains(1500));
    // 1560 % 1440 = 120 → not in window (end is exclusive)
    assert!(!q.contains(1560));
    // 2940 % 1440 = 60  → in window
    assert!(q.contains(2940));
    // 2879 % 1440 = 59  → not in window
    assert!(!q.contains(2879));
}

#[test]
fn decide_own_message_is_none_even_if_mentioned_and_direct() {
    let s = Settings::new("alice");
    let msg = Incoming { room: "general", author: "alice", mentioned: true, direct: true };
    assert_eq!(s.decide(&msg, 0, 0), Notify::None);
}

#[test]
fn decide_nothing_level_is_none_even_if_mentioned_and_direct() {
    let mut s = Settings::new("alice");
    s.set_level("general", Level::Nothing);
    let msg = Incoming { room: "general", author: "bob", mentioned: true, direct: true };
    assert_eq!(s.decide(&msg, 0, 0), Notify::None);
}

#[test]
fn decide_mentions_level_requires_mention_or_direct() {
    let mut s = Settings::new("alice");
    s.set_level("general", Level::Mentions);

    let plain = Incoming { room: "general", author: "bob", mentioned: false, direct: false };
    assert_eq!(s.decide(&plain, 0, 0), Notify::None);

    let mentioned = Incoming { room: "general", author: "bob", mentioned: true, direct: false };
    assert_eq!(s.decide(&mentioned, 0, 0), Notify::Sound);

    let direct = Incoming { room: "general", author: "bob", mentioned: false, direct: true };
    assert_eq!(s.decide(&direct, 0, 0), Notify::Sound);
}

#[test]
fn decide_all_level_notifies_sound_by_default() {
    let s = Settings::new("alice");
    let msg = Incoming { room: "some_room", author: "bob", mentioned: false, direct: false };
    assert_eq!(s.decide(&msg, 0, 0), Notify::Sound);
}

#[test]
fn decide_dnd_makes_sound_become_silent() {
    let mut s = Settings::new("alice");
    s.set_dnd_until(1000);
    let msg = Incoming { room: "general", author: "bob", mentioned: true, direct: true };
    // now_ms = 500 < 1000 → DND active
    assert_eq!(s.decide(&msg, 500, 0), Notify::Silent);
    // now_ms = 0 < 1000 → DND active
    assert_eq!(s.decide(&msg, 0, 0), Notify::Silent);
    // now_ms = 1000, not < 1000 → DND inactive
    assert_eq!(s.decide(&msg, 1000, 0), Notify::Sound);
    // now_ms = 1001 → DND inactive
    assert_eq!(s.decide(&msg, 1001, 0), Notify::Sound);
}

#[test]
fn decide_dnd_until_zero_disables_dnd() {
    let mut s = Settings::new("alice");
    s.set_dnd_until(1000);
    s.set_dnd_until(0);
    let msg = Incoming { room: "general", author: "bob", mentioned: true, direct: true };
    assert_eq!(s.decide(&msg, 500, 0), Notify::Sound);
}

#[test]
fn decide_quiet_hours_make_sound_become_silent() {
    let mut s = Settings::new("alice");
    s.set_quiet(Some(Quiet::new(60, 120).unwrap()));
    let msg = Incoming { room: "general", author: "bob", mentioned: true, direct: true };
    assert_eq!(s.decide(&msg, 0, 90), Notify::Silent);
    assert_eq!(s.decide(&msg, 0, 60), Notify::Silent);
    assert_eq!(s.decide(&msg, 0, 119), Notify::Silent);
    assert_eq!(s.decide(&msg, 0, 59), Notify::Sound);
    assert_eq!(s.decide(&msg, 0, 120), Notify::Sound);
}

#[test]
fn decide_order_own_message_beats_dnd_and_quiet() {
    let mut s = Settings::new("alice");
    s.set_dnd_until(1000);
    s.set_quiet(Some(Quiet::new(0, 1439).unwrap()));
    let msg = Incoming { room: "general", author: "alice", mentioned: true, direct: true };
    assert_eq!(s.decide(&msg, 500, 720), Notify::None);
}

#[test]
fn decide_order_nothing_beats_dnd_and_quiet() {
    let mut s = Settings::new("alice");
    s.set_level("general", Level::Nothing);
    s.set_dnd_until(1000);
    s.set_quiet(Some(Quiet::new(0, 1439).unwrap()));
    let msg = Incoming { room: "general", author: "bob", mentioned: true, direct: true };
    assert_eq!(s.decide(&msg, 500, 720), Notify::None);
}

#[test]
fn level_default_is_all_for_unset_rooms() {
    let s = Settings::new("alice");
    assert_eq!(s.level("never_configured"), Level::All);
    assert_eq!(s.level("another_room"), Level::All);
}

#[test]
fn set_level_overwrites_and_round_trips() {
    let mut s = Settings::new("alice");
    s.set_level("general", Level::Mentions);
    assert_eq!(s.level("general"), Level::Mentions);
    s.set_level("general", Level::Nothing);
    assert_eq!(s.level("general"), Level::Nothing);
    s.set_level("general", Level::All);
    assert_eq!(s.level("general"), Level::All);
}
