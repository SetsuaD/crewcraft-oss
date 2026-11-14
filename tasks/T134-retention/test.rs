#![allow(clippy::unwrap_used)]

use crewcraft_server_core::retention::{DAY_MS, Msg, Policy, removed_by, to_remove};

#[test]
fn forever_removes_nothing() {
    let msgs = vec![
        Msg { cursor: 1, posted_ms: 0, pinned: false },
        Msg { cursor: 2, posted_ms: 1_000, pinned: false },
        Msg { cursor: 3, posted_ms: 2_000, pinned: true },
    ];
    assert_eq!(removed_by(Policy::Forever, &msgs, 999_999_999), Vec::<u64>::new());
}

#[test]
fn max_age_days_exact_boundary_includes_equal() {
    // days = 2 → threshold = 2 * DAY_MS = 172_800_000
    let now: u64 = 172_800_000;
    let msgs = vec![
        // 0 + 172_800_000 = 172_800_000 <= 172_800_000  → removed
        Msg { cursor: 1, posted_ms: 0, pinned: false },
        // 1 + 172_800_000 = 172_800_001 >  172_800_000  → kept
        Msg { cursor: 2, posted_ms: 1, pinned: false },
    ];
    assert_eq!(removed_by(Policy::MaxAgeDays(2), &msgs, now), vec![1]);
}

#[test]
fn max_age_days_one_ms_below_boundary_keeps_message() {
    let now: u64 = 172_799_999; // one ms before the threshold
    let msgs = vec![
        // 0 + 172_800_000 = 172_800_000 > 172_799_999  → kept
        Msg { cursor: 1, posted_ms: 0, pinned: false },
    ];
    assert_eq!(removed_by(Policy::MaxAgeDays(2), &msgs, now), Vec::<u64>::new());
}

#[test]
fn max_age_days_zero_removes_everything_at_or_before_now() {
    let now: u64 = 500;
    let msgs = vec![
        Msg { cursor: 1, posted_ms: 0, pinned: false },
        Msg { cursor: 2, posted_ms: 500, pinned: false }, // exactly at now
    ];
    assert_eq!(removed_by(Policy::MaxAgeDays(0), &msgs, now), vec![1, 2]);
}

#[test]
fn max_count_keeps_highest_cursors() {
    let msgs = vec![
        Msg { cursor: 5, posted_ms: 0, pinned: false },
        Msg { cursor: 10, posted_ms: 0, pinned: false },
        Msg { cursor: 3, posted_ms: 0, pinned: false },
        Msg { cursor: 8, posted_ms: 0, pinned: false },
        Msg { cursor: 1, posted_ms: 0, pinned: false },
    ];
    // MaxCount(2): keep cursors 10 and 8; remove 1, 3, 5
    assert_eq!(removed_by(Policy::MaxCount(2), &msgs, 0), vec![1, 3, 5]);
}

#[test]
fn max_count_zero_removes_all_non_pinned() {
    let msgs = vec![
        Msg { cursor: 5, posted_ms: 0, pinned: false },
        Msg { cursor: 10, posted_ms: 0, pinned: true },
        Msg { cursor: 3, posted_ms: 0, pinned: false },
    ];
    // MaxCount(0): remove every non-pinned message; pinned 10 stays
    assert_eq!(removed_by(Policy::MaxCount(0), &msgs, 0), vec![3, 5]);
}

#[test]
fn pinned_never_removed_and_excluded_from_max_count() {
    // MaxCount: pinned cursor is not counted toward the "newest N"
    let msgs = vec![
        Msg { cursor: 1, posted_ms: 0, pinned: true },
        Msg { cursor: 5, posted_ms: 0, pinned: false },
        Msg { cursor: 10, posted_ms: 0, pinned: false },
    ];
    // Non-pinned = {5, 10}; keep top 1 → {10}; remove {5}; pinned {1} untouched
    assert_eq!(removed_by(Policy::MaxCount(1), &msgs, 0), vec![5]);

    // MaxAgeDays: pinned message would satisfy the age check but is still skipped
    let msgs2 = vec![Msg { cursor: 1, posted_ms: 0, pinned: true }, Msg { cursor: 2, posted_ms: 0, pinned: false }];
    // 0 + DAY_MS = DAY_MS <= DAY_MS → age condition met, but pinned → not removed
    assert_eq!(removed_by(Policy::MaxAgeDays(1), &msgs2, DAY_MS), vec![2]);
}

#[test]
fn removed_by_ascending_order_independent_of_input_order() {
    let input_a = vec![
        Msg { cursor: 10, posted_ms: 0, pinned: false },
        Msg { cursor: 3, posted_ms: 0, pinned: false },
        Msg { cursor: 7, posted_ms: 0, pinned: false },
    ];
    let input_b = vec![
        Msg { cursor: 7, posted_ms: 0, pinned: false },
        Msg { cursor: 10, posted_ms: 0, pinned: false },
        Msg { cursor: 3, posted_ms: 0, pinned: false },
    ];
    let expected = vec![3u64, 7u64];
    assert_eq!(removed_by(Policy::MaxCount(1), &input_a, 0), expected);
    assert_eq!(removed_by(Policy::MaxCount(1), &input_b, 0), expected);
}

#[test]
fn to_remove_unions_server_and_room_policies() {
    let now: u64 = 100_000_000;
    let msgs = vec![
        // Server MaxAgeDays(1): 0 + 86_400_000 = 86_400_000 <= 100_000_000 → removed
        // Room  MaxCount(1):  non-pinned {1,2,3}, keep 3 → removed
        Msg { cursor: 1, posted_ms: 0, pinned: false },
        // Server MaxAgeDays(1): 50_000_000 + 86_400_000 = 136_400_000 > 100_000_000 → kept
        // Room  MaxCount(1):  removed (not the top cursor)
        Msg { cursor: 2, posted_ms: 50_000_000, pinned: false },
        // Server: kept; Room: kept (highest cursor)
        Msg { cursor: 3, posted_ms: 90_000_000, pinned: false },
    ];
    // Server removes {1}; Room removes {1, 2}; union = {1, 2}
    assert_eq!(to_remove(Policy::MaxAgeDays(1), Some(Policy::MaxCount(1)), false, &msgs, now), vec![1, 2],);
}

#[test]
fn to_remove_legal_hold_stops_all_removal() {
    let msgs = vec![Msg { cursor: 1, posted_ms: 0, pinned: false }, Msg { cursor: 2, posted_ms: 0, pinned: false }];
    assert_eq!(to_remove(Policy::MaxAgeDays(0), Some(Policy::MaxCount(0)), true, &msgs, 1_000), Vec::<u64>::new(),);
}

#[test]
fn to_remove_room_none_applies_server_policy_only() {
    let msgs = vec![
        Msg { cursor: 1, posted_ms: 0, pinned: false },
        Msg { cursor: 2, posted_ms: 0, pinned: false },
        Msg { cursor: 3, posted_ms: 0, pinned: false },
    ];
    // MaxCount(1): keep cursor 3; remove 1 and 2
    assert_eq!(to_remove(Policy::MaxCount(1), None, false, &msgs, 0), vec![1, 2],);
}

#[test]
fn to_remove_union_has_no_duplicates() {
    let msgs = vec![Msg { cursor: 1, posted_ms: 0, pinned: false }, Msg { cursor: 2, posted_ms: 0, pinned: false }];
    // Server MaxAgeDays(0): 0 <= 1000 → removes both
    // Room  MaxCount(0):  removes both non-pinned
    // Union must list each cursor exactly once
    assert_eq!(to_remove(Policy::MaxAgeDays(0), Some(Policy::MaxCount(0)), false, &msgs, 1_000), vec![1, 2],);
}
