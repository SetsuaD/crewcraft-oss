//! The calendar's week (docs/MEETINGS.md "Calendar queries", task T370a): a client's local work week as the UTC window
//! `Request::MeetingList` asks for. The server keeps times in UTC and has no time zone database, so the client, which
//! knows its own zone, makes the window. The calendar math is chrono's (Craft time standard).
//!
//! Owns: `work_week`, `work_week_at`. Called by: the apps' calendar views.

use chrono::{DateTime, Datelike, Days, NaiveDate};

/// The UTC window, in Unix milliseconds, of the work week that holds `day`: from Monday 00:00 to Saturday 00:00 local
/// time, where local time is UTC plus `utc_offset_minutes` (east positive). `None` when the week falls outside the
/// Unix-millisecond range. Within `proto::meeting::MAX_WINDOW_MS`. A daylight-saving change during the week moves the
/// end by the change; a client that cares asks with the offset at each end and joins the results.
pub fn work_week(day: NaiveDate, utc_offset_minutes: i32) -> Option<(u64, u64)> {
    let monday = day.checked_sub_days(Days::new(u64::from(day.weekday().num_days_from_monday())))?;
    let saturday = monday.checked_add_days(Days::new(5))?;
    let utc_ms = |date: NaiveDate| -> Option<u64> {
        let local_ms = date.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis();
        u64::try_from(local_ms.checked_sub(i64::from(utc_offset_minutes).checked_mul(60_000)?)?).ok()
    };
    Some((utc_ms(monday)?, utc_ms(saturday)?))
}

/// The UTC window of the work week `weeks` after (or, negative, before) the one that holds the instant `now_ms`, local
/// time being UTC plus `utc_offset_minutes`, as `work_week` makes it (task T370b: the calendar's previous and next week).
/// `None` outside chrono's or the Unix-millisecond range.
pub fn work_week_at(now_ms: u64, utc_offset_minutes: i32, weeks: i64) -> Option<(u64, u64)> {
    let local_ms = i64::try_from(now_ms).ok()?.checked_add(i64::from(utc_offset_minutes).checked_mul(60_000)?)?;
    let today = DateTime::from_timestamp_millis(local_ms)?.date_naive();
    let days = weeks.checked_mul(7)?;
    let day = if days >= 0 {
        today.checked_add_days(Days::new(days.unsigned_abs()))?
    } else {
        today.checked_sub_days(Days::new(days.unsigned_abs()))?
    };
    work_week(day, utc_offset_minutes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_week_at_an_instant_holds_it_and_its_neighbours_follow_on() {
        // 2026-11-26 (a Thursday) 12:00 UTC.
        let now = 1_795_694_400_000;
        let (from, to) = work_week_at(now, 0, 0).unwrap_or_default();
        assert!(from <= now && now < to);
        let (next_from, _) = work_week_at(now, 0, 1).unwrap_or_default();
        let (_, last_to) = work_week_at(now, 0, -1).unwrap_or_default();
        assert_eq!(next_from - from, 7 * 24 * 60 * 60 * 1000);
        assert!(last_to <= from);
        // Sunday 22:30 UTC is already Monday two hours east of UTC: the next local week.
        let sunday_late = 1_795_991_400_000;
        assert_eq!(work_week_at(sunday_late, 120, 0), work_week_at(now, 120, 1));
        assert_ne!(work_week_at(sunday_late, 0, 0), work_week_at(now, 0, 1));
    }
}
