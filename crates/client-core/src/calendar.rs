//! The calendar's week (docs/MEETINGS.md "Calendar queries", task T370a): a client's local work week as the UTC window
//! `Request::MeetingList` asks for. The server keeps times in UTC and has no time zone database, so the client, which
//! knows its own zone, makes the window. The calendar math is chrono's (Craft time standard).
//!
//! Owns: `work_week`. Called by: the apps' calendar views.

use chrono::{Datelike, Days, NaiveDate};

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
