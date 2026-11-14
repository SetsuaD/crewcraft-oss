//! Whether a new message notifies the user, and how loudly. The clock and the local time of day are passed in. Task
//! T126.

use std::collections::HashMap;

/// What a room notifies for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Every message (the default for a room never set).
    All,
    /// Only messages that mention the user, and direct messages.
    Mentions,
    /// Nothing at all, not even direct messages.
    Nothing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notify {
    Sound,
    /// Shown in the notification list without sound or banner.
    Silent,
    None,
}

/// Quiet hours: minutes after local midnight, from `start` (inclusive) to `end` (exclusive). When `start > end` the window
/// runs past midnight (for example 22:00 to 07:00); when `start == end` there are no quiet hours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quiet {
    start: u16,
    end: u16,
}

impl Quiet {
    /// `None` if either value is 1440 or more.
    pub fn new(start: u16, end: u16) -> Option<Self> {
        if start >= 1440 || end >= 1440 {
            return None;
        }
        Some(Quiet { start, end })
    }

    /// Whether `minute` (taken modulo 1440) falls in the window.
    pub fn contains(&self, minute: u16) -> bool {
        let m = minute % 1440;
        if self.start == self.end {
            return false;
        }
        if self.start < self.end { m >= self.start && m < self.end } else { m >= self.start || m < self.end }
    }
}

/// One incoming message, as the client sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incoming<'a> {
    pub room: &'a str,
    pub author: &'a str,
    /// The message mentions the user (the server's `mentions` list contains them).
    pub mentioned: bool,
    /// The room is a direct conversation.
    pub direct: bool,
}

#[derive(Debug, Default)]
pub struct Settings {
    me: String,
    levels: HashMap<String, Level>,
    quiet: Option<Quiet>,
    dnd_until: u64,
}

impl Settings {
    /// Settings for `me`: every room `All`, no quiet hours, no do-not-disturb.
    pub fn new(me: &str) -> Self {
        Self { me: me.to_owned(), levels: HashMap::new(), quiet: None, dnd_until: 0 }
    }

    pub fn set_level(&mut self, room: &str, level: Level) {
        self.levels.insert(room.to_owned(), level);
    }

    pub fn level(&self, room: &str) -> Level {
        self.levels.get(room).copied().unwrap_or(Level::All)
    }

    pub fn set_quiet(&mut self, quiet: Option<Quiet>) {
        self.quiet = quiet;
    }

    /// Do not disturb while `now_ms < until_ms`; 0 turns it off.
    pub fn set_dnd_until(&mut self, until_ms: u64) {
        self.dnd_until = until_ms;
    }

    /// Decide, in order: a message by `me` is `None`; a room at `Nothing` is `None`; a room at `Mentions` is `None` unless
    /// the message mentions me or is direct. Anything left notifies: `Silent` during do-not-disturb or quiet hours
    /// (`local_minute` is minutes after local midnight), else `Sound`.
    pub fn decide(&self, msg: &Incoming<'_>, now_ms: u64, local_minute: u16) -> Notify {
        if msg.author == self.me {
            return Notify::None;
        }
        let level = self.level(msg.room);
        match level {
            Level::Nothing => return Notify::None,
            Level::Mentions => {
                if !msg.mentioned && !msg.direct {
                    return Notify::None;
                }
            }
            Level::All => {}
        }
        if self.dnd_until > 0 && now_ms < self.dnd_until {
            return Notify::Silent;
        }
        if let Some(quiet) = &self.quiet
            && quiet.contains(local_minute)
        {
            return Notify::Silent;
        }
        Notify::Sound
    }
}
