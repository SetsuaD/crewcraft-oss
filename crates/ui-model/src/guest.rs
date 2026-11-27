//! Staff calendar commands and confirmed server updates for the guest lobby (T370d).

pub use crewcraft_client_core::guest::{GuestCode, GuestDecision, GuestEntry, GuestLobby, GuestMeetingChange, GuestMeetingDraft, GuestState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestCommand {
    Open { room: String, meeting: u64 },
    ClosePanel,
    Create(GuestMeetingDraft),
    SetLobby { meeting: u64, revision: u64, lobby: bool, confirm_direct: bool },
    Decide { meeting: u64, guest: u64, revision: u64, decision: GuestDecision },
    CloseLink { meeting: u64, revision: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestUpdate {
    /// Availability for this session. False clears the lobby and waiting counts.
    Available(bool),
    /// The fresh count for one room. Notify only for a new observed increase.
    Waiting { room: String, waiting: u32, notify: bool },
    ClearRoom { room: String },
    /// A confirmed roster. Only creating a meeting can return a code, whose Debug output is redacted.
    Snapshot { room: String, lobby: GuestLobby, code: Option<GuestCode> },
    Refused { meeting: Option<u64>, reason: String, conflict: bool, access_lost: bool },
}
