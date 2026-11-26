//! T316: the composer's edit submission: `Command::Edit` for the message being edited, with the same trimming and
//! refusals as a new message, and only that room's draft cleared.
#![allow(clippy::unwrap_used)]

use crewcraft_ui_model::composer::Composer;
use crewcraft_ui_model::{Command, DraftError, MAX_DRAFT_CHARS};

#[test]
fn an_edit_is_checked_like_a_post_and_names_its_message() {
    let mut composer = Composer::new();
    composer.set("general", "  fixed text \n");
    composer.set("design", "kept");
    assert_eq!(composer.submit_edit("general", 42).unwrap(), Command::Edit { room: "general".into(), target: 42, text: "fixed text".into() });
    assert_eq!(composer.draft("general"), "", "the edited room's draft is cleared");
    assert_eq!(composer.draft("design"), "kept");

    composer.set("general", "   ");
    assert_eq!(composer.submit_edit("general", 42), Err(DraftError::Empty));
    assert_eq!(composer.draft("general"), "   ", "a refusal keeps the draft");
    let long = "x".repeat(MAX_DRAFT_CHARS + 1);
    composer.set("general", &long);
    assert_eq!(composer.submit_edit("general", 42), Err(DraftError::TooLong));
    composer.set("general", &"x".repeat(MAX_DRAFT_CHARS));
    assert!(matches!(composer.submit_edit("general", 42), Ok(Command::Edit { target: 42, .. })));
    // A plain submit still posts.
    composer.set("general", "new");
    assert_eq!(composer.submit("general").unwrap(), Command::Post { room: "general".into(), text: "new".into() });
}
