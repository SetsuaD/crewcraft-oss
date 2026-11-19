use crewcraft_ui_model::composer::Composer;
use crewcraft_ui_model::{Command, DraftError, MAX_DRAFT_CHARS};

fn post(room: &str, text: &str) -> Result<Command, DraftError> {
    Ok(Command::Post { room: room.to_string(), text: text.to_string() })
}

#[test]
fn keeps_one_draft_per_room() {
    let mut composer = Composer::new();
    assert_eq!(composer.draft("ops"), "");
    composer.set("ops", "  half a thought");
    composer.set("design", "other room");
    assert_eq!(composer.draft("ops"), "  half a thought", "set stores the text exactly as typed");
    assert_eq!(composer.draft("design"), "other room");
    composer.set("ops", "");
    assert_eq!(composer.draft("ops"), "");
    assert_eq!(composer.draft("design"), "other room");
}

#[test]
fn submit_trims_the_ends_keeps_inner_whitespace_and_clears_only_that_room() {
    let mut composer = Composer::new();
    composer.set("ops", " \n hello\n\n  world  \t\n");
    composer.set("design", "keep me");
    assert_eq!(composer.submit("ops"), post("ops", "hello\n\n  world"));
    assert_eq!(composer.draft("ops"), "");
    assert_eq!(composer.draft("design"), "keep me");
}

#[test]
fn refuses_blank_drafts_and_keeps_them() {
    let mut composer = Composer::new();
    assert_eq!(composer.submit("ops"), Err(DraftError::Empty), "no draft at all");
    composer.set("ops", " \n\t ");
    assert_eq!(composer.submit("ops"), Err(DraftError::Empty));
    assert_eq!(composer.draft("ops"), " \n\t ");
}

#[test]
fn length_is_counted_in_characters_after_trimming() {
    let mut composer = Composer::new();
    // Each 'é' is two bytes but one character; the surrounding spaces do not count.
    let at_limit = "é".repeat(MAX_DRAFT_CHARS);
    composer.set("ops", &format!("  {at_limit}  "));
    assert_eq!(composer.submit("ops"), post("ops", &at_limit));

    let over = "é".repeat(MAX_DRAFT_CHARS + 1);
    composer.set("ops", &over);
    assert_eq!(composer.submit("ops"), Err(DraftError::TooLong));
    assert_eq!(composer.draft("ops"), over, "a refused draft is kept");
}
