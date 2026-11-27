# Accessibility readiness

What the CrewCraft apps do today for people who use a screen reader or braille display, a magnifier, high contrast,
large text, voice control or only a keyboard, and what is known not to work yet. It follows the "Progress" section of
the Craft accessibility standard,
[`standards/accessibility.md`](https://github.com/storytold/craft-contrib/blob/main/standards/accessibility.md): an
app's progress docs say whether its core tasks can be done with a screen reader, with only a keyboard, at 200% text
size and in high contrast.

This is an engineering record, read from the code and tests at the time of writing (2026-11-27). It is not a
user-facing accessibility statement: the Craft suite is discussing a shared one (craft-contrib RFC-0086, open), and
CrewCraft will take it when it lands. Nothing here has been tested with a screen reader, a magnifier or voice control
yet. A tree test is not that test, so this file never says "works with screen readers".

Update this file in the pull request that changes what it describes.

## How the apps reach assistive technology

- The desktop app is egui, built with eframe's `accesskit` feature (`apps/crewcraft/Cargo.toml`). AccessKit publishes
  the window's controls to UI Automation on Windows, NSAccessibility on macOS and AT-SPI on Linux. On Linux that goes
  through `accesskit_unix` and zbus (`deny.toml` explains three accepted advisories on that path).
- The phone apps (`apps/crewcraft-android`, the iOS build of `apps/crewcraft`) draw the same egui window in a phone
  layout. Whether their platform screen readers (TalkBack, VoiceOver) receive that tree has not been checked.
- The web client is not built yet.

## Readiness by core task

"Tested" means a kittest test drives the task through the accessibility tree. "Expected" means the controls are
standard egui widgets that should work this way, with no test that proves it. "Not verified" means nobody has looked.

| Core task | Screen reader | Keyboard only | 200% text | High contrast |
|---|---|---|---|---|
| Join from an invitation link, set up the authenticator | Fields are named from their labels (tested for the invitation link field: `t611k_enroll_way`); the read-only authenticator entry is named "Authenticator entry" and its value is the entry (tested: `t406_keyboard_route`) | Tab goes invitation link, new password, Enroll this device, and Shift+Tab goes back; Enter on the focused button enrolls, and so does Enter in the password field. On the authenticator screen Tab goes entry, Copy entry, code; Enter in the code field confirms once it is a code, and until then focus stays in the field (tested by keyboard: `t406_keyboard_route`). The way in through the organization's page is reachable by Tab but not tested by keyboard | Not verified | Built-in high-contrast theme; the system setting is not followed |
| Sign in | Named (tested: `t305_desktop_window`, `t611h_signin_button`) | Tab goes email, password, code, Sign in; Enter on Sign in signs in, and so does Enter in any of the three fields once all are filled (tested by keyboard: `t406_keyboard_route`). Sign in with your organization is not tested by keyboard | Not verified | As above |
| Choose a room, read messages | Room buttons are named (tested); messages are text rows; image previews are images named by their file name (tested: `a11y_image_names`); a new message in another room is announced through a live region (tested: `a11y_announcements`); a new message in the open room is not announced yet | Tab reaches every room button and Enter opens the room (tested by keyboard: `t406_keyboard_route`); after an unread action is confirmed, focus returns to the room button (tested: `t344_mark_unread_window`). Messages themselves are not tested by Tab | Not verified | As above |
| Send a message | The message box is named "Message" (tested) | Tab reaches the message box from the room list; Enter sends and focus stays in the box (tested by keyboard: `t406_keyboard_route`); Shift+Enter adds a line (tested: `t305_desktop_window`) | Not verified | As above |
| Search, open a result | The search box is named (tested) | Enter searches; opening a result moves the window's focus to the message (tested: `t321_search_focus_window`). Whether that also moves egui's keyboard focus there is not verified | Not verified | As above |
| Threads, reactions, edit and delete, pins | Controls are named (tested in their window tests) | Expected; not tested | Not verified | As above |
| Calendar: schedule, edit, cancel, join a meeting | Buttons are named with the meeting's title ("Join Weekly review"); the form's fields are named from their labels; a cancelled meeting says "(cancelled)" in its title, not by colour (tested: `t370b_calendar_window`); a refused save is also announced through the status line | The form opens with focus in its title; Tab goes title, start, length, agenda, Save, Discard changes, and Enter in a one-line field saves (tested by keyboard: `t370b2_calendar_keyboard`). Esc closes the form unsaved; the Cancel confirmation opens with focus on Keep the meeting, and Esc keeps the meeting. When the form or the confirmation closes, by Esc or its own button, focus goes back to the Edit, Schedule a meeting or Cancel button that opened it. Esc with nothing open inside the Calendar, or Close calendar, closes it and focus goes back to the Calendar button (tested by keyboard: `t406_keyboard_route`) | Not verified | As above |
| Calendar guest lobby | Guest controls name their actions and relevant visitor or meeting. A waiting-count increase is announced through the polite status region (tested by `t370d_guest_lobby_window`). | Native controls take keyboard focus. Waiting notices leave focus where it is. The lobby opens with focus on Back to calendar; Esc leaves it and focus goes back to its Lobby button. Its confirmations (direct entry, closing the link, removing a guest) open with focus on the answer that changes nothing; Esc or that answer dismisses them and focus goes back to the control that asked (tested by keyboard: `t406_keyboard_route`). After a confirmed change, focus is not placed anywhere | Not verified | As above |
| Attach a file | The Attach file button and the path entry are named from their labels (tested) | Attach file opens a path entry that takes focus; Enter attaches, Esc closes, and focus returns to the button (tested by keyboard: `a11y_attach_keyboard`). There is no file browser: the full path is typed or pasted | Not verified | As above |

## What the apps do today

- **Names.** Text fields are labelled through `labelled_by`, so their accessible name is their visible label
  (`crates/desktop-ui/src/lib.rs`). Buttons carry their text as their name. Image previews carry their file name. The window tests find controls by these
  names through the AccessKit tree: `get_by_label` and `query_by_label`, about 280 uses across `crates/desktop-ui/tests`
  and `apps/crewcraft/tests`.
- **Real focus.** Where the window moves focus on purpose, it uses egui's `request_focus`, not only a highlight.
  Examples: returning to the room button after a confirmed unread action (T344), and returning to the control that
  opened the Calendar's form, a confirmation, the guest lobby or the attach path entry when it closes (T406).
- **A new screen starts with nothing focused.** Going from joining to the authenticator, to sign-in and to the chat
  clears focus, so the first Tab reaches the new screen's first control rather than whatever shares an old control's
  id. Focus is not put into a text field on its own: on a phone that would raise the on-screen keyboard unasked.
- **Contrast.** Every theme, built-in or an installed addon, must pass WCAG 2.2 AA contrast before it is used: 4.5:1
  for text and 3:1 for controls and the focus ring, on each background it is drawn on (`crates/theme/src/lib.rs`, the
  contrast rule table; REQUIREMENTS 2.19). A theme that fails is refused and the default applies (`t314_themes`).
- **Themes.** Light, dark, follow the system's light or dark choice, and a built-in high-contrast theme
  (`crewcraft-high-contrast`).
- **Announcements.** Changes away from focus go to the status line, a polite AccessKit live region: new messages in
  another room, a call someone starts, the connection lost and back, and errors and hints.
- **Colour is not the only signal for presence.** The contrast rules exempt presence colours because presence is also
  shown by the icon's shape (`crates/theme/src/lib.rs`).

## Known gaps

Each gap names the standard's rule it falls under. The "Known failures" items of the standard are marked (KF).

1. **Partly closed: live-region announcements** (rule 4, KF "a state change nobody hears"). The status line at the
   top of the window is a polite live region: a new message in another room, a call someone starts, a lost
   connection, the connection coming back and every error or hint shown there are announced without moving focus
   (`a11y_announcements` reads the tree and checks focus stays put). Still not announced: a new message in the open
   room, a finished upload, a search result count and "sent".
2. **Closed: drag-only file attachment** (rule 7, KF "an action that only works by dragging"). The composer has an
   Attach file button that opens a path entry; Enter attaches the file through the same command a dropped file uses.
   What remains: there is no file browser, so the person types or pastes the file's full path. A browser drawn in
   egui would need the window to list folders, which it does not do today (it touches no disk).
3. **Closed: image previews are named** (rule 5). The previews under messages (T333) are image nodes whose name is
   their file name, read back from the tree in `a11y_image_names`. The name is the file name only: CrewCraft has no
   way yet for the sender to write a description of the picture.
4. **System settings are not followed** (rule 6). The app follows the system's light or dark choice, but not its high
   contrast mode, text size or reduced motion setting. High contrast is a theme the person chooses. Text sizes come
   from the theme, and the app sets no zoom.
5. **No keyboard shortcuts or shortcuts dialog** (rule 1; REQUIREMENTS 2.20 asks for both). There is also no F6 movement
   between the room list, the conversation and the side pane.
6. **Partly closed: Esc** (rule 1). Esc closes the attach path entry (`a11y_attach_keyboard`) and, in the Calendar,
   the guest lobby's confirmations, the lobby, the meeting form, the Cancel confirmation and the area itself, innermost
   first, with focus back on the control that opened what closed (`t406_keyboard_route`). Still not handled: the
   message's Delete confirmation, the thread pane, Files, Saved, Activity and search results do not close on Esc, and
   where focus goes when they close is not checked.
7. **Partly closed: keyboard paths in tests** (Checks). Driven by keyboard only in tests: joining, the authenticator,
   sign-in, opening a room and sending (`t406_keyboard_route`), the calendar form (`t370b2_calendar_keyboard`) and its
   panels and the guest lobby (`t406_keyboard_route`), attaching a file (`a11y_attach_keyboard`), focus after an
   unread action and the search focus. Still untested: threads, reactions, edit and delete, pins, Files, Saved,
   Activity and search results by Tab; the organization sign-in buttons; the phone layout; and focus visibility in
   both themes.
8. **The keyboard focus indicator is not checked as such** (rule 2). The theme's `focus-ring` colour passes 3:1, but it
   is drawn as the pressed-state outline. Whether egui's keyboard focus outline uses a checked colour in every theme
   has not been verified.
9. **No check of what the platform reports** (Checks). Nothing reads the running app through UI Automation, AT-SPI or
   NSAccessibility. The Craft suite runs such checks in its hosted CI, which CrewCraft does not use.
10. **Not checked on phones or with real assistive technology.** No TalkBack, VoiceOver, NVDA, Narrator or Orca run
    has been recorded: what a native screen reader says is not yet observed on a real desktop.
11. **A new screen is not announced** (rule 4). After joining, signing in or signing out, focus is on nothing until the
    person presses Tab, so a screen reader is not told the screen changed. Moving focus into the first field would
    say it, but on a phone it would also raise the on-screen keyboard unasked (`t421_ios_window` keeps that off), so
    an announcement through the live region is the likely fix.

## Next steps, in order

1. Done: a button that attaches a file without dragging (gap 2). A file browser drawn in egui could follow.
2. Done: names for image previews, from the file name (gap 3).
3. Announce new messages in the open room, sent messages, upload results and search result counts through the
   status line's live region (the rest of gap 1).
4. Partly done: keyboard tests for join, sign-in, send and the Calendar's panels, with Esc there (T406). Still to do:
   F6, Esc with focus return for the other panes (gaps 5 to 7), and announcing a new screen (gap 11).
5. Follow the system's high contrast and text size settings (gap 4).
6. A first manual pass with NVDA on Windows and Orca on Linux over the core tasks, recorded in this file (gap 10).
