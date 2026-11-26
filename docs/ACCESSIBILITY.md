# Accessibility readiness

What the CrewCraft apps do today for people who use a screen reader or braille display, a magnifier, high contrast,
large text, voice control or only a keyboard, and what is known not to work yet. It follows the "Progress" section of
the Craft accessibility standard,
[`standards/accessibility.md`](https://github.com/storytold/craft-contrib/blob/main/standards/accessibility.md): an
app's progress docs say whether its core tasks can be done with a screen reader, with only a keyboard, at 200% text
size and in high contrast.

This is an engineering record, read from the code and tests at the time of writing (2026-11-26). It is not a
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
| Join from an invitation link, set up the authenticator | Fields are named from their labels (tested for the invitation link field: `t611k_enroll_way`) | Expected (Tab between fields, Enter on buttons); not tested | Not verified | Built-in high-contrast theme; the system setting is not followed |
| Sign in | Named (tested: `t305_desktop_window`, `t611h_signin_button`) | Expected; not tested | Not verified | As above |
| Choose a room, read messages | Room buttons are named (tested); messages are text rows; no announcement when a new message arrives | Room buttons take focus; after an unread action is confirmed, focus returns to the room button (tested: `t344_mark_unread_window`) | Not verified | As above |
| Send a message | The message box is named "Message" (tested) | Enter sends, Shift+Enter adds a line (tested: `t305_desktop_window`) | Not verified | As above |
| Search, open a result | The search box is named (tested) | Enter searches; opening a result moves the window's focus to the message (tested: `t321_search_focus_window`). Whether that also moves egui's keyboard focus there is not verified | Not verified | As above |
| Threads, reactions, edit and delete, pins | Controls are named (tested in their window tests) | Expected; not tested | Not verified | As above |
| Attach a file | — | **Not possible**: files are attached only by dropping them onto the window | Not verified | As above |

## What the apps do today

- **Names.** Text fields are labelled through `labelled_by`, so their accessible name is their visible label
  (`crates/desktop-ui/src/lib.rs`). Buttons carry their text as their name. The window tests find controls by these
  names through the AccessKit tree: `get_by_label` and `query_by_label`, about 280 uses across `crates/desktop-ui/tests`
  and `apps/crewcraft/tests`.
- **Real focus.** Where the window moves focus on purpose, it uses egui's `request_focus`, not only a highlight.
  An example is returning to the room button after a confirmed unread action (T344).
- **Contrast.** Every theme, built-in or an installed addon, must pass WCAG 2.2 AA contrast before it is used: 4.5:1
  for text and 3:1 for controls and the focus ring, on each background it is drawn on (`crates/theme/src/lib.rs`, the
  contrast rule table; REQUIREMENTS 2.19). A theme that fails is refused and the default applies (`t314_themes`).
- **Themes.** Light, dark, follow the system's light or dark choice, and a built-in high-contrast theme
  (`crewcraft-high-contrast`).
- **Colour is not the only signal for presence.** The contrast rules exempt presence colours because presence is also
  shown by the icon's shape (`crates/theme/src/lib.rs`).

## Known gaps

Each gap names the standard's rule it falls under. The "Known failures" items of the standard are marked (KF).

1. **No live-region announcements** (rule 4, KF "a state change nobody hears"). Nothing is announced away from focus:
   a new message, a finished upload, a search result count, an error, "sent".
2. **Drag-only file attachment** (rule 7, KF "an action that only works by dragging"). The composer says "Drop a file
   onto the window to attach it", and there is no button or file chooser.
3. **Image previews have no name** (rule 5). The previews under messages (T333) are drawn as `egui::Image` with no
   alternative text, so a screen reader meets an unnamed image. The file name is available and could be its name.
4. **System settings are not followed** (rule 6). The app follows the system's light or dark choice, but not its high
   contrast mode, text size or reduced motion setting. High contrast is a theme the person chooses. Text sizes come
   from the theme, and the app sets no zoom.
5. **No keyboard shortcuts or shortcuts dialog** (rule 1; REQUIREMENTS 2.20 asks for both). There is also no F6 movement
   between the room list, the conversation and the side pane.
6. **Esc is not handled by CrewCraft** (rule 1). `crates/desktop-ui` handles no Esc key. egui's own popups may close on
   Esc, but CrewCraft's confirmations and panes do not, and where focus goes after Esc has not been checked.
7. **Keyboard paths are mostly untested** (Checks). Only Enter-to-send, focus after an unread action and the search
   focus are driven by keyboard in tests. Tab order, focus visibility in both themes and focus after closing a pane
   have no test.
8. **The keyboard focus indicator is not checked as such** (rule 2). The theme's `focus-ring` colour passes 3:1, but it
   is drawn as the pressed-state outline. Whether egui's keyboard focus outline uses a checked colour in every theme
   has not been verified.
9. **No check of what the platform reports** (Checks). Nothing reads the running app through UI Automation, AT-SPI or
   NSAccessibility. The Craft suite runs such checks in its hosted CI, which CrewCraft does not use.
10. **Not checked on phones or with real assistive technology.** No TalkBack, VoiceOver, NVDA, Narrator or Orca run
    has been recorded.

## Next steps, in order

1. A button or file chooser that attaches a file without dragging (gap 2).
2. Names for image previews, from the file name (gap 3).
3. A live region for new messages in the open room, sent messages, upload results and errors (gap 1).
4. Esc and F6 behaviour, with kittest keyboard tests for join, sign-in, send and closing a pane (gaps 5 to 7).
5. Follow the system's high contrast and text size settings (gap 4).
6. A first manual pass with NVDA on Windows and Orca on Linux over the core tasks, recorded in this file (gap 10).
