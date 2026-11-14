#![allow(clippy::unwrap_used)]

use crewcraft_server_core::html_text::html_text;
use crewcraft_server_core::render::render;

#[test]
fn br_becomes_newline() {
    assert_eq!(html_text("<br>"), "\n");
    assert_eq!(html_text("a<br>b<br>c"), "a\nb\nc");
}

#[test]
fn other_tags_are_removed() {
    assert_eq!(html_text("<strong>bold</strong>"), "bold");
    assert_eq!(html_text("<code>x</code>"), "x");
    assert_eq!(html_text("<em>it</em>"), "it");
}

#[test]
fn all_five_escapes_unescaped() {
    assert_eq!(html_text("&amp;"), "&");
    assert_eq!(html_text("&lt;"), "<");
    assert_eq!(html_text("&gt;"), ">");
    assert_eq!(html_text("&quot;"), "\"");
    assert_eq!(html_text("&#39;"), "'");
}

#[test]
fn unknown_ampersand_kept() {
    assert_eq!(html_text("&foo;"), "&foo;");
    assert_eq!(html_text("a & b"), "a & b");
}

#[test]
fn lt_without_following_gt_kept() {
    assert_eq!(html_text("a < b"), "a < b");
    assert_eq!(html_text("< 10"), "< 10");
}

#[test]
fn escaped_angle_brackets_do_not_form_tags() {
    // Tag-removal sees no literal '<' or '>', so nothing is stripped;
    // unescaping then yields '<br>' as plain text, not a newline.
    assert_eq!(html_text("&lt;br&gt;"), "<br>");
}

#[test]
fn round_trip_plain_text() {
    assert_eq!(html_text(&render("hello world")), "hello world");
    assert_eq!(html_text(&render("The quick brown fox")), "The quick brown fox");
    assert_eq!(html_text(&render("")), "");
}

#[test]
fn round_trip_with_special_characters() {
    assert_eq!(html_text(&render("a & b")), "a & b");
    assert_eq!(html_text(&render("a < b > c")), "a < b > c");
    assert_eq!(html_text(&render("say \"hi\"")), "say \"hi\"");
    assert_eq!(html_text(&render("it's fine")), "it's fine");
}

#[test]
fn link_keeps_only_text() {
    assert_eq!(html_text(&render("[docs](https://example.org)")), "docs");
}

#[test]
fn tag_with_attributes_is_removed_whole() {
    // render produces <a href="https://a.b/c" rel="nofollow noopener noreferrer">x</a>
    // The opening tag (from '<' to the first '>') includes all attributes and is removed.
    assert_eq!(html_text(&render("[x](https://a.b/c)")), "x");
}
