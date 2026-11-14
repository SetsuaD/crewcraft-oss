// T115: message text to safe HTML (escaping, code spans, bold/italic with flanking rules, http(s)-only links, <br>).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::render::render;

const REL: &str = "rel=\"nofollow noopener noreferrer\"";

#[test]
fn everything_is_escaped() {
    assert_eq!(render("<script>alert('x')</script> & \"q\""), "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;q&quot;");
    assert_eq!(render("plain"), "plain");
    assert_eq!(render(""), "");
}

#[test]
fn code_spans() {
    assert_eq!(render("use `<b>` here"), "use <code>&lt;b&gt;</code> here");
    assert_eq!(render("`**x**`"), "<code>**x**</code>");
    assert_eq!(render("a ` b"), "a ` b");
}

#[test]
fn bold_and_italic() {
    assert_eq!(render("**hi** and *there*"), "<strong>hi</strong> and <em>there</em>");
    assert_eq!(render("2 * 3 * 4"), "2 * 3 * 4");
    assert_eq!(render("**open"), "**open");
    assert_eq!(render("*<i>*"), "<em>&lt;i&gt;</em>");
}

#[test]
fn only_http_links_become_anchors() {
    assert_eq!(render("[docs](https://example.org/a?b=1&c=2)"), format!("<a href=\"https://example.org/a?b=1&amp;c=2\" {REL}>docs</a>"));
    assert_eq!(render("see [x](HTTP://example.org) ok"), format!("see <a href=\"HTTP://example.org\" {REL}>x</a> ok"));
    assert_eq!(render("[x](javascript:alert(1))"), "[x](javascript:alert(1))");
    assert_eq!(render("[x](data:text/html,hi)"), "[x](data:text/html,hi)");
}

#[test]
fn a_quote_in_a_url_cannot_break_out_of_the_attribute() {
    assert_eq!(
        render("[x](https://example.org/\"onmouseover=\"y)"),
        format!("<a href=\"https://example.org/&quot;onmouseover=&quot;y\" {REL}>x</a>")
    );
    assert_eq!(render("[<b>](https://example.org)"), format!("<a href=\"https://example.org\" {REL}>&lt;b&gt;</a>"));
}

#[test]
fn newlines_become_br() {
    assert_eq!(render("a\nb"), "a<br>b");
    assert_eq!(render("*a\nb*"), "*a<br>b*"); // markers never span lines
}
