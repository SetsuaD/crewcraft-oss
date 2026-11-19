//! Plain text for a message's sanitised HTML, for the beta's text-only feed. Rich text comes with M3's full feed.

/// The text a person reads in `html`: tags removed, `<br>` and the end of a paragraph or list item turned into a new
/// line, and the five XML entities plus numeric character references decoded. Anything malformed is shown as written,
/// so nothing a sender typed is silently dropped. Leading and trailing whitespace is trimmed.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(c) = rest.chars().next() {
        match c {
            '<' => match rest.find('>') {
                Some(end) => {
                    let tag = rest[1..end].trim().to_ascii_lowercase();
                    let name = tag.trim_start_matches('/').split([' ', '/']).next().unwrap_or("");
                    let closing = tag.starts_with('/');
                    if name == "br" || (closing && matches!(name, "p" | "li" | "div" | "blockquote" | "pre")) {
                        out.push('\n');
                    }
                    rest = &rest[end + 1..];
                }
                None => {
                    out.push_str(rest);
                    rest = "";
                }
            },
            '&' => match decode_entity(rest) {
                Some((decoded, used)) => {
                    out.push(decoded);
                    rest = &rest[used..];
                }
                None => {
                    out.push('&');
                    rest = &rest[1..];
                }
            },
            _ => {
                out.push(c);
                rest = &rest[c.len_utf8()..];
            }
        }
    }
    out.trim().to_owned()
}

/// The character an entity at the start of `s` stands for, and how many bytes it used.
fn decode_entity(s: &str) -> Option<(char, usize)> {
    let end = s.get(..12).unwrap_or(s).find(';')?;
    let body = &s[1..end];
    let decoded = match body {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" | "#39" => '\'',
        _ => {
            let number = body.strip_prefix('#')?;
            let code = match number.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => number.parse().ok()?,
            };
            char::from_u32(code).filter(|c| !c.is_control() || *c == '\n' || *c == '\t')?
        }
    };
    Some((decoded, end + 1))
}

#[cfg(test)]
mod tests {
    use super::html_to_text;

    #[test]
    fn strips_tags_and_decodes_entities() {
        assert_eq!(html_to_text("<p>Hello <b>crew</b> &amp; friends</p>"), "Hello crew & friends");
        assert_eq!(html_to_text("a<br>b<br/>c"), "a\nb\nc");
        assert_eq!(html_to_text("<p>one</p><p>two</p>"), "one\ntwo");
        assert_eq!(html_to_text("1 &lt; 2 &gt; 0 &quot;q&quot; &#39;s&#39; &#x41;&#66;"), "1 < 2 > 0 \"q\" 's' AB");
    }

    #[test]
    fn keeps_malformed_input_visible() {
        assert_eq!(html_to_text("a < b"), "a < b");
        assert_eq!(html_to_text("fish & chips"), "fish & chips");
        assert_eq!(html_to_text("&bogus;"), "&bogus;");
        assert_eq!(html_to_text("&#0;"), "&#0;");
    }
}
