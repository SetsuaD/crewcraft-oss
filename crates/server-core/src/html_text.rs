//! Plain text back out of the safe HTML that `render::render` (T115) produces, for search and for notification
//! previews. It only has to undo what `render` writes, not parse arbitrary HTML. Task T141.

/// The text of `html`:
/// - every tag (from `<` to the next `>`) is removed, except that `<br>` becomes a newline;
/// - the five escapes `render` writes become their characters again: `&amp;` `&lt;` `&gt;` `&quot;` `&#39;` are `&` `<`
///   `>` `"` `'`; any other `&` is kept as it is;
/// - a `<` with no `>` after it is kept, with the rest of the text, as it is.
///
/// For every text `t` that has no newline, `html_text(&render(t)) == t` when `t` contains no formatting markers
/// (backticks, `*`, `[`); a link keeps only its text, so `[docs](https://example.org)` becomes `docs`.
pub fn html_text(html: &str) -> String {
    let chars: Vec<char> = html.chars().collect();
    let mut result = String::with_capacity(html.len());
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c == '<' {
            let close = (i + 1..chars.len()).find(|&j| chars[j] == '>');
            match close {
                Some(close) => {
                    let tag: String = chars[i + 1..close].iter().collect();
                    if tag == "br" {
                        result.push('\n');
                    }
                    i = close + 1;
                }
                None => {
                    result.push('<');
                    i += 1;
                }
            }
            continue;
        }

        if c == '&'
            && let Some((ch, next)) = unescape_at(&chars, i)
        {
            result.push(ch);
            i = next;
            continue;
        }

        result.push(c);
        i += 1;
    }

    result
}

fn unescape_at(chars: &[char], i: usize) -> Option<(char, usize)> {
    let seqs: [&str; 5] = ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"];
    for seq in seqs {
        let sc: Vec<char> = seq.chars().collect();
        if i + sc.len() <= chars.len() && chars[i..i + sc.len()] == sc[..] {
            let ch = match seq {
                "&amp;" => '&',
                "&lt;" => '<',
                "&gt;" => '>',
                "&quot;" => '"',
                _ => '\'',
            };
            return Some((ch, i + sc.len()));
        }
    }
    None
}
