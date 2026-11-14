//! Message text to HTML that is safe to insert into a page (the web client and the admin console). Task T115.

/// Render `text`:
///
/// - HTML-escape everything: `&` `<` `>` `"` `'` become `&amp;` `&lt;` `&gt;` `&quot;` `&#39;`.
/// - A code span, a backtick up to the next backtick, becomes `<code>...</code>`; nothing inside it is formatted
///   further. A backtick with no closing one is literal.
/// - `**text**` becomes `<strong>text</strong>` and `*text*` becomes `<em>text</em>`. An opening marker must be followed by
///   a non-space character and its closing marker preceded by one, on the same line; a marker with no such closer is
///   literal (so `2 * 3 * 4` stays as it is).
/// - `[text](url)` becomes `<a href="url" rel="nofollow noopener noreferrer">text</a>` only when `url` starts with
///   `http://` or `https://` (any case); the url ends at the first `)`. Any other url leaves the whole thing literal. The
///   href is the escaped url; the text is the escaped text.
/// - A newline becomes `<br>`.
pub fn render(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut result = String::with_capacity(text.len() * 2);
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c == '\n' {
            result.push_str("<br>");
            i += 1;
            continue;
        }

        if c == '`' {
            let close = (i + 1..chars.len()).find(|&j| chars[j] == '`');
            if let Some(close) = close {
                let content: String = chars[i + 1..close].iter().collect();
                result.push_str("<code>");
                result.push_str(&escape_html(&content));
                result.push_str("</code>");
                i = close + 1;
            } else {
                result.push('`');
                i += 1;
            }
            continue;
        }

        if c == '*' && i + 1 < chars.len() && chars[i + 1] == '*' {
            let close = if i + 2 < chars.len() && chars[i + 2] != ' ' { find_closing_bold(&chars, i + 2) } else { None };
            if let Some(close) = close {
                let content: String = chars[i + 2..close].iter().collect();
                result.push_str("<strong>");
                result.push_str(&escape_html(&content));
                result.push_str("</strong>");
                i = close + 2;
            } else {
                result.push('*');
                i += 1;
            }
            continue;
        }

        if c == '*' {
            let close = if i + 1 < chars.len() && chars[i + 1] != ' ' { find_closing_italic(&chars, i + 1) } else { None };
            if let Some(close) = close {
                let content: String = chars[i + 1..close].iter().collect();
                result.push_str("<em>");
                result.push_str(&escape_html(&content));
                result.push_str("</em>");
                i = close + 1;
            } else {
                result.push('*');
                i += 1;
            }
            continue;
        }

        if c == '[' {
            let link = try_parse_link(&chars, i);
            if let Some((link_text, url, end)) = link {
                let lower = url.to_lowercase();
                if lower.starts_with("http://") || lower.starts_with("https://") {
                    result.push_str("<a href=\"");
                    result.push_str(&escape_html(&url));
                    result.push_str("\" rel=\"nofollow noopener noreferrer\">");
                    result.push_str(&escape_html(&link_text));
                    result.push_str("</a>");
                    i = end;
                } else {
                    result.push('[');
                    i += 1;
                }
            } else {
                result.push('[');
                i += 1;
            }
            continue;
        }

        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
        i += 1;
    }

    result
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn find_closing_bold(chars: &[char], from: usize) -> Option<usize> {
    let mut j = from;
    while j + 1 < chars.len() {
        if chars[j] == '\n' || chars[j + 1] == '\n' {
            return None;
        }
        if chars[j] == '*' && chars[j + 1] == '*' && chars[j - 1] != ' ' {
            return Some(j);
        }
        j += 1;
    }
    None
}

fn find_closing_italic(chars: &[char], from: usize) -> Option<usize> {
    let mut j = from;
    while j < chars.len() {
        if chars[j] == '\n' {
            return None;
        }
        if chars[j] == '*' {
            let prev_is_star = chars[j - 1] == '*';
            let next_is_star = j + 1 < chars.len() && chars[j + 1] == '*';
            if !prev_is_star && !next_is_star && chars[j - 1] != ' ' {
                return Some(j);
            }
        }
        j += 1;
    }
    None
}

fn try_parse_link(chars: &[char], i: usize) -> Option<(String, String, usize)> {
    let bracket = (i + 1..chars.len()).find(|&j| chars[j] == ']')?;
    if !(bracket + 1 < chars.len() && chars[bracket + 1] == '(') {
        return None;
    }
    let paren = (bracket + 2..chars.len()).find(|&j| chars[j] == ')')?;
    let link_text: String = chars[i + 1..bracket].iter().collect();
    let url: String = chars[bracket + 2..paren].iter().collect();
    Some((link_text, url, paren + 1))
}
