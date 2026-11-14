//! @mentions in message text, for notifications. Task T104.

/// The names mentioned in `text`, lowercased, without duplicates, in first-seen order.
///
/// - A mention is `@` followed by a run of 1 to 32 name characters: ASCII letters, digits, `_`, `.`, `-`. The run ends
///   at the first other character. A run longer than 32 characters is not a mention at all.
/// - The `@` must be at the start of the text or right after whitespace or `(`. So `ana@example.org` is not a mention.
/// - Trailing `.` and `-` are sentence punctuation, not part of the name; a name that is empty after trimming them is
///   not a mention.
/// - Text inside a backtick code span (from a backtick to the next one, or to the end if it is never closed) is ignored.
pub fn mentions(text: &str) -> Vec<String> {
    use std::collections::HashSet;

    let mut results: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut i: usize = 0;
    let mut prev_char: Option<char> = None;
    let mut in_code = false;

    while i < text.len() {
        // Get current character safely
        let c = match text[i..].chars().next() {
            Some(ch) => ch,
            None => break, // should not happen
        };
        let ch_len = c.len_utf8();

        // Toggle code span state on backticks
        if c == '`' {
            in_code = !in_code;
            i += ch_len;
            prev_char = Some(c);
            continue;
        }

        if !in_code && c == '@' {
            // Determine if '@' is at a valid position
            let ok_pre = match prev_char {
                None => true,
                Some(p) => p.is_whitespace() || p == '(',
            };
            if ok_pre {
                // Collect the run of allowed characters after '@'
                let mut name = String::new();
                let mut j = i + ch_len;
                while j < text.len() {
                    let next_c = match text[j..].chars().next() {
                        Some(ch) => ch,
                        None => break,
                    };
                    if next_c.is_ascii_alphanumeric() || matches!(next_c, '_' | '.' | '-') {
                        name.push(next_c);
                        j += next_c.len_utf8();
                    } else {
                        break;
                    }
                }

                // Validate and store the mention
                if !name.is_empty() && name.len() <= 32 {
                    // Trim trailing '.' and '-'
                    while name.ends_with('.') || name.ends_with('-') {
                        name.pop();
                    }
                    if !name.is_empty() {
                        let lowered = name.to_ascii_lowercase();
                        if !seen.contains(&lowered) {
                            seen.insert(lowered.clone());
                            results.push(lowered);
                        }
                    }
                }

                // Skip past the processed characters. The character before whatever comes next is the last one consumed
                // (the `@` itself when the run was empty), never "start of text": `@ana@bo` mentions only ana.
                i = j;
                prev_char = text[..j].chars().next_back();
                continue;
            }
        }

        // Regular character processing
        i += ch_len;
        prev_char = Some(c);
    }

    results
}
