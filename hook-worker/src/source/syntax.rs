//! Adapt parser diagnostics to the legacy authoring interface.
use ruff_python_ast::{
    Expr, Stmt,
    helpers::any_over_body,
    token::{TokenKind, Tokens},
};
use ruff_python_parser::{LexicalErrorType, ParseError, ParseErrorType, parse_expression};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// Generator delimiters do not count as parentheses around a yield expression.
pub(super) fn bare_generator_yield(body: &[Stmt], tokens: &Tokens) -> bool {
    any_over_body(body, |expr| {
        let Expr::Generator(generator) = expr else {
            return false;
        };
        if !matches!(&*generator.elt, Expr::Yield(_) | Expr::YieldFrom(_)) {
            return false;
        }
        tokens
            .in_range(generator.range)
            .iter()
            .filter(|t| !t.kind().is_trivia())
            .nth(usize::from(generator.parenthesized))
            .is_some_and(|t| t.kind() == TokenKind::Yield)
    })
}

fn missing_suite(source: &str, tokens: &Tokens, error: &ParseError) -> Option<String> {
    let ParseErrorType::OtherError(message) = &error.error else {
        return None;
    };
    let kind = message.strip_prefix("Expected an indented block after ")?;
    let prefix = tokens.before(error.location.start());
    let colon = prefix
        .iter()
        .rposition(|token| token.kind() == TokenKind::Colon)?;
    let stmt = prefix[..colon]
        .rsplit(|token| token.kind() == TokenKind::Newline)
        .next()?;
    let mut significant = stmt.iter().filter(|token| {
        !token.kind().is_trivia() && !matches!(token.kind(), TokenKind::Indent | TokenKind::Dedent)
    });
    let first = significant.next()?;
    let label = match first.kind() {
        TokenKind::Class => "class definition".to_owned(),
        TokenKind::Except
            if significant
                .next()
                .is_some_and(|t| t.kind() == TokenKind::Star) =>
        {
            "'except*' statement".to_owned()
        }
        _ => kind
            .replace('`', "'")
            .replace(" clause", " statement")
            .replace(" block", " statement"),
    };
    let line = LineIndex::from_source_text(source).line_index(first.start());
    Some(format!(
        "syntax error: expected an indented block after {label} on line {line}"
    ))
}

fn delete_target(text: &str) -> Option<&'static str> {
    let parsed = parse_expression(&format!("({text})")).ok()?;
    Some(match parsed.expr() {
        Expr::Call(_) => "function call",
        Expr::NoneLiteral(_) => "None",
        Expr::BooleanLiteral(b) => {
            if b.value {
                "True"
            } else {
                "False"
            }
        }
        Expr::BytesLiteral(_) | Expr::StringLiteral(_) | Expr::NumberLiteral(_) => "literal",
        Expr::EllipsisLiteral(_) => "ellipsis",
        Expr::Dict(_) => "dict literal",
        Expr::Set(_) => "set display",
        Expr::FString(_) => "f-string expression",
        Expr::ListComp(_) => "list comprehension",
        Expr::DictComp(_) => "dict comprehension",
        Expr::SetComp(_) => "set comprehension",
        Expr::Generator(_) => "generator expression",
        Expr::Compare(_) => "comparison",
        Expr::Lambda(_) => "lambda",
        Expr::If(_) => "conditional expression",
        Expr::Named(_) => "named expression",
        _ => "expression",
    })
}

fn delimiter_message(source: &str, tokens: &Tokens, error: &ParseError) -> Option<String> {
    let mut openings = Vec::new();
    for token in tokens
        .iter()
        .take_while(|t| t.start() <= error.location.start())
    {
        let (close, expected) = match token.kind() {
            TokenKind::Lpar | TokenKind::Lsqb | TokenKind::Lbrace => {
                let text = &source[token.range()];
                openings.push((text, token.start()));
                continue;
            }
            TokenKind::Rpar => (")", "("),
            TokenKind::Rsqb => ("]", "["),
            TokenKind::Rbrace => ("}", "{"),
            _ => continue,
        };
        let Some((open, offset)) = openings.pop() else {
            return Some(format!("unmatched '{close}'"));
        };
        if open != expected {
            let lines = LineIndex::from_source_text(source);
            let first = lines.line_index(offset);
            let suffix = if first == lines.line_index(token.start()) {
                String::new()
            } else {
                format!(" on line {first}")
            };
            return Some(format!(
                "closing parenthesis '{close}' does not match opening parenthesis '{open}'{suffix}"
            ));
        }
    }
    if matches!(error.error, ParseErrorType::Lexical(LexicalErrorType::Eof)) {
        openings
            .last()
            .map(|(open, _)| format!("'{open}' was never closed"))
    } else {
        None
    }
}

fn unclosed_string(source: &str, error: &ParseError) -> String {
    let text = &source[error.location];
    let quoted = text.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let triple = quoted.starts_with("\"\"\"") || quoted.starts_with("'''");
    let kind = if triple { "triple-quoted " } else { "" };
    let end = error.location.end().to_usize();
    let prefix = &source[..end];
    let last = prefix
        .strip_suffix("\r\n")
        .or_else(|| prefix.strip_suffix(['\r', '\n']))
        .unwrap_or(prefix)
        .len();
    let line = LineIndex::from_source_text(source)
        .line_index(ruff_text_size::TextSize::try_from(last).unwrap());
    format!("unterminated {kind}string literal (detected at line {line})")
}

pub(super) fn diagnostic(source: &str, tokens: &Tokens, error: &ParseError) -> String {
    if let Some(message) = missing_suite(source, tokens, error) {
        return message;
    }
    let detail = match &error.error {
        ParseErrorType::UnexpectedIndentation => "unexpected indent".into(),
        ParseErrorType::Lexical(LexicalErrorType::IndentationError) => {
            "unindent does not match any outer indentation level".into()
        }
        ParseErrorType::Lexical(LexicalErrorType::UnclosedStringError) => {
            unclosed_string(source, error)
        }
        ParseErrorType::ExpectedToken {
            expected: TokenKind::Colon,
            found: TokenKind::Newline | TokenKind::EndOfFile,
        } => "expected ':'".into(),
        ParseErrorType::InvalidDeleteTarget => delete_target(&source[error.location]).map_or_else(
            || "invalid syntax".into(),
            |target| format!("cannot delete {target}"),
        ),
        _ => delimiter_message(source, tokens, error).unwrap_or_else(|| "invalid syntax".into()),
    };
    format!("syntax error: {detail}")
}

#[cfg(test)]
mod tests {
    use super::super::diagnostic;

    #[test]
    fn describes_the_offending_expression_or_delimiter() {
        for (source, reason) in [
            ("del helper()", "cannot delete function call"),
            ("del (item:=1)", "cannot delete named expression"),
            (
                "x=(\n  1]",
                "closing parenthesis ']' does not match opening parenthesis '(' on line 1",
            ),
            (
                "x=\"\"\"a\n\n",
                "unterminated triple-quoted string literal (detected at line 2)",
            ),
            ("if ok\n    pass", "expected ':'"),
            ("pass\0", "source code string cannot contain null bytes"),
        ] {
            assert_eq!(diagnostic(source), Some(format!("syntax error: {reason}")));
        }
    }
}
