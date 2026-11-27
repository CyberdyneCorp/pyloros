//! First-stage checks for stored hook source. Parsing never runs the module.
mod compiler;
mod policy;

use ruff_python_ast::{
    AnyNodeRef, ModModule, PySourceType,
    token::{TokenKind, Tokens},
    visitor::source_order::{SourceOrderVisitor, TraversalSignal},
};
use ruff_python_parser::{ParseError, ParseErrorType, Parsed, parse_unchecked_source};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use serde_json::{Value, json};
use std::io::Read;

const MAX_SOURCE: u64 = 2 << 20;

#[derive(Default)]
struct Prescan {
    depth: usize,
    first: Option<(usize, String)>,
}

impl<'a> SourceOrderVisitor<'a> for Prescan {
    fn enter_node(&mut self, node: AnyNodeRef<'a>) -> TraversalSignal {
        self.depth += 1;
        if self
            .first
            .as_ref()
            .is_some_and(|(depth, _)| *depth <= self.depth)
        {
            return TraversalSignal::Skip;
        }
        let reason = match node {
            AnyNodeRef::StmtImport(_) | AnyNodeRef::StmtImportFrom(_) => {
                "import statements are not allowed in hooks".to_owned()
            }
            AnyNodeRef::ExprName(name) if name.id.starts_with("__") => {
                format!("dunder name '{}' is not allowed", name.id)
            }
            AnyNodeRef::ExprAttribute(attr)
                if attr.attr.starts_with("__")
                    || matches!(attr.attr.as_str(), "mro" | "subclasses") =>
            {
                format!("attribute access to '{}' is not allowed", attr.attr)
            }
            _ => return TraversalSignal::Traverse,
        };
        self.first = Some((self.depth, reason));
        TraversalSignal::Skip
    }

    fn leave_node(&mut self, _: AnyNodeRef<'a>) {
        self.depth -= 1;
    }
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

fn rejection(source: &str, parsed: &Parsed<ModModule>) -> Option<String> {
    if let Some(error) = parsed.errors().first() {
        if let Some(message) = missing_suite(source, parsed.tokens(), error) {
            return Some(message);
        }
        let mut brackets = Vec::new();
        for token in parsed.tokens().iter() {
            match token.kind() {
                TokenKind::Lpar => brackets.push('('),
                TokenKind::Lsqb => brackets.push('['),
                TokenKind::Lbrace => brackets.push('{'),
                TokenKind::Rpar | TokenKind::Rsqb | TokenKind::Rbrace => {
                    brackets.pop();
                }
                _ => {}
            }
        }
        let message = if matches!(error.error, ParseErrorType::UnexpectedIndentation) {
            "unexpected indent".to_owned()
        } else if let Some(open) = brackets.last() {
            format!("'{open}' was never closed")
        } else {
            "invalid syntax".to_owned()
        };
        return Some(format!("syntax error: {message}"));
    }
    let mut scan = Prescan::default();
    for stmt in &parsed.syntax().body {
        scan.visit_stmt(stmt);
    }
    scan.first
        .map(|(_, reason)| reason)
        .or_else(|| policy::diagnostic(source, &parsed.syntax().body))
}

pub fn inspect(input: impl Read) -> Option<Value> {
    let mut source = String::new();
    input
        .take(MAX_SOURCE + 1)
        .read_to_string(&mut source)
        .ok()?;
    if source.len() as u64 > MAX_SOURCE {
        return None;
    }
    let parsed = parse_unchecked_source(&source, PySourceType::Python);
    Some(match rejection(&source, &parsed) {
        Some(error) => json!({"status":"rejected","error":error}),
        None if compiler::fails(&parsed.syntax().body) => json!({"status":"compiler_error"}),
        None => json!({"status":"parsed"}),
    })
}

#[cfg(test)]
fn diagnostic(source: &str) -> Option<String> {
    rejection(
        source,
        &parse_unchecked_source(source, PySourceType::Python),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_structure_without_running_the_source() {
        for code in [
            "# import example",
            "print('import example')",
            "raise Exception('never run')",
        ] {
            assert_eq!(
                inspect(code.as_bytes()).unwrap(),
                json!({"status":"parsed"})
            );
        }
        assert_eq!(
            diagnostic("if True:\n    import math"),
            Some("import statements are not allowed in hooks".into())
        );
        assert_eq!(
            diagnostic("print("),
            Some("syntax error: '(' was never closed".into())
        );
        assert_eq!(
            diagnostic("  pass"),
            Some("syntax error: unexpected indent".into())
        );
    }

    #[test]
    fn locates_missing_bodies_at_the_start_of_multiline_headers() {
        for (source, expected) in [
            (
                "try: pass\nexcept* ValueError:",
                "syntax error: expected an indented block after 'except*' statement on line 2",
            ),
            (
                "if value: pass\nelse:",
                "syntax error: expected an indented block after 'else' statement on line 2",
            ),
            (
                "class C:",
                "syntax error: expected an indented block after class definition on line 1",
            ),
            (
                "if (\n  flag\n):",
                "syntax error: expected an indented block after 'if' statement on line 1",
            ),
            (
                "@decorator\ndef example():",
                "syntax error: expected an indented block after function definition on line 2",
            ),
            (
                "if outer:\n    for i in items:\n # unfinished",
                "syntax error: expected an indented block after 'for' statement on line 2",
            ),
        ] {
            assert_eq!(diagnostic(source).as_deref(), Some(expected));
        }
    }

    #[test]
    fn compiler_errors_respect_nested_scopes_and_policy_precedence() {
        for source in [
            "return 1",
            "def f(a, *, a): pass",
            "for x in xs:\n    pass\nelse:\n    break",
            "while True:\n    def inner():\n        continue",
        ] {
            assert_eq!(
                inspect(source.as_bytes()).unwrap()["status"],
                "compiler_error",
                "{source}"
            );
        }
        for source in [
            "def f():\n    for x in xs:\n        return x",
            "for x in xs:\n    if x: break",
            "f = lambda x: (yield x)",
        ] {
            assert_eq!(
                inspect(source.as_bytes()).unwrap()["status"],
                "parsed",
                "{source}"
            );
        }
        assert_eq!(
            inspect(b"return _hidden".as_slice()).unwrap()["status"],
            "rejected"
        );
    }

    #[test]
    fn reports_syntax_before_policy_and_shallow_nodes_first() {
        assert_eq!(
            diagnostic("import math\nif True pass"),
            Some("syntax error: invalid syntax".into())
        );
        assert_eq!(
            diagnostic("print(obj.__name__)\nimport math"),
            Some("import statements are not allowed in hooks".into())
        );
        assert_eq!(
            diagnostic("__example"),
            Some("dunder name '__example' is not allowed".into())
        );
        assert!(inspect([0xff].as_slice()).is_none());
        assert!(inspect(std::io::repeat(b' ')).is_none());
    }
}
