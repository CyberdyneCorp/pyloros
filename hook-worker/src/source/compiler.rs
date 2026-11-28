//! Detect context errors that arise after parsing and restricted-language validation.
use ruff_python_ast::{
    AnyNodeRef as Node, Comprehension, Parameters, Stmt,
    visitor::source_order::{SourceOrderVisitor, TraversalSignal},
};
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq)]
enum Scope {
    Function,
    Class,
    Loop,
}

fn body_range(body: &[Stmt]) -> Option<TextRange> {
    Some(TextRange::new(body.first()?.start(), body.last()?.end()))
}

fn scope(node: Node<'_>) -> Option<(Scope, TextRange)> {
    Some(match node {
        Node::StmtFunctionDef(f) => (Scope::Function, body_range(&f.body)?),
        Node::ExprLambda(f) => (Scope::Function, f.body.range()),
        Node::StmtClassDef(c) => (Scope::Class, body_range(&c.body)?),
        Node::StmtFor(f) => (Scope::Loop, body_range(&f.body)?),
        Node::StmtWhile(w) => (Scope::Loop, body_range(&w.body)?),
        _ => return None,
    })
}

#[derive(Default)]
struct Context<'a> {
    module_names: HashSet<&'a str>,
    namespaces: Vec<Namespace<'a>>,
    scopes: Vec<(Scope, TextRange)>,
    invalid: bool,
}

struct Namespace<'a> {
    body: TextRange,
    outer_iter: Option<TextRange>,
    names: HashSet<&'a str>,
}

impl<'a> Namespace<'a> {
    fn new(body: TextRange, params: Option<&'a Parameters>) -> Self {
        Self {
            body,
            outer_iter: None,
            names: params
                .into_iter()
                .flat_map(|p| p.iter())
                .map(|p| p.name().as_str())
                .collect(),
        }
    }

    fn comprehension(body: TextRange, clauses: &[Comprehension]) -> Self {
        Self {
            body,
            outer_iter: clauses.first().map(|c| c.iter.range()),
            names: HashSet::new(),
        }
    }

    fn contains(&self, range: TextRange) -> bool {
        self.body.contains_range(range)
            && !self
                .outer_iter
                .is_some_and(|iter| iter.contains_range(range))
    }

    fn for_node(node: Node<'a>) -> Option<Self> {
        Some(match node {
            Node::StmtFunctionDef(f) => Self::new(body_range(&f.body)?, Some(&f.parameters)),
            Node::StmtClassDef(c) => Self::new(body_range(&c.body)?, None),
            Node::ExprLambda(f) => Self::new(f.body.range(), f.parameters.as_deref()),
            Node::ExprListComp(c) => Self::comprehension(node.range(), &c.generators),
            Node::ExprDictComp(c) => Self::comprehension(node.range(), &c.generators),
            Node::ExprSetComp(c) => Self::comprehension(node.range(), &c.generators),
            Node::ExprGenerator(c) => Self::comprehension(node.range(), &c.generators),
            _ => return None,
        })
    }
}

impl<'a> Context<'a> {
    fn names(&mut self, node: Node<'_>) -> &mut HashSet<&'a str> {
        let namespace = self
            .namespaces
            .iter_mut()
            .rev()
            .find(|n| n.contains(node.range()));
        namespace.map_or(&mut self.module_names, |n| &mut n.names)
    }

    fn conflicting_declaration(&mut self, node: Node<'a>) -> bool {
        let name = match node {
            Node::StmtGlobal(s) => {
                let names = self.names(node);
                return s.names.iter().any(|name| names.contains(name.as_str()));
            }
            Node::ExprName(n) => n.id.as_str(),
            Node::StmtFunctionDef(f) => f.name.as_str(),
            Node::StmtClassDef(c) => c.name.as_str(),
            Node::ExceptHandlerExceptHandler(h) => match &h.name {
                Some(name) => name.as_str(),
                None => return false,
            },
            _ => return false,
        };
        self.names(node).insert(name);
        false
    }

    // Loop else suites, decorators and parameter defaults run in the enclosing scope.
    fn allows(&self, node: Node<'_>, wanted: Scope) -> bool {
        for &(kind, body) in self.scopes.iter().rev() {
            if body.contains_range(node.range()) {
                if kind == wanted {
                    return true;
                }
                if kind != Scope::Loop {
                    return false;
                }
            }
        }
        false
    }
}

impl<'a> SourceOrderVisitor<'a> for Context<'a> {
    fn enter_node(&mut self, node: Node<'a>) -> TraversalSignal {
        self.invalid |= self.conflicting_declaration(node);
        self.invalid |= match node {
            Node::StmtReturn(_) => !self.allows(node, Scope::Function),
            Node::ExprYield(_) | Node::ExprYieldFrom(_) => {
                let namespace = self
                    .namespaces
                    .iter()
                    .rev()
                    .find(|n| n.contains(node.range()));
                !self.allows(node, Scope::Function)
                    || namespace.is_some_and(|n| n.outer_iter.is_some())
            }
            Node::StmtBreak(_) | Node::StmtContinue(_) => !self.allows(node, Scope::Loop),
            Node::Arguments(a) => {
                let mut keys = HashSet::new();
                a.keywords
                    .iter()
                    .filter_map(|k| k.arg.as_ref())
                    .any(|k| !keys.insert(k.as_str()))
            }
            Node::Parameters(p) => {
                let mut names = HashSet::new();
                p.iter().any(|param| !names.insert(param.name().as_str()))
            }
            _ => false,
        };
        if let Some(namespace) = Namespace::for_node(node) {
            self.namespaces.push(namespace);
        }
        if let Some(scope) = scope(node) {
            self.scopes.push(scope);
        }
        TraversalSignal::Traverse
    }

    fn leave_node(&mut self, node: Node<'a>) {
        if matches!(
            node,
            Node::StmtFunctionDef(_)
                | Node::StmtClassDef(_)
                | Node::ExprLambda(_)
                | Node::ExprListComp(_)
                | Node::ExprDictComp(_)
                | Node::ExprSetComp(_)
                | Node::ExprGenerator(_)
        ) {
            self.namespaces.pop();
        }
        if scope(node).is_some() {
            self.scopes.pop();
        }
    }
}

pub(super) fn fails(body: &[Stmt]) -> bool {
    let mut context = Context::default();
    context.visit_body(body);
    context.invalid
}

#[cfg(test)]
mod tests {
    use super::super::inspect;

    #[test]
    fn yield_uses_the_innermost_evaluation_namespace() {
        for (expression, expected) in [
            ("[(yield item) for item in items]", "compiler_error"),
            ("{(yield item) for item in items}", "compiler_error"),
            ("{item: (yield item) for item in items}", "compiler_error"),
            ("((yield item) for item in items)", "compiler_error"),
            (
                "[x for group in groups for x in (yield group)]",
                "compiler_error",
            ),
            ("[x for x in items if (yield from x)]", "compiler_error"),
            ("[x for x in (yield items)]", "parsed"),
            ("[(lambda: (yield x)) for x in items]", "parsed"),
            (
                "[[x for x in (yield items)] for items in groups]",
                "compiler_error",
            ),
        ] {
            let source = format!("def collect():\n    return {expression}");
            assert_eq!(
                inspect(source.as_bytes()).unwrap()["status"],
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn global_conflicts_use_the_current_namespace() {
        for (source, expected) in [
            ("fncall(x=1, x=2)", "compiler_error"),
            ("def f(a):\n    global a", "compiler_error"),
            ("x = 1\nglobal x", "compiler_error"),
            ("[x for x in xs]\nglobal xs", "compiler_error"),
            ("[x for x in xs]\nglobal x", "parsed"),
            ("def f():\n    x=1\nglobal x", "parsed"),
            (
                "def f():\n    def g(x=y): pass\n    global y",
                "compiler_error",
            ),
        ] {
            assert_eq!(
                inspect(source.as_bytes()).unwrap()["status"],
                expected,
                "{source}"
            );
        }
    }
}
