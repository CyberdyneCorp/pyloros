//! Detect context errors that arise after parsing and restricted-language validation.
use ruff_python_ast::{
    AnyNodeRef as Node, Stmt,
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
struct Context {
    scopes: Vec<(Scope, TextRange)>,
    invalid: bool,
}

impl Context {
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

impl<'a> SourceOrderVisitor<'a> for Context {
    fn enter_node(&mut self, node: Node<'a>) -> TraversalSignal {
        self.invalid |= match node {
            Node::StmtReturn(_) | Node::ExprYield(_) | Node::ExprYieldFrom(_) => {
                !self.allows(node, Scope::Function)
            }
            Node::StmtBreak(_) | Node::StmtContinue(_) => !self.allows(node, Scope::Loop),
            Node::Parameters(p) => {
                let mut names = HashSet::new();
                p.iter().any(|param| !names.insert(param.name().as_str()))
            }
            _ => false,
        };
        if let Some(scope) = scope(node) {
            self.scopes.push(scope);
        }
        TraversalSignal::Traverse
    }

    fn leave_node(&mut self, node: Node<'a>) {
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
