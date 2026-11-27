//! Report restricted authoring constructs after syntax and structural checks.
use ruff_python_ast::{
    AnyNodeRef as Node, Expr, ExprContext, Parameters, Stmt,
    visitor::source_order::{SourceOrderVisitor, TraversalSignal},
};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(super) fn diagnostic(source: &str, body: &[Stmt]) -> Option<String> {
    let mut check = Policy {
        source,
        lines: LineIndex::from_source_text(source),
        errors: Vec::new(),
    };
    for stmt in body {
        check.visit_stmt(stmt);
    }
    (!check.errors.is_empty()).then(|| check.errors.join("; "))
}

struct Policy<'a> {
    source: &'a str,
    lines: LineIndex,
    errors: Vec<String>,
}

fn prohibited_statement(node: Node<'_>) -> Option<&'static str> {
    Some(match node {
        Node::StmtAnnAssign(_) => "AnnAssign",
        Node::StmtMatch(_) => "Match",
        Node::StmtNonlocal(_) => "Nonlocal",
        Node::StmtTypeAlias(_) => "TypeAlias",
        Node::TypeParamTypeVar(_) => "TypeVar",
        Node::TypeParamTypeVarTuple(_) => "TypeVarTuple",
        Node::TypeParamParamSpec(_) => "ParamSpec",
        Node::StmtTry(stmt) if stmt.is_star => "TryStar",
        Node::StmtFunctionDef(stmt) if stmt.is_async => "AsyncFunctionDef",
        Node::StmtWith(stmt) if stmt.is_async => "AsyncWith",
        Node::StmtFor(stmt) if stmt.is_async => "AsyncFor",
        Node::ExprAwait(_) => "Await",
        _ => return None,
    })
}

impl Policy<'_> {
    fn report(&mut self, node: Node<'_>, message: impl std::fmt::Display) {
        let offset = match node {
            Node::StmtFunctionDef(f) => f.name.start(),
            Node::StmtClassDef(c) => c.name.start(),
            _ => node.start(),
        };
        let line = self.lines.line_index(offset);
        self.errors.push(format!("Line {line}: {message}"));
    }

    fn name(&mut self, node: Node<'_>, name: &str) {
        if name.starts_with('_') && name != "_" {
            self.report(
                node,
                format_args!("\"{name}\" is an invalid variable name because it starts with \"_\""),
            );
        } else if name.ends_with("__roles__") {
            self.report(
                node,
                format_args!(
                    "\"{name}\" is an invalid variable name because it ends with \"__roles__\"."
                ),
            );
        } else if matches!(name, "print" | "printed" | "breakpoint" | "builtins") {
            self.report(node, format_args!("\"{name}\" is a reserved name."));
        }
    }

    fn parameters(&mut self, node: Node<'_>, params: &Parameters) {
        for param in params.posonlyargs.iter().chain(&params.args) {
            self.name(node, param.name());
        }
        for param in params.vararg.iter().chain(&params.kwarg) {
            self.name(node, &param.name);
        }
        for param in &params.kwonlyargs {
            self.name(node, param.name());
        }
    }

    fn attribute(&mut self, node: Node<'_>, name: &str) {
        if name.starts_with('_') && name != "_" {
            self.report(
                node,
                format_args!(
                    "\"{name}\" is an invalid attribute name because it starts with \"_\"."
                ),
            );
        }
        if name.ends_with("__roles__") {
            self.report(
                node,
                format_args!(
                    "\"{name}\" is an invalid attribute name because it ends with \"__roles__\"."
                ),
            );
        }
        if matches!(
            name,
            "tb_next"
                | "cr_await"
                | "f_code"
                | "gi_frame"
                | "f_generator"
                | "f_locals"
                | "f_trace"
                | "gi_code"
                | "cr_origin"
                | "f_globals"
                | "gi_yieldfrom"
                | "cr_code"
                | "tb_frame"
                | "f_back"
                | "co_code"
                | "f_builtins"
                | "cr_frame"
        ) {
            self.report(node, format_args!("\"{name}\" is a restricted name, that is forbidden to access in RestrictedPython."));
        }
    }

    fn class(&mut self, node: Node<'_>, c: &ruff_python_ast::StmtClassDef) {
        self.name(node, &c.name);
        if let Some(arguments) = &c.arguments {
            self.visit_arguments(arguments);
        }
        self.visit_body(&c.body);
        for decorator in &c.decorator_list {
            self.visit_decorator(decorator);
        }
        if let Some(params) = &c.type_params {
            self.visit_type_params(params);
        }
    }

    fn function(&mut self, node: Node<'_>, f: &ruff_python_ast::StmtFunctionDef) {
        let start = f.name.start().to_usize();
        let prefix = self.source[..start]
            .rsplit(['\n', '\r'])
            .next()
            .unwrap_or("");
        let method = prefix.starts_with([' ', '\t'])
            && matches!(
                f.name.as_str(),
                "__init__"
                    | "__eq__"
                    | "__ne__"
                    | "__ge__"
                    | "__gt__"
                    | "__le__"
                    | "__lt__"
                    | "__contains__"
            );
        if !method {
            self.name(node, &f.name);
        }
        self.parameters(node, &f.parameters);

        self.visit_parameters(&f.parameters);
        self.visit_body(&f.body);
        for decorator in &f.decorator_list {
            self.visit_decorator(decorator);
        }
        if let Some(returns) = &f.returns {
            self.visit_expr(returns);
        }
        if let Some(params) = &f.type_params {
            self.visit_type_params(params);
        }
    }
}

impl<'a> SourceOrderVisitor<'a> for Policy<'_> {
    fn enter_node(&mut self, node: Node<'a>) -> TraversalSignal {
        if let Some(kind) = prohibited_statement(node) {
            self.report(node, format_args!("{kind} statements are not allowed."));
            return TraversalSignal::Skip;
        }
        match node {
            Node::ExprName(n)
                if n.ctx != ExprContext::Load || !matches!(n.id.as_str(), "print" | "printed") =>
            {
                self.name(node, &n.id)
            }
            Node::ExprAttribute(n) => self.attribute(node, &n.attr),
            Node::StmtClassDef(c) => {
                self.class(node, c);
                return TraversalSignal::Skip;
            }
            Node::StmtFunctionDef(f) => {
                self.function(node, f);
                return TraversalSignal::Skip;
            }
            Node::ExprLambda(l) => {
                if let Some(params) = &l.parameters {
                    self.parameters(node, params);
                }
            }
            Node::ExprCall(c) => match c.func.as_name_expr().map(|n| n.id.as_str()) {
                Some("eval") => self.report(node, "Eval calls are not allowed."),
                Some("exec") => self.report(node, "Exec calls are not allowed."),
                _ => {}
            },
            _ => {}
        }
        TraversalSignal::Traverse
    }

    fn leave_node(&mut self, node: Node<'a>) {
        match node {
            Node::StmtAugAssign(s) => match s.target.as_ref() {
                Expr::Attribute(_) => {
                    self.report(node, "Augmented assignment of attributes is not allowed.")
                }
                Expr::Subscript(_) => self.report(
                    node,
                    "Augmented assignment of object items and slices is not allowed.",
                ),
                _ => {}
            },
            Node::ExceptHandlerExceptHandler(h) => {
                if let Some(name) = &h.name {
                    self.name(node, name);
                }
            }
            Node::StmtClassDef(c)
                if c.arguments.as_ref().is_some_and(|a| {
                    a.keywords
                        .iter()
                        .any(|k| k.arg.as_ref().is_some_and(|n| n.as_str() == "metaclass"))
                }) =>
            {
                self.report(node, "The keyword argument \"metaclass\" is not allowed.");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::diagnostic;

    #[test]
    fn restricted_constructs_report_the_statement_once() {
        assert_eq!(
            diagnostic("x: _Private = _value").as_deref(),
            Some("Line 1: AnnAssign statements are not allowed.")
        );
        assert_eq!(
            diagnostic("async def f():\n    await task()").as_deref(),
            Some("Line 1: AsyncFunctionDef statements are not allowed.")
        );
        assert!(diagnostic("class Box:\n    def __init__(self): pass").is_none());
    }

    #[test]
    fn reports_definition_body_before_decorators_with_physical_line_numbers() {
        assert_eq!(
            diagnostic("@_dec\r\ndef _f(_p):\r\n    _local=1").as_deref(),
            Some(
                "Line 2: \"_f\" is an invalid variable name because it starts with \"_\"; Line 2: \"_p\" is an invalid variable name because it starts with \"_\"; Line 3: \"_local\" is an invalid variable name because it starts with \"_\"; Line 1: \"_dec\" is an invalid variable name because it starts with \"_\""
            )
        );
    }

    #[test]
    fn reports_the_target_and_value_before_augmented_assignment() {
        assert_eq!(
            diagnostic("obj._value += _delta").as_deref(),
            Some(
                "Line 1: \"_value\" is an invalid attribute name because it starts with \"_\".; Line 1: \"_delta\" is an invalid variable name because it starts with \"_\"; Line 1: Augmented assignment of attributes is not allowed."
            )
        );
    }
}
