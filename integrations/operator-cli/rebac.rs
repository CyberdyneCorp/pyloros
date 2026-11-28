//! Object relationship commands for a service client.
use std::path::PathBuf;

use clap::{Args, Subcommand};
use reqwest::Method;
use serde_json::{Value, json};

use crate::commands::common::read_json;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::output::View;
use crate::registry::{Op, op};

pub const OPS: &[Op] = &[
    op("service rebac model", "replaceRelationshipModel"),
    op("service rebac grant", "grantRelationship"),
    op("service rebac revoke", "revokeRelationship"),
    op("service rebac check", "checkRelationshipPermission"),
];

const MODEL: &str = "/api/v1/clients/me/rebac/model";
const ASSIGNMENTS: &str = "/api/v1/clients/me/rebac/relationships";
const CHECK: &str = "/api/v1/clients/me/rebac/check";

#[derive(Clone, Debug, Args)]
pub struct Object {
    #[arg(long)]
    object_type: String,
    #[arg(long)]
    object_id: String,
}

impl Object {
    fn reference(&self) -> Value {
        json!({"type": self.object_type, "id": self.object_id})
    }
}

#[derive(Clone, Debug, Args)]
pub struct Assignment {
    #[command(flatten)]
    object: Object,
    #[arg(long)]
    relation: String,
    #[arg(long)]
    subject_type: String,
    #[arg(long)]
    subject_id: String,
}

impl Assignment {
    fn payload(&self) -> Value {
        json!({"object": self.object.reference(), "relation": self.relation,
            "subject": {"type": self.subject_type, "id": self.subject_id}})
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Install a complete relationship model.
    Model {
        /// JSON model file, or - for standard input.
        #[arg(long)]
        from_file: PathBuf,
    },
    /// Assign a subject to an object.
    Grant(Assignment),
    /// Remove an assignment.
    Revoke(Assignment),
    /// Evaluate one user's permission on an object.
    Check {
        #[command(flatten)]
        object: Object,
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        permission: String,
    },
}

impl Command {
    pub fn mutating(&self) -> bool {
        !matches!(self, Self::Check { .. })
    }

    pub fn scope(&self) -> &'static str {
        if self.mutating() {
            "rebac:manage"
        } else {
            "rebac:check"
        }
    }

    pub async fn run(self, ctx: &Ctx, token: &str) -> Result<()> {
        let call = match self {
            Self::Model { from_file } => {
                ctx.mutate(Method::PUT, MODEL).json(read_json(&from_file)?)
            }
            Self::Grant(edge) => ctx.mutate(Method::PUT, ASSIGNMENTS).json(edge.payload()),
            Self::Revoke(edge) => ctx
                .destroy(Method::DELETE, ASSIGNMENTS, &edge.object.object_id)
                .json(edge.payload()),
            Self::Check {
                object,
                user_id,
                permission,
            } => {
                return ctx.call(Method::POST, CHECK)
                    .json(json!({"user_id":user_id, "object":object.reference(), "permission":permission}))
                    .bearer(token).run(View::Object(&[("Allowed", "/allowed")])).await;
            }
        };
        call.bearer(token).run(View::Raw).await
    }
}
