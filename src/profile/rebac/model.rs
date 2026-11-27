//! Object definitions and the alternatives that prove a permission.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::profile) struct Model {
    types: BTreeMap<String, Object>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Object {
    relations: BTreeMap<String, BTreeSet<String>>,
    permissions: BTreeMap<String, Vec<Proof>>,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
enum Proof {
    Direct { relation: String },
    Inherited { via: String, permission: String },
}

pub(super) fn name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

impl Model {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        let mut remaining = 65_536;
        for (kind, object) in &self.types {
            if !name(kind) || kind == "user" {
                return Err("Invalid object type name");
            }
            for (relation, targets) in &object.relations {
                if !name(relation) || targets.is_empty() {
                    return Err("Invalid relation definition");
                }
                if targets
                    .iter()
                    .any(|t| t != "user" && !self.types.contains_key(t))
                {
                    return Err("Unknown relation destination");
                }
            }
            self.validate_permissions(object, &mut remaining)?;
        }
        Ok(())
    }

    fn validate_permissions(
        &self,
        object: &Object,
        remaining: &mut usize,
    ) -> Result<(), &'static str> {
        for (permission, proofs) in &object.permissions {
            if !name(permission) || proofs.is_empty() {
                return Err("Invalid permission definition");
            }
            for proof in proofs {
                let cost = match proof {
                    Proof::Direct { .. } => 1,
                    Proof::Inherited { via, .. } => {
                        object.relations.get(via).map_or(1, BTreeSet::len)
                    }
                };
                *remaining = remaining
                    .checked_sub(cost)
                    .ok_or("Too many permission references")?;
                if !self.valid_proof(object, proof) {
                    return Err("Invalid permission path");
                }
            }
        }
        Ok(())
    }

    fn valid_proof(&self, object: &Object, proof: &Proof) -> bool {
        match proof {
            Proof::Direct { relation } => object
                .relations
                .get(relation)
                .is_some_and(|t| t.contains("user")),
            Proof::Inherited { via, permission } => {
                object.relations.get(via).is_some_and(|targets| {
                    let mut objects = targets.iter().filter(|t| t.as_str() != "user").peekable();
                    objects.peek().is_some()
                        && objects.all(|t| {
                            self.types
                                .get(t)
                                .is_some_and(|target| target.permissions.contains_key(permission))
                        })
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recursive_paths_require_a_declared_permission_on_every_object_destination() {
        let mut model = json!({"types":{
            "album":{"relations":{"viewer":["user"],"parent":["album","library"]},
                "permissions":{"see":[{"relation":"viewer"},{"via":"parent","permission":"see"}]}},
            "library":{"relations":{"member":["user"]},"permissions":{"see":[{"relation":"member"}]}}
        }});
        let valid = |doc| serde_json::from_value::<Model>(doc).unwrap().validate();
        assert!(valid(model.clone()).is_ok());
        model["types"]["library"]["permissions"] = json!({});
        assert!(valid(model.clone()).is_err());
        model["types"]["album"]["permissions"]["see"] = json!([{"relation":"parent"}]);
        assert!(valid(model).is_err());
    }

    #[test]
    fn model_validation_limits_total_references_across_permissions() {
        let definition = json!({"relations":{"members":["user"]},
            "permissions":{"a":[{"relation":"members"}], "b":[{"relation":"members"}]}});
        let model: Model = serde_json::from_value(json!({"types":{"team":definition}})).unwrap();
        assert!(
            model
                .validate_permissions(&model.types["team"], &mut 1)
                .is_err()
        );
        assert!(
            model
                .validate_permissions(&model.types["team"], &mut 2)
                .is_ok()
        );
    }

    #[test]
    fn ambiguous_or_unknown_proof_fields_are_rejected() {
        assert!(
            serde_json::from_value::<Proof>(
                json!({"relation":"reader","via":"owner","permission":"read"})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<Proof>(json!({"through":"group"})).is_err());
    }
}
