"""Validate the ReBAC OpenAPI document and the JSON examples clients copy from it."""

# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "openapi-spec-validator==0.9.0",
#   "jsonschema==4.26.0",
#   "PyYAML==6.0.3",
#   "referencing==0.37.0",
# ]
# ///

from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


def media_examples(media, resolver):
    if "example" in media:
        yield "example", media["example"]
    for name, example in media.get("examples", {}).items():
        if "$ref" in example:
            example = resolver.lookup(example["$ref"]).contents
        yield name, example["value"]


def check_examples(document, uri):
    resource = Resource(contents=document, specification=DRAFT202012)
    resolver = Registry().with_resource(uri, resource).resolver(uri)
    root = Draft202012Validator(document, format_checker=Draft202012Validator.FORMAT_CHECKER)
    checked = 0
    for path, operations in document["paths"].items():
        for method, operation in operations.items():
            for label, message in {"request": operation["requestBody"], **operation["responses"]}.items():
                if "$ref" in message:
                    message = resolver.lookup(message["$ref"]).contents
                media = message.get("content", {}).get("application/json", {})
                examples = list(media_examples(media, resolver))
                location = f"{method.upper()} {path} {label}"
                if label in ("request", "200") and not examples:
                    raise ValueError(f"{location} is missing its JSON example")
                for name, value in examples:
                    validator = root.evolve(schema=media["schema"])
                    error = next(validator.iter_errors(value), None)
                    if error:
                        raise ValueError(f"{location} {name}: {error.message}")
                    checked += 1
    return checked


if __name__ == "__main__":
    contract = Path(__file__).resolve().parents[1] / "openapi/rebac.yaml"
    document = yaml.safe_load(contract.read_text())
    validate(document, base_uri=contract.as_uri())
    print(f"Validated OpenAPI document and {check_examples(document, contract.as_uri())} JSON examples.")
