from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from core.models import ScanState, Scope, Target
from scanners.recon.openapi_model import OpenApiDocument, OpenApiParseError
from scanners.recon.openapi_scanner import OpenAPIScanner


def test_parse_openapi_json_relative_server_local_refs_and_parameters():
    raw = json.dumps({
        "openapi": "3.0.3",
        "servers": [{"url": "/v1"}],
        "components": {
            "parameters": {
                "Trace": {"name": "trace", "in": "query", "schema": {"type": "string"}}
            }
        },
        "paths": {
            "/users/{user_id}": {
                "parameters": [{"name": "user_id", "in": "path", "required": True}],
                "get": {
                    "operationId": "getUser",
                    "parameters": [{"$ref": "#/components/parameters/Trace"}],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    })

    document = OpenApiDocument.parse(raw, "https://api.example.test/openapi.json")

    assert document.version == "3.0.3"
    assert document.blocked_references == ()
    assert document.blocked_servers == ()
    assert len(document.operations) == 1
    operation = document.operations[0]
    assert operation.method == "GET"
    assert operation.url == "https://api.example.test/v1/users/{user_id}"
    assert operation.operation_id == "getUser"
    assert operation.path_parameters == ("user_id",)
    assert operation.query_parameters == ("trace",)


def test_parse_openapi_yaml_and_deduplicates_operations():
    raw = """
openapi: 3.1.0
servers:
  - url: https://api.example.test/v2
paths:
  /items:
    get:
      operationId: listItems
      parameters:
        - name: page
          in: query
      responses:
        '200': {description: ok}
"""
    document = OpenApiDocument.parse(raw, "https://api.example.test/spec/openapi.yaml")
    assert [(op.method, op.url) for op in document.operations] == [
        ("GET", "https://api.example.test/v2/items")
    ]
    assert document.operations[0].query_parameters == ("page",)

    duplicate = json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "/"}, {"url": "/"}],
        "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}},
    })
    parsed = OpenApiDocument.parse(duplicate, "https://api.example.test/openapi.json")
    assert len(parsed.operations) == 1


def test_external_refs_and_servers_are_recorded_but_never_resolved():
    raw = json.dumps({
        "openapi": "3.0.0",
        "servers": [
            {"url": "https://api.example.test/v1"},
            {"url": "https://outside.invalid/steal"},
        ],
        "paths": {
            "/users": {
                "get": {
                    "parameters": [
                        {"$ref": "https://outside.invalid/parameters.json#/Trace"},
                        {"$ref": "//outside.invalid/relative.json#/Other"},
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    })
    document = OpenApiDocument.parse(raw, "https://api.example.test/openapi.json")

    assert document.blocked_servers == ("https://outside.invalid/steal",)
    assert set(document.blocked_references) == {
        "https://outside.invalid/parameters.json#/Trace",
        "//outside.invalid/relative.json#/Other",
    }
    assert [operation.url for operation in document.operations] == [
        "https://api.example.test/v1/users"
    ]


@pytest.mark.parametrize("raw", ["not: [valid", "[]", '{"openapi":"3.0.0","paths":[]}'])
def test_malformed_documents_are_rejected(raw):
    with pytest.raises(OpenApiParseError):
        OpenApiDocument.parse(raw, "https://api.example.test/openapi.json")


def test_oversized_and_excessively_deep_documents_are_rejected():
    oversized = json.dumps({"openapi": "3.0.0", "paths": {}, "padding": "x" * 4096})
    with pytest.raises(OpenApiParseError, match="size"):
        OpenApiDocument.parse(
            oversized,
            "https://api.example.test/openapi.json",
            max_bytes=256,
        )

    nested = value = {}
    for _ in range(12):
        value["child"] = {}
        value = value["child"]
    nested.update({"openapi": "3.0.0", "paths": {}})
    with pytest.raises(OpenApiParseError, match="depth"):
        OpenApiDocument.parse(
            json.dumps(nested),
            "https://api.example.test/openapi.json",
            max_depth=8,
        )


@dataclass
class FakeResponse:
    status_code: int
    text: str
    headers: dict = field(default_factory=lambda: {"content-type": "application/json"})

    @property
    def content(self):
        return self.text.encode("utf-8")


class FakeClient:
    def __init__(self, documents):
        self.documents = documents
        self.request_log = []
        self._policy_enforcer = None

    async def get(self, url, **_kwargs):
        self.request_log.append(("GET", url))
        response = self.documents.get(url, FakeResponse(404, "not found"))
        return response, f"GET {url}"


@pytest.mark.asyncio
async def test_scanner_is_bounded_passive_and_does_not_execute_operations(monkeypatch):
    source = "https://api.example.test/openapi.json"
    client = FakeClient({
        source: FakeResponse(200, json.dumps({
            "openapi": "3.0.0",
            "servers": [
                {"url": "/v1"},
                {"url": "https://outside.invalid/api"},
            ],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path"},
                            {"name": "expand", "in": "query"},
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        })),
    })
    target = Target(
        url="https://api.example.test",
        scope=Scope(allowed_domains=["api.example.test"]),
        discovered_urls=["https://api.example.test/already-known"],
    )
    state = ScanState(target=target)
    scanner = OpenAPIScanner(client, spec_paths=("/openapi.json", "/swagger.json"))

    findings = await scanner.run(state)

    assert findings == []
    assert [entry[1] for entry in client.request_log] == [
        "https://api.example.test/openapi.json",
        "https://api.example.test/swagger.json",
    ]
    assert target.discovered_urls == ["https://api.example.test/already-known"]
    assert target.metadata["openapi_candidates"] == [{
        "method": "GET",
        "url": "https://api.example.test/v1/users/{id}",
        "operation_id": "",
        "path_parameters": ["id"],
        "query_parameters": ["expand"],
        "source_url": source,
    }]
    assert target.metadata["openapi_blocked_servers"] == ["https://outside.invalid/api"]
    assert all("outside.invalid" not in requested for _, requested in client.request_log)


@pytest.mark.asyncio
async def test_scanner_rejects_out_of_scope_candidates_and_obeys_probe_limit():
    source = "https://api.example.test/openapi.json"
    client = FakeClient({
        source: FakeResponse(200, json.dumps({
            "openapi": "3.0.0",
            "paths": {"/ok": {"get": {"responses": {"200": {"description": "ok"}}}}},
        }))
    })
    state = ScanState(target=Target(
        url="https://api.example.test",
        scope=Scope(
            allowed_domains=["api.example.test"],
            excluded_paths=["/ok"],
        ),
    ))
    scanner = OpenAPIScanner(
        client,
        spec_paths=("/openapi.json", "/one", "/two"),
        max_probes=2,
    )

    await scanner.scan(state)

    assert len(client.request_log) == 2
    assert state.target.metadata["openapi_candidates"] == []
