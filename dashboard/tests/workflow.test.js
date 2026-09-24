import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_SAFE_MODULES,
  buildReconRequest,
  buildScanRequest,
  normalizeReconAsset,
  phaseForTerminalStatus,
} from "../src/workflow.js";

test("reconnaissance is restricted to the exact operator-provided host", () => {
  assert.deepEqual(buildReconRequest("https://app.example.test/account"), {
    url: "https://app.example.test/account",
    in_scope: ["app.example.test"],
    out_scope: [],
  });
});

test("canonical target remains a selectable URL", () => {
  assert.deepEqual(
    normalizeReconAsset(
      { type: "target", url: "https://app.example.test/account" },
      "https://app.example.test/account",
    ),
    {
      id: "target-https://app.example.test/account",
      type: "target",
      host: "app.example.test",
      label: "https://app.example.test/account",
      url: "https://app.example.test/account",
      selectable: true,
      selectionReason: "Exact operator-provided target",
    },
  );
});

test("web ports become selectable URLs while non-web ports do not", () => {
  assert.equal(
    normalizeReconAsset(
      { type: "port", host: "app.example.test", port: 8443, service: "https-alt" },
      "https://app.example.test",
    ).url,
    "https://app.example.test:8443/",
  );
  assert.equal(
    normalizeReconAsset(
      { type: "port", host: "app.example.test", port: 5432, service: "postgresql" },
      "https://app.example.test",
    ).selectable,
    false,
  );
});

test("technology observations are never treated as scan targets", () => {
  const asset = normalizeReconAsset(
    { type: "tech", tech: "React", source: "https://app.example.test" },
    "https://app.example.test",
  );
  assert.equal(asset.selectable, false);
  assert.equal(asset.url, "");
});

test("scan request contains only selected URLs and exact host scope", () => {
  const request = buildScanRequest({
    target: "https://app.example.test/account",
    assets: [
      { url: "https://app.example.test/account", host: "app.example.test", selectable: true },
      { url: "", host: "app.example.test", selectable: false },
    ],
    modules: ["header_security"],
    depth: "light",
    threads: 1,
    verifySsl: true,
    authorizationAcknowledged: true,
  });

  assert.deepEqual(request, {
    url: "https://app.example.test/account",
    modules: ["header_security"],
    depth: "light",
    threads: 1,
    in_scope: ["app.example.test"],
    out_scope: [],
    instructions: "",
    selected_assets: ["https://app.example.test/account"],
    verify_ssl: true,
    authorization_acknowledged: true,
  });
});

test("safe defaults exclude high-impact and credential-testing modules", () => {
  assert.deepEqual(DEFAULT_SAFE_MODULES, [
    "ssl_tls_scanner",
    "header_security",
    "session_cookie_scanner",
  ]);
  for (const moduleId of [
    "sql_injection",
    "command_injection",
    "ssrf",
    "race_condition",
    "auth_scanner",
    "rate_limit_scanner",
  ]) {
    assert.equal(DEFAULT_SAFE_MODULES.includes(moduleId), false);
  }
});

test("terminal error and abort statuses are not rendered as complete", () => {
  assert.equal(phaseForTerminalStatus("complete", "scan"), "complete");
  assert.equal(phaseForTerminalStatus("error", "scan"), "error");
  assert.equal(phaseForTerminalStatus("aborted", "scan"), "aborted");
  assert.equal(phaseForTerminalStatus("interrupted", "scan"), "interrupted");
  assert.equal(phaseForTerminalStatus("running", "strategy"), "strategy");
});
