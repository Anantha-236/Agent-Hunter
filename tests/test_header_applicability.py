import asyncio

import pytest

from core.models import Scope, ScanState, Target
from scanners.misconfig.header_security import HeaderSecurityScanner


class _Response:
    def __init__(self, content_type):
        self.headers = {"content-type": content_type}


class _Client:
    def __init__(self, content_type):
        self.content_type = content_type

    async def get(self, _url, **_kwargs):
        return _Response(self.content_type), "GET / HTTP/1.1"


def _scan_headers(content_type):
    scanner = HeaderSecurityScanner(_Client(content_type))
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(scanner._check_headers("https://example.test/"))


@pytest.mark.parametrize("content_type", ["application/json", "image/png", "text/css"])
def test_document_only_headers_not_reported_for_non_documents(content_type):
    findings = _scan_headers(content_type)
    headers = {finding.extra.get("header") for finding in findings}

    assert "content-security-policy" not in headers
    assert "x-frame-options" not in headers
    assert not any("CSP" in finding.evidence for finding in findings)
    assert not any("X-Frame-Options" in finding.evidence for finding in findings)


def test_html_documents_receive_document_header_checks():
    findings = _scan_headers("text/html; charset=utf-8")
    headers = {finding.extra.get("header") for finding in findings}

    assert "content-security-policy" in headers
    assert "x-frame-options" in headers


def test_api_relevant_headers_are_evaluated_separately():
    findings = _scan_headers("application/json")
    headers = {finding.extra.get("header") for finding in findings}

    assert "strict-transport-security" in headers
    assert "x-content-type-options" in headers
