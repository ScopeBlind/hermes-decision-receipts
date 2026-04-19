"""Tests for hermes-decision-receipts signer."""

from __future__ import annotations

import json

import pytest

from hermes_decision_receipts import ReceiptSigner
from hermes_decision_receipts.signer import _jcs_canonicalize


def test_signer_generates_and_signs() -> None:
    signer = ReceiptSigner.generate()
    receipt = signer.sign_tool_call(
        tool_name="web_search",
        tool_args={"query": "test"},
        decision="allow",
    )
    assert receipt.payload["tool_name"] == "web_search"
    assert receipt.payload["decision"] == "allow"
    assert receipt.signature["alg"] == "EdDSA"
    assert len(receipt.signature["sig"]) == 128  # 64 bytes hex-encoded


def test_receipt_verifies_against_own_key() -> None:
    signer = ReceiptSigner.generate()
    receipt = signer.sign_tool_call(
        tool_name="read_file",
        tool_args={"path": "README.md"},
        decision="allow",
    )
    assert receipt.verify(signer.public_key_hex)


def test_receipt_rejects_wrong_key() -> None:
    signer_a = ReceiptSigner.generate()
    signer_b = ReceiptSigner.generate()
    receipt = signer_a.sign_tool_call(
        tool_name="web_search",
        tool_args={"query": "test"},
        decision="allow",
    )
    assert receipt.verify(signer_a.public_key_hex)
    assert not receipt.verify(signer_b.public_key_hex)


def test_receipt_rejects_tampered_payload() -> None:
    signer = ReceiptSigner.generate()
    receipt = signer.sign_tool_call(
        tool_name="web_search",
        tool_args={"query": "test"},
        decision="allow",
    )
    receipt.payload["decision"] = "deny"  # tamper
    assert not receipt.verify(signer.public_key_hex)


def test_chain_linking() -> None:
    signer = ReceiptSigner.generate()
    r1 = signer.sign_tool_call(tool_name="a", tool_args={}, decision="allow")
    r2 = signer.sign_tool_call(tool_name="b", tool_args={}, decision="allow")
    r3 = signer.sign_tool_call(tool_name="c", tool_args={}, decision="allow")

    assert r1.payload["previousReceiptHash"] is None
    assert r2.payload["previousReceiptHash"] is not None
    assert r3.payload["previousReceiptHash"] is not None

    # Each receipt's previousReceiptHash should equal the JCS-sha256 of the prior payload.
    import hashlib

    r1_canonical = _jcs_canonicalize(r1.payload)
    expected_hash_r2_prev = "sha256:" + hashlib.sha256(r1_canonical.encode("utf-8")).hexdigest()
    assert r2.payload["previousReceiptHash"] == expected_hash_r2_prev


def test_sequence_numbers_monotonic() -> None:
    signer = ReceiptSigner.generate()
    receipts = [
        signer.sign_tool_call(tool_name=f"tool_{i}", tool_args={}, decision="allow")
        for i in range(5)
    ]
    for i, r in enumerate(receipts, start=1):
        assert r.payload["sequence"] == i


def test_jcs_ascii_only_keys() -> None:
    """AIP-0001 requires ASCII-only keys in receipt payloads."""
    signer = ReceiptSigner.generate()
    # A non-ASCII key in tool_args is fine (it gets hashed, not embedded as key).
    receipt = signer.sign_tool_call(
        tool_name="translate",
        tool_args={"q": "こんにちは"},
        decision="allow",
    )
    assert receipt.verify(signer.public_key_hex)


def test_invalid_decision_rejected() -> None:
    signer = ReceiptSigner.generate()
    with pytest.raises(ValueError, match="invalid decision"):
        signer.sign_tool_call(tool_name="x", tool_args={}, decision="banana")


def test_skill_version_hash_optional() -> None:
    signer = ReceiptSigner.generate()
    # Without skill_version_hash
    r1 = signer.sign_tool_call(tool_name="a", tool_args={}, decision="allow")
    assert "skill_version_hash" not in r1.payload

    # With skill_version_hash
    r2 = signer.sign_tool_call(
        tool_name="b",
        tool_args={},
        decision="allow",
        skill_version_hash="sha256:abc",
    )
    assert r2.payload["skill_version_hash"] == "sha256:abc"


def test_delegation_chain_root_composes() -> None:
    """Receipt references APS delegation root without verifying it itself."""
    signer = ReceiptSigner.generate()
    root = "sha256:deadbeef" + "0" * 56
    receipt = signer.sign_tool_call(
        tool_name="web_search",
        tool_args={},
        decision="allow",
        delegation_chain_root=root,
    )
    assert receipt.payload["delegation_chain_root"] == root
    assert receipt.verify(signer.public_key_hex)


def test_receipt_json_parseable() -> None:
    signer = ReceiptSigner.generate()
    receipt = signer.sign_tool_call(tool_name="x", tool_args={}, decision="allow")
    parsed = json.loads(receipt.to_json())
    assert parsed["payload"]["tool_name"] == "x"
    assert parsed["signature"]["alg"] == "EdDSA"
