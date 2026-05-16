"""Ed25519-signed decision receipts for Hermes agent tool calls.

Companion to hermes-aps-delegation (APS delegation/identity layer).
Conforms to draft-farley-acta-signed-receipts-01.

Quick start:

    from hermes_decision_receipts import ReceiptSigner

    signer = ReceiptSigner.generate()
    receipt = signer.sign_tool_call(
        tool_name="web_search",
        tool_args={"query": "..."},
        decision="allow",
        policy_id="research-read-only-v1",
    )
    print(receipt.to_json())

Verify externally:
    npx @veritasacta/verify receipt.json --key <signer.public_key_hex>
"""

from __future__ import annotations

from .signer import PREDICATE_TYPE_DECISION_RECEIPT, Receipt, ReceiptChain, ReceiptSigner

__version__ = "0.1.0a1"
__all__ = ["PREDICATE_TYPE_DECISION_RECEIPT", "Receipt", "ReceiptChain", "ReceiptSigner"]
