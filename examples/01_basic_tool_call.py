"""Basic tool call receipt example.

Shows the minimum viable use of hermes-decision-receipts:
generate a signer, wrap a tool call, verify the output.

Run:
    python examples/01_basic_tool_call.py
"""

from hermes_decision_receipts import ReceiptSigner


def main() -> None:
    # In production, load signer from KMS/HSM. Here we generate for demo.
    signer = ReceiptSigner.generate(agent_id="hermes-research-01")
    print(f"Agent key ID: {signer.kid}")
    print(f"Public key: {signer.public_key_hex}\n")

    # Simulate Hermes invoking a tool.
    receipt = signer.sign_tool_call(
        tool_name="web_search",
        tool_args={"query": "Nous Research Hermes 4 release notes"},
        decision="allow",
        policy_id="research-read-only-v1",
        policy_hash="sha256:0000000000000000000000000000000000000000000000000000000000000000",
        skill_version_hash="sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )

    print(f"Receipt ID: {receipt.receipt_id}")
    print(f"Signature: {receipt.signature['sig'][:32]}...")
    print()
    print("Full receipt:")
    print(receipt.to_json())
    print()

    # Verify locally.
    assert receipt.verify(signer.public_key_hex), "Self-verification failed"
    print("✓ Local verification passed")
    print()
    print("External verification:")
    print(f"  echo '{receipt.to_json()}' > receipt.json")
    print(f"  npx @veritasacta/verify receipt.json --key {signer.public_key_hex}")


if __name__ == "__main__":
    main()
