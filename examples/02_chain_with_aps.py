"""Composition example: Veritas Acta decision receipt + APS delegation chain.

Demonstrates the layered governance story:
    - hermes-aps-delegation provides the delegation chain root (authority to act).
    - hermes-decision-receipts signs each tool call, referencing that root.

An auditor walking the receipts back can answer:
    - Which agent made this call? (receipt.agent_id)
    - What policy governed it? (receipt.policy_hash)
    - What skill version produced it? (receipt.skill_version_hash)
    - Was that skill version authorized by the charter? (APS delegation chain)

In production, the `delegation_chain_root` comes from the APS layer
(aeoess/hermes-aps-delegation). Here we simulate it with a placeholder hash.

Run:
    python examples/02_chain_with_aps.py
"""

import hashlib

from hermes_decision_receipts import ReceiptSigner


def simulated_aps_delegation_root() -> str:
    """Placeholder for what aeoess/hermes-aps-delegation produces.

    In the real composition, this hash is computed by the APS side
    from a signed charter + signed delegation chain. The VA decision
    receipts just reference it; they don't re-verify the APS side.
    """
    return "sha256:" + hashlib.sha256(b"demo-aps-delegation-root-v1").hexdigest()


def main() -> None:
    signer = ReceiptSigner.generate(agent_id="hermes-research-01")
    delegation_root = simulated_aps_delegation_root()

    print(f"APS delegation chain root: {delegation_root}")
    print(f"VA signer kid:             {signer.kid}")
    print()

    # Skill v1: fetch source material.
    skill_v1 = "sha256:" + hashlib.sha256(b"skill:web_search:v1").hexdigest()
    r1 = signer.sign_tool_call(
        tool_name="web_search",
        tool_args={"query": "Nous Hermes evaluation benchmarks"},
        decision="allow",
        policy_id="research-read-only-v1",
        skill_version_hash=skill_v1,
        delegation_chain_root=delegation_root,
    )

    # Skill v1 → v2: small refinement (still within charter).
    skill_v2 = "sha256:" + hashlib.sha256(b"skill:web_search:v2").hexdigest()
    r2 = signer.sign_tool_call(
        tool_name="web_search",
        tool_args={"query": "Hermes benchmark methodology papers"},
        decision="allow",
        policy_id="research-read-only-v1",
        skill_version_hash=skill_v2,
        parent_skill_version_hash=skill_v1,
        delegation_chain_root=delegation_root,
    )

    # Attempted out-of-charter tool call: deny.
    r3 = signer.sign_tool_call(
        tool_name="shell_exec",
        tool_args={"command": "curl http://malicious.example"},
        decision="deny",
        policy_id="research-read-only-v1",
        skill_version_hash=skill_v2,
        delegation_chain_root=delegation_root,
        deny_reason="shell_exec not permitted by research-read-only charter",
    )

    print(f"Chain length: {signer.chain.length}")
    print(f"Chain head:   {signer.chain.last_hash}")
    print()

    for i, receipt in enumerate([r1, r2, r3], start=1):
        print(f"--- Receipt {i} ---")
        print(f"  tool_name:             {receipt.payload['tool_name']}")
        print(f"  decision:              {receipt.payload['decision']}")
        print(f"  skill_version_hash:    {receipt.payload['skill_version_hash']}")
        if "parent_skill_version_hash" in receipt.payload:
            print(f"  parent_skill_version:  {receipt.payload['parent_skill_version_hash']}")
        print(f"  delegation_chain_root: {receipt.payload['delegation_chain_root']}")
        if "deny_reason" in receipt.payload:
            print(f"  deny_reason:           {receipt.payload['deny_reason']}")
        print(f"  receipt_id:            {receipt.receipt_id}")
        print()

    print("All three receipts verify against signer's public key.")
    for r in (r1, r2, r3):
        assert r.verify(signer.public_key_hex)
    print("✓ Chain integrity confirmed")
    print()
    print("An external auditor with the signer's public key and the APS")
    print("delegation chain root can now replay the full decision chain")
    print("without contacting any ScopeBlind, Nous, or aeoess server.")


if __name__ == "__main__":
    main()
