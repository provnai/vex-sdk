# Silicon Identity (Attest) in VEX 🛡️⚓

VEX natively integrates **Silicon Identity** (formerly the standalone "Attest" module) to provide hardware-rooted trust for AI agent actions.

## What is Silicon Identity?

Silicon Identity ensures that an Evidence Capsule wasn't just signed by "some" key, but by a key tied to a specific piece of hardware (e.g., a **TPM 2.0**, **Secure Enclave**, or **HSM**).

## How it works in VEX

The `IdentitySegment` of a VEX Capsule contains:
- **AID (Attestation Identity Key)**: A unique identifier for the hardware.
- **Identity Type**: e.g., `tpm-2.0`, `nitro-enclave`, or `software-sim`.
- **PCRs (Platform Configuration Registers)**: In TPM-enabled environments, these provide a "cryptographic measurement" of the software stack (OS, kernel, binaries).

```python
identity = {
    "aid": "0x554433... (Hardware ID)",
    "identity_type": "tpm-2.0",
    "pcrs": {
        "0": "sha256:...", 
        "1": "sha256:..."
    }
}
```

## Why it matters for AI

1. **Anti-Spoofing**: Prevents an attacker from running your agent on an unauthorized, unhardened machine.
2. **Forensic Integrity**: If an agent makes a mistake, the `.capsule` provides irrefutable proof of WHICH physical or virtual machine issued the command.
3. **Regulatory Compliance**: Meets the "Sovereign Audit" requirements for high-stakes autonomous systems.

---
*For more technical details, see the [VEX Spec v1.5.0](https://specs.provn.ai/vex/v1.5.0).*
