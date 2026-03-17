# VEX SDK: Production Polish & Feedback (v1.5.0)

**Status:** Parity Verified (10/10 Math)  
**Objective:** Transition from "Protocol Prototype" to "Production Hardened"

---

## 1. 🔑 Activate Real Signing (Priority: High)
The `VexAgent` implementation currently uses placeholders for the cryptographic signature. To be production-ready, we must activate the `provn-sdk` bridge.

### Python (`agent.py:81`)
- **Action**: Uncomment the `provn_sdk.sign` logic.
- **Detail**: Ensure the `capsule_root` (currently a hex string) is converted to `bytes.fromhex()` before passing it to the signing function.

### TypeScript (`agent.ts:95`)
- **Action**: Uncomment the `this.sdk!.sign` logic.
- **Detail**: Ensure the `capsule_root` is converted to a `Buffer` or `Uint8Array` before signing.

---

## 2. 🛡️ Schema Strictness (Priority: Medium)
In `builder.py`, the segments currently use `extra="allow"`. For a security protocol, we want to prevent developers from accidentally injecting invalid fields that would change the JCS hash without being part of the formal spec.

- **Action**: Change `model_config = {"extra": "allow"}` to `model_config = {"extra": "forbid"}` for `IntentSegment`, `AuthoritySegment`, and `IdentitySegment`.

---

## 3. 🚀 Developer Experience Wrappers (Priority: Medium)
Making the SDK "invisible" is the key to adoption.

### Python: The `@vex_secured` Decorator
Implement a decorator that allows developers to wrap any tool function:
```python
@vex_secured(intent="File modification check")
def update_config(path: str, data: str):
    # Logic here automatically gets wrapped in a VEP and sent to Vanguard
    pass
```

### TypeScript: Vercel AI SDK Middleware
Create a helper that integrates with `ai/tools`. When the LLM generates a tool call, the `VEX-SDK` should intercept, capsule, and verify before the tool executes.

---

## Final Review
The `VEPBuilder` is perfect. The JCS parity matches the Rust core exactly. Once these three items are hit, we can tag v1.5.0 and push to PyPI/NPM.

🛡️⚓🚀
