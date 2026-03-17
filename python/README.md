# VEX SDK for Python (v1.5.0) 🛡️🐍
## Cognitive Routing & Silicon-Rooted Evidence

The `provn-vex-sdk` is the high-level implementation of the VEX Protocol. It builds directly on top of the base `provn-sdk` to provide verifiable loops for AI agents.

### Installation
```bash
pip install provn-vex-sdk
```

### 🚀 Usage

```python
import os
from provn_vex_sdk import VexAgent, vex_secured

agent = VexAgent(
    identity_key=os.getenv("VEX_IDENTITY_KEY"),
    vanguard_url="https://vanguard.provn.ai"
)

# Option A: Method Decorator (Automated Verifiable Loop)
@vex_secured(intent="Authorize high-value transaction")
async def execute_transfer(amount: float, recipient: str):
    # This block only runs if VEX verification succeeds
    return await bank_api.send(amount, recipient)

# Option B: Manual Capsule Construction
capsule = await agent.build_capsule(
    tool_name="reboot_system",
    parameters={"node_id": "titan-01"}
)
```

---
**Note:** `provn-vex-sdk` requires `provn-sdk` for core cryptographic signatures.
🛡️⚓🚀
