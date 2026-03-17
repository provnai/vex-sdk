# VEX SDK for TypeScript (v1.5.0) 🛡️js
## Cognitive Routing & Silicon-Rooted Evidence

Official TypeScript implementation of the VEX Protocol. Designed to wrap agent tool-calls in a cryptographically verifiable envelope.

### Installation
```bash
npm install @provnai/vex-sdk
```

### 🚀 Usage

```typescript
import { VexAgent, vexMiddleware } from '@provnai/vex-sdk';

const agent = new VexAgent({
    identityKey: process.env.VEX_IDENTITY_KEY!,
    vanguardUrl: 'https://vanguard.provn.ai'
});

// Use with Vercel AI SDK or custom tool loops
const securedResult = await agent.execute(
    'transfer_funds',
    { amount: 1000, currency: 'USD' },
    'Authorize emergency liquidation'
);

console.log(`VEX Outcome: ${securedResult.outcome}`); // ALLOWED
```

---
**Note:** This SDK natively integrates with `@provncloud/sdk` for hardware-rooted trust.
🛡️⚓🚀
