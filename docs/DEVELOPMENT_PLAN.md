# ProvnAI VEX SDK Architecture & Implementation Specification (v1.5.0)

## 1. The Core Problem Statement

The [VEX Protocol](../vex) (Rust) is a high-performance cognitive security proxy. It validates cryptographic Evidence Capsules (VEPs) containing four strictly defined pillars: Intent, Authority, Identity, and Witness. [McpVanguard](../McpVanguard) intercepts tool calls to ensure L1 physical isolation. 
The [Provn SDK](../provn-sdk) provides the low-level Ed25519 identity generation and generic data hashing.

Currently, if an application developer natively builds AI logic (e.g., using LangChain, OpenAI, or AutoGPT) and wants that agent to securely execute actions through Vanguard to VEX, they have to manually:
1. Wrap their LLM strings into a JSON representation of an `IntentData` structure.
2. Determine their hardware/identity footprint into `IdentityData`.
3. Extract dummy or valid `AuthorityData` and `WitnessData`.
4. Run the components through JCS (JSON Canonicalization) to derive exactly 4 hashes.
5. Create a `capsule_root` array, JCS it, SHA256 it, and then Ed25519 sign it via the `provn-sdk`.
6. Construct either a JSON VEP or a Base64-encoded TLV VEP payload wrapper.
7. Execute an HTTP POST to McpVanguard and unwrap the response.

**The Solution:** The `vex-sdk` abstractly handles this entire cryptographic orchestration, allowing the developer to instantiate a `VexAgent` and call `agent.execute("tool_name", params)`.

---

## 2. Core Architecture of the SDK

The `vex-sdk` (for both Python and TypeScript) relies on these foundational building blocks:

### A. The Core Engine (`VexAgent`)
The primary developer interface. It is instantiated with configuration (identity keys, the Vanguard/VEX sidecar endpoint, and optionally LLM models).

### B. The Context Builder (`VEPBuilder`)
An internal module dedicated to constructing the 4 evidence pillars strictly according to the `capsule-v0.2.md` specification. It natively pulls in `provn-sdk` (Python: `provn_sdk`, TypeScript: `@provncloud/sdk`) for all canonical sorting, SHA-256 digesting, and Ed25519 signing.

### C. The Transport Layer (`ProxyClient`)
A fast HTTP/WebSocket wrapper that fires the constructed payload to the proxy (McpVanguard/VEX sidecar) and deserializes the verification trace result.

---

## 3. Python Implementation Specifics (`/python/vex_sdk`)

The Python SDK is critical for enterprise, data-science, and frameworks like LangChain/LlamaIndex.

### Key Classes

#### `VexAgent(identity_key: str, vanguard_url: str = "http://localhost:3000")`
**Responsibilities:**
- Initializes the cryptography (loads the Ed25519 keys using `provn-sdk`).
- Manages the state and sequence nonces required by the VEX Authority layer.

#### `async def execute(self, tool_name: str, parameters: dict, intent_description: str) -> dict`
**Responsibilities:**
1. **Pillar 1 (IntentBuilder):** Serializes the `tool_name` and `parameters` alongside the `intent_description` (or LLM prompt metadata) into the `IntentData` schema.
2. **Pillar 2 (IdentityBuilder):** Packages the hardware-rooted public key (AID) into the `IdentityData` schema.
3. **Pillar 3 & 4 (Dummy/Proxy Builders):** Sets up standard placeholders for Authority and Witness parameters that the VEX sidecar/proxy will subsequently override or validate.
4. **Hashing & Signing:**
   - Feeds the 4 structures into `provn_sdk` to retrieve JCS SHA-256 hashes.
   - Computes the `capsule_root`.
   - Generates the Ed25519 signature over the `capsule_root`.
5. **Transport:** Uses `httpx` to POST the payload (either as JSON or a VEP binary blob) to `vanguard_url`.

### MCP (Model Context Protocol) Introspection Wrapper
Provide an `McpInterceptor` wrapper. If an agent calls a classic MCP Tool Call format, the `McpInterceptor` extracts the MCP `params`/`method` and funnels it into the `VexAgent.execute()` pipeline.

---

## 4. TypeScript Implementation Specifics (`/typescript/src`)

The TypeScript SDK is critical for Vercel AI SDK integration, Web-Agents, and front-end verification.

### Dependencies
- `@provncloud/sdk`
- `axios` (or native `fetch`) for transport

### Key Interfaces

```typescript
export interface VexConfig {
    identityKey: string;     // Hex or Base64 Ed25519 private key
    vanguardUrl: string;     // Target proxy endpoint
}

export class VexAgent {
    constructor(config: VexConfig);

    /**
     * Executes a tool via the VEX verifiable execution loop
     */
    async execute(toolName: string, params: Record<string, any>, intentContext?: string): Promise<any>;
    
    /**
     * Manually construct a signed Evidence Capsule without dispatching it
     */
    buildCapsule(toolName: string, params: Record<string, any>): VexCapsule;
}
```

### Protocol Mechanics
Because JavaScript does not naturally guarantee object key order, the TS implementation **must** strictly utilize the WASM-based JCS canonicalization imported from `@provncloud/sdk` to avoid hash mismatch bugs against the VEX Rust node.

---

## 5. Development Roadmap Summary

1. **Setup Monorepo Boilerplate**: Configure pre-commit hooks, Pytest, and Jest.
2. **Install Identity**: Link both sub-projects to their respective `provn-sdk` releases to prove Ed25519 alignment.
3. **Construct the `VEPBuilder`**: Write the pipeline that takes generic JSON, constructs `capsule_root` conforming *exactly* to `capsule-v0.2.md`, and signs it.
4. **Write the Tests**: Create dummy payloads in Python and TS and ensure that their emitted 32-byte `capsule_root` is bit-for-bit identical to a test vector extracted from the Rust `vex-core` crate.
5. **Implement `execute()`**: Tie the builder to `httpx`/`fetch`.
6. **Publish**: `npm publish` and `poetry publish`.

This repository essentially becomes the missing "UX Layer" for the entire ProvnAI VEX Protocol puzzle.
