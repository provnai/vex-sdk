import { VEPBuilder } from '../src/builder';

describe('VEX SDK Parity Verification', () => {
    test('calculateCapsuleRoot matches Rust test vector (v1.5.0 Merkle Shift)', () => {
        // Test hashes provided in COWORKER_HANDOFF.md.resolved
        const parityHashes = {
            authority_hash: "6fac0de31355fc1dfe36eee1e0c226f7cc36dd58eaad0aca0c2d3873b4784d35",
            identity_hash: "7869bae0249b33e09b881a0b44faba6ee3f4bab7edcc2aa5a5e9290e2563c828",
            intent_hash: "e02504ea88bd9f05a744cd8a462a114dc2045eb7210ea8c6f5ff2679663c92cb",
            witness_hash: "174dfb80917cca8a8d4760b82656e78df0778cb3aadd60b51cd018b3313d5733"
        };

        // Recalculated for 4-leaf Merkle Tree with 0x00/0x01 domain separation (Definitive v1.5.0)
        const expectedRoot = "8acf6d45aedaf61c61142ea8f9f7a89bc90994532313f20fcc1493a95e36d405";

        const calculatedRoot = VEPBuilder.calculateCapsuleRoot(parityHashes);
        expect(calculatedRoot).toBe(expectedRoot);
    });

    test('calculateCapsuleRoot matches Rust test vector (Empty Tree)', () => {
        const hashes = {
            intent_hash: '00'.repeat(32),
            authority_hash: '00'.repeat(32),
            identity_hash: '00'.repeat(32),
            witness_hash: '00'.repeat(32)
        };
        const root = VEPBuilder.calculateCapsuleRoot(hashes);
        expect(root).toBe('b46fd516fa6c7dcddd52ac2be2a014d8a8de4eaa059f79ccfcff4b8afc4e7ddc');
    });

    test('hashSegment matches expected output (Verification of JCS + SHA256)', () => {
        // Intent Pillar (Inclusive)
        const intent = {
            request_sha256: "e02504ea88bd9f05a744cd8a462a114dc2045eb7210ea8c6f5ff2679663c92cb",
            confidence: 0.95,
            capabilities: ["filesystem", "network"]
        };
        // This is a sanity check that JCS stable-sorting works
        const hash1 = VEPBuilder.hashSegment(intent);
        const hash2 = VEPBuilder.hashSegment({
            capabilities: ["filesystem", "network"],
            confidence: 0.95,
            request_sha256: "e02504ea88bd9f05a744cd8a462a114dc2045eb7210ea8c6f5ff2679663c92cb"
        });
        
        expect(hash1).toBe(hash2);
    });
});
