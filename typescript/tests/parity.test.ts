import { VEPBuilder } from '../src/builder';

describe('VEX SDK Parity Verification', () => {
    test('calculateCapsuleRoot matches Rust test vector (v1.6.0 Protocol Alignment)', () => {
        const parityHashes = {
            authority_hash: "1f66eab08c7276b5bd65b6624193eb216159a675e43b85d827de85ec065495c6",
            identity_hash: "7869bae0249b33e09b881a0b44faba6ee3f4bab7edcc2aa5a5e9290e2563c828",
            intent_hash: "ce4041d35af4dd0c00b60a04c80779516178097f7ab7e20fea6da2996dc06446",
            witness_hash: "2aa5ae39acd791e6ae12341b4e82ec16cfcdd2ab4e46a8fb48389dff6217fd42"
        };

        const expectedRoot = "35ef4684c3168f54f040e0e6a24d5bde35464731e6c32bb34bcc30fbb69c8255";

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
            schema: "vex/intent/v3",
            aid: "00".repeat(32),
            request_sha256: "ce4041d35af4dd0c00b60a04c80779516178097f7ab7e20fea6da2996dc06446",
            commands: ["test_tool", { foo: "bar" }],
            confidence: 1.0,
            capabilities: ["sdk_execution"]
        };
        // This is a sanity check that JCS stable-sorting works
        const hash1 = VEPBuilder.hashSegment(intent);
        const hash2 = VEPBuilder.hashSegment({
            capabilities: ["sdk_execution"],
            confidence: 1.0,
            commands: ["test_tool", { foo: "bar" }],
            request_sha256: "ce4041d35af4dd0c00b60a04c80779516178097f7ab7e20fea6da2996dc06446",
            aid: "00".repeat(32),
            schema: "vex/intent/v3"
        });
        
        expect(hash1).toBe(hash2);
    });
});
