import { VexAgent } from '../src/agent';

jest.mock('@provncloud/sdk', () => ({
    ProvnSDK: jest.fn().mockImplementation(() => ({
        generateKeypair: jest.fn(),
        setKeypair: jest.fn(),
        createClaimNow: jest.fn().mockReturnValue({ data: 'root', timestamp: 123 }),
        signClaim: jest.fn().mockReturnValue({ signature: '00'.repeat(64) })
    })),
    init: jest.fn().mockResolvedValue(undefined)
}));

describe('Binary Parity', () => {
    test('produces deterministic binary hex', async () => {
        const config = {
            identityKey: '0'.repeat(64),
            vanguardUrl: 'http://localhost:3000'
        };
        const agent = new VexAgent(config as any);

        // Mock Date.now and crypto.randomUUID
        const fixedNow = 1710500000000;
        jest.spyOn(Date, 'now').mockReturnValue(fixedNow);
        
        const crypto = require('crypto');
        jest.spyOn(crypto, 'randomUUID').mockReturnValue('0'.repeat(64));

        // Mock SDK signing
        const mockSDK = {
            createClaimNow: jest.fn().mockReturnValue({}),
            setKeypair: jest.fn(),
            signClaim: jest.fn().mockReturnValue({ signature: '00'.repeat(64) })
        };
        (agent as any).sdk = mockSDK;
        (agent as any).ensureSDK = jest.fn().mockResolvedValue(undefined);

        const capsule = await agent.buildCapsule('test_tool', { foo: 'bar' });
        const binary = agent.toBinary(capsule);

        require('fs').writeFileSync('../python/ts_payload.hex', binary.toString('hex'));
        expect(binary.subarray(0, 4).toString()).toBe('VEP\x03');
        // Forensic Footer Check
        const header = binary.subarray(0, 76);
        const footer = binary.subarray(binary.length - 76);
        expect(footer.equals(header)).toBe(true);
        expect(binary.length).toBeGreaterThan(152);
    });
});
