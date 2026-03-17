import { VexAgent, VexConfig } from '../src/agent';
import axios from 'axios';

jest.mock('axios');
jest.mock('@provncloud/sdk', () => ({
    ProvnSDK: jest.fn().mockImplementation(() => ({
        generateKeypair: jest.fn(),
        setKeypair: jest.fn(),
        createClaimNow: jest.fn().mockReturnValue({ data: 'root', timestamp: 123 }),
        signClaim: jest.fn().mockReturnValue({ signature: '66616b655f7369675f686578' })
    })),
    init: jest.fn().mockResolvedValue(undefined)
}));
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('VexAgent', () => {
    const config: VexConfig = {
        identityKey: 'fake_key',
        vanguardUrl: 'http://localhost:3000'
    };

    test('execute() constructs a capsule and sends it via POST', async () => {
        const agent = new VexAgent(config);
        
        mockedAxios.post.mockResolvedValue({ data: { status: 'verified' } });

        const result = await agent.execute('test_tool', { foo: 'bar' });

        expect(mockedAxios.post).toHaveBeenCalledWith(
            `${config.vanguardUrl}/dispatch`,
            expect.objectContaining({
                intent_hash: expect.any(String),
                capsule_root: expect.any(String)
            }),
            expect.any(Object)
        );
        expect(result.status).toBe('verified');
    });

    test('buildCapsule() produces expected structure', async () => {
        const agent = new VexAgent(config);
        const capsule = await agent.buildCapsule('test_tool', { foo: 'bar' });

        expect(capsule).toHaveProperty('intent');
        expect(capsule).toHaveProperty('authority');
        expect(capsule).toHaveProperty('identity');
        expect(capsule).toHaveProperty('witness');
        expect(capsule).toHaveProperty('capsule_root');
    });
});
