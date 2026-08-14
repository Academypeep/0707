const { LLMProvider } = require('../lib/llm-provider');

describe('LLMProvider', () => {
  test('defaults to mock provider in mock mode', async () => {
    const provider = new LLMProvider({ allowMock: true });
    expect(provider.provider).toBe('mock');

    const res = await provider.complete({ prompt: 'Analyze target code' });
    expect(res).toContain('[MOCK RESPONSE]');
  });

  test('configures provider explicitly', () => {
    const provider = new LLMProvider({ provider: 'openrouter', apiKey: 'test-key' });
    expect(provider.provider).toBe('openrouter');
  });

  test('falls back to local keyless provider when no keys present', () => {
    const oldEnv = process.env;
    process.env = {};
    const provider = new LLMProvider();
    expect(provider.provider).toBe('local');
    process.env = oldEnv;
  });
});
