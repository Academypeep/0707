// Universal Multi-Provider & Keyless LLM Engine
// Supports Anthropic, OpenRouter, Venice, xAI Grok, OpenAI, Local Ollama/vLLM, and Mock Mode

const axios = require('axios');

class LLMProvider {
  constructor(options = {}) {
    this.provider = (options.provider || process.env.TEMPEST_PROVIDER || 'auto').toLowerCase();
    this.model = options.model || process.env.TEMPEST_LOCAL_MODEL || process.env.MODEL || 'claude-opus-4.5';
    this.apiKey = options.apiKey || process.env.ANTHROPIC_API_KEY || process.env.OPENROUTER_API_KEY || process.env.VENICE_API_KEY || process.env.XAI_API_KEY || process.env.OPENAI_API_KEY;
    this.localBaseUrl = options.localBaseUrl || process.env.TEMPEST_LOCAL_BASE_URL || 'http://localhost:11434/api';
    this.allowMock = options.allowMock === true || this.apiKey === 'mock-key' || process.env.ALLOW_MOCK === 'true';

    // Auto detect provider if 'auto'
    if (this.provider === 'auto') {
      if (this.allowMock) {
        this.provider = 'mock';
      } else if (process.env.OPENROUTER_API_KEY) {
        this.provider = 'openrouter';
      } else if (process.env.VENICE_API_KEY) {
        this.provider = 'venice';
      } else if (process.env.XAI_API_KEY) {
        this.provider = 'xai';
      } else if (process.env.OPENAI_API_KEY) {
        this.provider = 'openai';
      } else if (process.env.ANTHROPIC_API_KEY) {
        this.provider = 'anthropic';
      } else {
        // Default keyless fallback
        this.provider = 'local';
      }
    }
  }

  async complete({ prompt, systemPrompt = '', temperature = 0.2, maxTokens = 2000 }) {
    if (this.allowMock || this.provider === 'mock') {
      return this._mockResponse(prompt);
    }

    try {
      switch (this.provider) {
        case 'anthropic':
          return await this._completeAnthropic(prompt, systemPrompt, temperature, maxTokens);
        case 'openrouter':
        case 'venice':
        case 'xai':
        case 'openai':
          return await this._completeOpenAICompatible(prompt, systemPrompt, temperature, maxTokens);
        case 'local':
        case 'ollama':
          return await this._completeLocalOllama(prompt, systemPrompt, temperature, maxTokens);
        default:
          return this._mockResponse(prompt);
      }
    } catch (err) {
      if (this.allowMock) {
        console.warn(`[LLMProvider] Call failed on provider ${this.provider}, falling back to mock: ${err.message}`);
        return this._mockResponse(prompt);
      }
      throw err;
    }
  }

  async _completeAnthropic(prompt, systemPrompt, temperature, maxTokens) {
    const { Anthropic } = require('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey: this.apiKey || process.env.ANTHROPIC_API_KEY });
    const response = await client.messages.create({
      model: this.model,
      max_tokens: maxTokens,
      temperature: temperature,
      system: systemPrompt || undefined,
      messages: [{ role: 'user', content: prompt }]
    });

    return response.content?.[0]?.text || '';
  }

  async _completeOpenAICompatible(prompt, systemPrompt, temperature, maxTokens) {
    let baseURL = 'https://api.openai.com/v1';
    let apiKey = this.apiKey;

    if (this.provider === 'openrouter') {
      baseURL = 'https://openrouter.ai/api/v1';
      apiKey = apiKey || process.env.OPENROUTER_API_KEY;
    } else if (this.provider === 'venice') {
      baseURL = 'https://api.venice.ai/api/v1';
      apiKey = apiKey || process.env.VENICE_API_KEY;
    } else if (this.provider === 'xai') {
      baseURL = 'https://api.x.ai/v1';
      apiKey = apiKey || process.env.XAI_API_KEY;
      if (!this.model || this.model.includes('claude')) this.model = 'grok-build-0.1';
    }

    const messages = [];
    if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
    messages.push({ role: 'user', content: prompt });

    const resp = await axios.post(
      `${baseURL}/chat/completions`,
      {
        model: this.model,
        messages,
        temperature,
        max_tokens: maxTokens
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 30000
      }
    );

    return resp.data?.choices?.[0]?.message?.content || '';
  }

  async _completeLocalOllama(prompt, systemPrompt, temperature, maxTokens) {
    // Keyless local model completion via Ollama / LM Studio / vLLM
    const url = this.localBaseUrl.endsWith('/generate')
      ? this.localBaseUrl
      : `${this.localBaseUrl.replace(/\/$/, '')}/generate`;

    const fullPrompt = systemPrompt ? `System: ${systemPrompt}\nUser: ${prompt}` : prompt;

    const resp = await axios.post(
      url,
      {
        model: this.model || 'llama3',
        prompt: fullPrompt,
        stream: false,
        options: { temperature, num_predict: maxTokens }
      },
      { timeout: 30000 }
    );

    return resp.data?.response || resp.data?.content || '';
  }

  _mockResponse(prompt) {
    // Return structured mock response for offline/testing mode
    return `[MOCK RESPONSE] Analysis complete for prompt context. No critical vulnerabilities found in test mode.`;
  }
}

module.exports = { LLMProvider };
