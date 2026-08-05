// Azure AI Service Wrapper for Mythos Agent
// Provides integration with Azure AI Services for enhanced vulnerability discovery

const axios = require('axios');

class AzureAIService {
  constructor(config = {}) {
    this.config = {
      // Azure OpenAI Configuration
      openAIEndpoint: config.openAIEndpoint || process.env.AZURE_OPENAI_ENDPOINT,
      openAIKey: config.openAIKey || process.env.AZURE_OPENAI_KEY,
      openAIDeployment: config.openAIDeployment || process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4',

      // Azure AI Search Configuration
      searchEndpoint: config.searchEndpoint || process.env.AZURE_SEARCH_ENDPOINT,
      searchKey: config.searchKey || process.env.AZURE_SEARCH_KEY,
      searchIndex: config.searchIndex || process.env.AZURE_SEARCH_INDEX || 'vulnerability-index',

      // Azure Document Intelligence Configuration
      formRecognizerEndpoint: config.formRecognizerEndpoint || process.env.AZURE_FORM_RECOGNIZER_ENDPOINT,
      formRecognizerKey: config.formRecognizerKey || process.env.AZURE_FORM_RECOGNIZER_KEY,

      // Azure AI Content Safety Configuration
      contentSafetyEndpoint: config.contentSafetyEndpoint || process.env.AZURE_CONTENT_SAFETY_ENDPOINT,
      contentSafetyKey: config.contentSafetyKey || process.env.AZURE_CONTENT_SAFETY_KEY,

      // General Settings
      timeout: config.timeout || 30000, // 30 seconds
      maxRetries: config.maxRetries || 3,
      ...config
    };

    // Initialize HTTP clients
    this.openAIClient = this.config.openAIEndpoint && this.config.openAIKey
      ? axios.create({
          baseURL: this.config.openAIEndpoint,
          headers: {
            'api-key': this.config.openAIKey,
            'Content-Type': 'application/json'
          },
          timeout: this.config.timeout
        })
      : null;

    this.searchClient = this.config.searchEndpoint && this.config.searchKey
      ? axios.create({
          baseURL: this.config.searchEndpoint,
          headers: {
            'Content-Type': 'application/json',
            'api-key': this.config.searchKey
          },
          timeout: this.config.timeout
        })
      : null;

    this.formRecognizerClient = this.config.formRecognizerEndpoint && this.config.formRecognizerKey
      ? axios.create({
          baseURL: this.config.formRecognizerEndpoint,
          headers: {
            'Ocp-Apim-Subscription-Key': this.config.formRecognizerKey,
            'Content-Type': 'application/json'
          },
          timeout: this.config.timeout
        })
      : null;

    this.contentSafetyClient = this.config.contentSafetyEndpoint && this.config.contentSafetyKey
      ? axios.create({
          baseURL: this.config.contentSafetyEndpoint,
          headers: {
            'Ocp-Apim-Subscription-Key': this.contentSafetyKey,
            'Content-Type': 'application/json'
          },
          timeout: this.config.timeout
        })
      : null;
  }

  /**
   * Check if Azure OpenAI is configured and available
   */
  isOpenAIAvailable() {
    return !!this.openAIClient;
  }

  /**
   * Check if Azure AI Search is configured and available
   */
  isSearchAvailable() {
    return !!this.searchClient;
  }

  /**
   * Check if Azure Document Intelligence is configured and available
   */
  isFormRecognizerAvailable() {
    return !!this.formRecognizerClient;
  }

  /**
   * Check if Azure AI Content Safety is configured and available
   */
  isContentSafetyAvailable() {
    return !!this.contentSafetyClient;
  }

  /**
   * Generate text using Azure OpenAI
   */
  async generateText(prompt, options = {}) {
    if (!this.isOpenAIAvailable()) {
      throw new Error('Azure OpenAI is not configured or unavailable');
    }

    try {
      const response = await this.openAIClient.post('/openai/deployments/' + this.config.openAIDeployment + '/completions', {
        prompt: prompt,
        max_tokens: options.maxTokens || 1000,
        temperature: options.temperature || 0.7,
        top_p: options.topP || 1.0,
        frequency_penalty: options.frequencyPenalty || 0.0,
        presence_penalty: options.presencePenalty || 0.0,
        stop: options.stop || []
      }, {
        params: {
          'api-version': '2023-05-15'
        }
      });

      return response.data.choices[0].text;
    } catch (error) {
      throw new Error(`Azure OpenAI text generation failed: ${error.message}`);
    }
  }

  /**
   * Generate chat completion using Azure OpenAI
   */
  async generateChatCompletion(messages, options = {}) {
    if (!this.isOpenAIAvailable()) {
      throw new Error('Azure OpenAI is not configured or unavailable');
    }

    try {
      const response = await this.openAIClient.post('/openai/deployments/' + this.config.openAIDeployment + '/chat/completions', {
        messages: messages,
        max_tokens: options.maxTokens || 1000,
        temperature: options.temperature || 0.7,
        top_p: options.topP || 1.0,
        frequency_penalty: options.frequencyPenalty || 0.0,
        presence_penalty: options.presencePenalty || 0.0,
        stop: options.stop || []
      }, {
        params: {
          'api-version': '2023-05-15'
        }
      });

      return response.data.choices[0].message.content;
    } catch (error) {
      throw new Error(`Azure OpenAI chat completion failed: ${error.message}`);
    }
  }

  /**
   * Search for vulnerability patterns using Azure AI Search
   */
  async searchVulnerabilityPatterns(query, options = {}) {
    if (!this.isSearchAvailable()) {
      throw new Error('Azure AI Search is not configured or unavailable');
    }

    try {
      const response = await this.searchClient.post('/indexes/' + this.config.searchIndex + '/docs/search', {
        search: query,
        top: options.top || 10,
        skip: options.skip || 0,
        count: options.count || true,
        facets: options.facets || [],
        highlight: options.highlight || [],
        orderBy: options.orderBy || []
      }, {
        params: {
          'api-version': '2023-07-01-preview'
        }
      });

      return response.data;
    } catch (error) {
      throw new Error(`Azure AI Search failed: ${error.message}`);
    }
  }

  /**
   * Analyze code structure using Azure Document Intelligence
   */
  async analyzeCodeStructure(fileContent, fileType = 'text/plain') {
    if (!this.isFormRecognizerAvailable()) {
      throw new Error('Azure Document Intelligence is not configured or unavailable');
    }

    try {
      // For code analysis, we'll use the general document analysis model
      const response = await this.formRecognizerClient.post('/formrecognizer/v3.0/prebuilt/document:analyze', {
        base64Source: Buffer.from(fileContent).toString('base64')
      }, {
        params: {
          'api-version': '2023-07-31'
        }
      });

      return response.data;
    } catch (error) {
      throw new Error(`Azure Document Intelligence analysis failed: ${error.message}`);
    }
  }

  /**
   * Check content for safety issues using Azure AI Content Safety
   */
  async checkContentSafety(text, options = {}) {
    if (!this.isContentSafetyAvailable()) {
      throw new Error('Azure AI Content Safety is not configured or unavailable');
    }

    try {
      const response = await this.contentSafetyClient.post('/contentsafety/text:analyze', {
        text: text,
        categories: options.categories || ['Hate', 'SelfHarm', 'Sexual', 'Violence'],
        blocklistNames: options.blocklistNames || []
      }, {
        params: {
          'api-version': '2023-04-01'
        }
      });

      return response.data;
    } catch (error) {
      throw new Error(`Azure AI Content Safety check failed: ${error.message}`);
    }
  }

  /**
   * Estimate cost for Azure AI service usage
   */
  estimateCost(serviceType, operationType, units = 1) {
    // Approximate costs per 1K tokens or per operation (in USD)
    const costRates = {
      openAI: {
        gpt4: { input: 0.03, output: 0.06 }, // per 1K tokens
        gpt35: { input: 0.0015, output: 0.002 } // per 1K tokens
      },
      search: {
        standard: 0.50 // per 1K queries
      },
      formRecognizer: {
        documentAnalysis: 1.50 // per 1K pages
      },
      contentSafety: {
        textAnalysis: 1.00 // per 1K text records
      }
    };

    let cost = 0;

    switch (serviceType) {
      case 'openAI':
        const model = this.config.openAIDeployment.includes('gpt-4') ? 'gpt4' : 'gpt35';
        const rate = costRates.openAI[model];
        // Rough estimate: 1 unit = 1K tokens
        cost = (rate.input + rate.output) * units / 1000;
        break;

      case 'search':
        cost = costRates.search.standard * units / 1000;
        break;

      case 'formRecognizer':
        cost = costRates.formRecognizer.documentAnalysis * units / 1000;
        break;

      case 'contentSafety':
        cost = costRates.contentSafety.textAnalysis * units / 1000;
        break;

      default:
        cost = 0.01 * units; // Default fallback
    }

    return cost;
  }
}

module.exports = { AzureAIService };