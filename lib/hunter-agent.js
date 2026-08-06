/**
 * Hunter Agent - Performs vulnerability analysis using VSP prompting + tools
 * Orchestrates code browser, sandbox executor, and Claude reasoning
 */

const { Anthropic } = require('@anthropic-ai/sdk');
const { CodeBrowser } = require('./code-browser');
const { SandboxExecutor } = require('./sandbox-executor');
const { buildVSPPrompt, buildThinkAndVerifyPrompt } = require('./vsp-prompts');
const { buildStaticAnalysisSummary, loadStaticAnalysisFile, parseSemgrepJson, parseSarif } = require('./tool-bridge');

class HunterAgent {
  constructor(options = {}) {
    this.targetDir = options.targetDir || process.cwd();
    this.model = options.model || 'claude-opus-4.5';
    this.apiKey = options.apiKey || process.env.ANTHROPIC_API_KEY;
    this.maxIterations = options.maxIterations || 10;
    this.useThinkAndVerify = options.useThinkAndVerify !== false;
    this.allowMock = options.allowMock === true;
    this.staticAnalysis = options.staticAnalysis || {};

    if (!this.apiKey && !this.allowMock) {
      throw new Error('ANTHROPIC_API_KEY environment variable is required when allowMock is false');
    }

    if (this.apiKey) {
      this.client = new Anthropic({ apiKey: this.apiKey });
    }

    // Initialize tools
    this.codeBrowser = new CodeBrowser(this.targetDir, {
      includeHiddenDirs: options.includeHiddenDirs === true || (options.entryPoint || '').startsWith('.')
    });
    this.sandbox = new SandboxExecutor(options.sandbox || {});

    // Track findings
    this.findings = [];
    this.costTracker = { total: 0, tokens: 0 };

    this.staticFindings = [];
    this.entryPoint = options.entryPoint || null;
    if (this.staticAnalysis.semgrepJsonPath) {
      this.staticFindings = loadStaticAnalysisFile(this.staticAnalysis.semgrepJsonPath);
    } else if (this.staticAnalysis.codeqlSarifPath) {
      this.staticFindings = loadStaticAnalysisFile(this.staticAnalysis.codeqlSarifPath);
    } else if (this.staticAnalysis.raw) {
      if (this.staticAnalysis.raw.results) {
        this.staticFindings = parseSemgrepJson(this.staticAnalysis.raw);
      } else if (this.staticAnalysis.raw.runs) {
        this.staticFindings = parseSarif(this.staticAnalysis.raw);
      }
    }
  }

  /**
   * Main hunting loop for a single file
   */
  async hunt(filePath, language) {
    console.log(`\n[HUNTER] Starting hunt on ${filePath} (${language})`);

    try {
      // Step 1: Get file metadata and initial context
      const metadata = this.codeBrowser.getFileMetadata(filePath);
      const definitions = this.codeBrowser.getDefinitions(filePath);
      const source = this.codeBrowser.viewSource(filePath);

      // Step 2: Build VSP prompt with code context, entry point origin, and static analysis annotations
      const staticAnnotations = buildStaticAnalysisSummary(this.staticFindings, filePath);
      let prompt = buildVSPPrompt(
        source.lines.map(l => l.content).join('\n'),
        language,
        `
File: ${filePath}
Lines: ${source.lines.length}
Functions: ${definitions.definitions?.length || 0}
Size: ${metadata.size} bytes
`,
        staticAnnotations,
        this.entryPoint
      );

      if (this.useThinkAndVerify) {
        prompt = buildThinkAndVerifyPrompt(prompt);
      }

      // Step 3: Call Claude with the VSP-guided prompt
      const findings = await this._callClaude(prompt, filePath);

      // Step 4: For each finding, attempt live verification
      if (findings && findings.length > 0) {
        for (const finding of findings) {
          await this._verifyFinding(finding, filePath, source);
        }
      }

      return this.findings;
    } catch (error) {
      console.error(`[HUNTER] Error hunting ${filePath}:`, error.message);
      return [];
    }
  }

  /**
   * Call Claude API with VSP-guided prompt
   */
  async _callClaude(prompt, context) {
    console.log(`[CLAUDE] Calling with context: ${context}`);

    if (this.allowMock) {
      const { FableModelSimulator } = require('./fable-model-simulator');
      const source = this.codeBrowser.viewSource(context);
      const fileContent = source.lines ? source.lines.map(l => l.content).join('\n') : '';
      const simulated = FableModelSimulator.simulateHunt(fileContent, context, 'javascript');
      return simulated;
    }

    try {
      const response = await this._makeApiCall({
        model: this.model,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 1, // Extended thinking benefits from higher temperature
        max_tokens: 16000
      });

      const content = Array.isArray(response.content)
        ? response.content.map(block => block.text || '').join('')
        : response.content || response.completion || '';

      const findings = this._parseFindings(content);
      return findings;
    } catch (error) {
      console.error(`[CLAUDE] API error:`, error.message);
      return [];
    }
  }

  /**
   * Call Anthropic API with real SDK
   */
  async _makeApiCall(params) {
    if (this.allowMock) {
      return { content: `MOCK RESPONSE FOR PROMPT:\n${params.messages[0].content.slice(0, 512)}...` };
    }

    if (!this.client) {
      throw new Error('Anthropic client is not initialized');
    }

    try {
      const response = await this.client.beta.messages.create({
        model: params.model,
        messages: params.messages,
        temperature: params.temperature || 1,
        max_tokens: params.max_tokens || 16000,
      });

      if (response.usage) {
        const inputTokens = response.usage.input_tokens || 0;
        const outputTokens = response.usage.output_tokens || 0;
        const inputCost = (inputTokens / 1_000_000) * 3;
        const outputCost = (outputTokens / 1_000_000) * 15;
        this.costTracker.total += inputCost + outputCost;
        this.costTracker.tokens += inputTokens + outputTokens;
      }

      const content = Array.isArray(response.content)
        ? response.content.map(block => block.text || '').join('')
        : response.content || response.completion || '';

      return {
        content,
        usage: response.usage,
        cost: this.costTracker.total
      };
    } catch (error) {
      console.error('[HUNTER] API Error:', error.message);
      throw error;
    }
  }

  /**
   * Parse Claude's response to extract structured findings
   */
  _parseFindings(content) {
    const findings = [];
    const findingRegex = /FINDING:\s*\[(CWE-\d+)\]\s*(.+?)\nSEVERITY:\s*(.+?)\nLOCATION:\s*(.+?)\n/gi;

    let match;
    while ((match = findingRegex.exec(content)) !== null) {
      findings.push({
        cwe: match[1],
        title: match[2],
        severity: match[3],
        location: match[4],
        raw: match[0]
      });
    }

    return findings;
  }

  /**
   * Attempt to verify a finding live
   */
  async _verifyFinding(finding, filePath, sourceCode) {
    console.log(`[VERIFY] Checking ${finding.cwe}: ${finding.title}`);

    // Extract line numbers
    const lineMatch = finding.location.match(/:(\d+)/);
    const line = lineMatch ? parseInt(lineMatch[1]) : null;

    if (!line) return;

    // Get context around the vulnerable code
    const context = this.codeBrowser.viewSource(
      filePath,
      Math.max(1, line - 5),
      line + 5
    );

    // Generate test payloads based on vulnerability type
    const payloads = this.sandbox.generateTestInputs(
      filePath.split('.').pop(),
      finding.cwe.toLowerCase()
    );

    // Try each payload
    for (const payload of payloads) {
      const result = await this._testPayload(payload, filePath);

      if (result.triggered) {
        finding.verified = true;
        finding.poc = payload;
        finding.output = result.output;
        this.findings.push(finding);
        console.log(`✓ CONFIRMED: ${finding.cwe}`);
        return;
      }
    }

    // If unverified but high-confidence, still report
    if (finding.confidence > 0.8) {
      this.findings.push(finding);
      console.log(`◇ THEORETICAL: ${finding.cwe}`);
    }
  }

  /**
   * Test payload execution
   */
  async _testPayload(payload, filePath) {
    // This would execute the target with the payload
    // Return { triggered: boolean, output: string }
    return { triggered: false, output: '' };
  }

  /**
   * Get hunt summary
   */
  getSummary() {
    const confirmed = this.findings.filter(f => f.verified).length;
    const total = this.findings.length;

    return {
      totalFindings: total,
      confirmedFindings: confirmed,
      theoreticalFindings: total - confirmed,
      findings: this.findings,
      cost: this.costTracker.total
    };
  }
}

module.exports = { HunterAgent };
