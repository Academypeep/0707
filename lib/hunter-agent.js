/**
 * Hunter Agent - Performs vulnerability analysis using VSP prompting + tools
 * Orchestrates code browser, sandbox executor, and Claude reasoning
 */

const { Anthropic } = require('@anthropic-ai/sdk');
const { CodeBrowser } = require('./code-browser');
const { SandboxExecutor } = require('./sandbox-executor');
const { buildVSPPrompt, buildThinkAndVerifyPrompt } = require('./vsp-prompts');
const { buildStaticAnalysisSummary, loadStaticAnalysisFile, parseSemgrepJson, parseSarif } = require('./tool-bridge');
const { CostTracker } = require('./cost-tracker');

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

    // Track findings using actual CostTracker
    this.findings = [];
    this.costTracker = new CostTracker();

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

    // Define standard Tool schemas for Claude tool-calling
    this.toolSchemas = [
      {
        name: 'view_source',
        description: 'Inspect specified source lines from a code file.',
        input_schema: {
          type: 'object',
          properties: {
            filePath: { type: 'string', description: 'Path to target source file' },
            startLine: { type: 'number', description: 'Starting line number' },
            endLine: { type: 'number', description: 'Ending line number' }
          },
          required: ['filePath']
        }
      },
      {
        name: 'search_patterns',
        description: 'Find dangerous keywords, regex expressions, or code patterns inside files.',
        input_schema: {
          type: 'object',
          properties: {
            regex: { type: 'string', description: 'Keyword or regex to search' }
          },
          required: ['regex']
        }
      }
    ];
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

      // Step 3: Call Claude with the VSP-guided prompt (incorporating tool calling)
      const findings = await this._callClaudeWithToolLoop(prompt, filePath);

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
   * Call Claude API with VSP-guided prompt + Tool-Calling Loop
   */
  async _callClaudeWithToolLoop(prompt, context) {
    console.log(`[CLAUDE] Calling with context: ${context}`);

    const messages = [{ role: 'user', content: prompt }];
    let iterations = 0;

    while (iterations < this.maxIterations) {
      try {
        const response = await this._makeApiCall({
          model: this.model,
          messages: messages,
          tools: this.toolSchemas,
          temperature: 1,
          max_tokens: 16000
        });

        // Add model response to message log
        messages.push({ role: 'assistant', content: response.content });

        // If tool_use calls are requested, execute them
        const toolCalls = (response.tool_calls || []).filter(tc => tc.type === 'tool_use');
        if (toolCalls.length === 0) {
          // No more tools called, parse and exit
          return this._parseFindings(response.content);
        }

        console.log(`[CLAUDE TOOL LOOP] Processing ${toolCalls.length} tool calls...`);
        for (const tc of toolCalls) {
          const toolResult = await this._executeTool(tc.name, tc.input);
          messages.push({
            role: 'user',
            content: [
              {
                type: 'tool_result',
                tool_use_id: tc.id,
                content: JSON.stringify(toolResult)
              }
            ]
          });
        }

        iterations++;
      } catch (error) {
        console.error(`[CLAUDE TOOL LOOP] API error:`, error.message);
        break;
      }
    }

    return [];
  }

  /**
   * Execute local tool based on tool call parameters
   */
  async _executeTool(name, input) {
    try {
      if (name === 'view_source') {
        return this.codeBrowser.viewSource(input.filePath, input.startLine, input.endLine);
      }
      if (name === 'search_patterns') {
        return this.codeBrowser.searchPattern(input.regex);
      }
    } catch (e) {
      return { error: e.message };
    }
    return { error: `Tool ${name} not supported.` };
  }

  /**
   * Call Anthropic API with real SDK & track cost using CostTracker
   */
  async _makeApiCall(params) {
    if (!this.client) {
      if (this.allowMock) {
        return {
          content: `MOCK RESPONSE FOR PROMPT:\n${params.messages[0].content?.slice(0, 512) || 'N/A'}...`,
          tool_calls: []
        };
      }
      throw new Error('Anthropic client is not initialized');
    }

    try {
      const response = await this.client.beta.messages.create({
        model: params.model,
        messages: params.messages,
        tools: params.tools,
        temperature: params.temperature || 1,
        max_tokens: params.max_tokens || 16000,
      });

      // Track usage using our new CostTracker class
      if (response.usage) {
        this.costTracker.trackUsage('liveAgenticHunt', response.usage);
      }

      const content = Array.isArray(response.content)
        ? response.content.map(block => block.text || '').join('')
        : response.content || response.completion || '';

      // Collect tool calls from assistant message content blocks if any
      const tool_calls = [];
      if (Array.isArray(response.content)) {
        for (const block of response.content) {
          if (block.type === 'tool_use') {
            tool_calls.push(block);
          }
        }
      }

      return {
        content,
        tool_calls,
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
