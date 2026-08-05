/**
 * Validator Agent - Secondary verification to reduce false positives
 * Reviews findings with: "Is this real? Prove it."
 */

const { Anthropic } = require('@anthropic-ai/sdk');
const path = require('path');
const { CodeBrowser } = require('./code-browser');

class ValidatorAgent {
  constructor(options = {}) {
    this.targetDir = options.targetDir || process.cwd();
    this.model = options.model || 'claude-opus-4.5';
    this.apiKey = options.apiKey || process.env.ANTHROPIC_API_KEY;

    // Initialize Anthropic client
    if (!this.apiKey && options.allowMock !== true) {
      throw new Error('ANTHROPIC_API_KEY environment variable is required');
    }
    if (this.apiKey) {
      this.client = new Anthropic({ apiKey: this.apiKey });
    }

    this.codeBrowser = new CodeBrowser(this.targetDir, {
      includeHiddenDirs: options.includeHiddenDirs === true || (options.targetDir ? path.basename(path.resolve(options.targetDir)).startsWith('.') : false)
    });
    this.validationResults = [];
    this.falsePositives = 0;
    this.truePositives = 0;
  }

  /**
   * Validate a batch of findings
   */
  async validateFindings(findings) {
    console.log(`\n[VALIDATOR] Validating ${findings.length} findings...`);

    const validated = [];

    for (const finding of findings) {
      const result = await this.validateFinding(finding);
      if (result.isReal) {
        validated.push({ ...finding, ...result });
      }
    }

    console.log(`[VALIDATOR] ${validated.length}/${findings.length} confirmed as real`);
    return validated;
  }

  /**
   * Validate a single finding
   */
  async validateFinding(finding) {
    console.log(`[VALIDATOR] Checking ${finding.cwe}: ${finding.title}`);

    // Get code context
    const codeContext = this._extractCodeContext(finding);

    // Build validation prompt
    const prompt = this._buildValidationPrompt(finding, codeContext);

    try {
      // Call Claude to verify
      const response = await this._callClaude(prompt);

      // Parse validation result
      const result = this._parseValidationResponse(response, finding);

      this.validationResults.push(result);
      return result;
    } catch (error) {
      console.error(`[VALIDATOR] Error validating ${finding.cwe}:`, error.message);
      return { isReal: false, confidence: 0, reason: 'Validation error' };
    }
  }

  /**
   * Extract code context for a finding
   */
  _extractCodeContext(finding) {
    try {
      // Parse location: "file.js:45 - functionName"
      const locMatch = finding.location.match(/^(.+?):(\d+)/);
      if (!locMatch) return null;

      const [, filePath, line] = locMatch;
      const lineNum = parseInt(line);

      // Get code snippet
      const snippet = this.codeBrowser.viewSource(filePath, Math.max(1, lineNum - 3), lineNum + 3);

      return {
        file: filePath,
        line: lineNum,
        snippet
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Build the validation prompt
   */
  _buildValidationPrompt(finding, codeContext) {
    let prompt = `You are a security code reviewer verifying a claimed vulnerability.

CLAIMED VULNERABILITY:
CWE: ${finding.cwe}
Title: ${finding.title}
Severity: ${finding.severity}
Location: ${finding.location}
Evidence: ${finding.evidence || 'N/A'}
PoC: ${finding.poc || 'N/A'}

`;

    if (codeContext && codeContext.snippet) {
      prompt += `CODE CONTEXT:
\`\`\`
${codeContext.snippet.lines.map(l => `${l.number}: ${l.content}`).join('\n')}
\`\`\`

`;
    }

    prompt += `TASK: Verify this finding.

Answer these questions:
1. Is the claimed vulnerability REAL and exploitable in this code?
2. If YES: Can you construct a concrete PoC input/scenario that triggers it?
3. Are there any defensive checks I missed that mitigate the vulnerability?
4. Rate your confidence 0-100% that this is exploitable.

Format your response as:
IS_REAL: [YES/NO]
CONFIDENCE: [0-100]
REASONING: [your analysis]
POC_CONFIRMED: [exact PoC if confirmed, or "N/A"]
DEFENSE_CHECKS: [defensive code found, or "None"]`;

    return prompt;
  }

  /**
   * Call Claude API with real Anthropic SDK
   */
  async _callClaude(prompt) {
    try {
      const response = await this.client.beta.messages.create({
        model: this.model,
        max_tokens: 2000,
        temperature: 0.5,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      });

      const content = Array.isArray(response.content)
        ? response.content.map(block => block.text || '').join('')
        : response.content || response.completion || '';

      return content;
    } catch (error) {
      console.error('[VALIDATOR] API Error:', error.message);
      throw error;
    }
  }

  /**
   * Parse validation response
   */
  _parseValidationResponse(response, finding) {
    const isRealMatch = response.match(/IS_REAL:\s*(YES|NO)/i);
    const confidenceMatch = response.match(/CONFIDENCE:\s*(\d+)/);
    const pocMatch = response.match(/POC_CONFIRMED:\s*(.+?)(?:\n|$)/);

    const isReal = isRealMatch && isRealMatch[1].toUpperCase() === 'YES';
    const confidence = confidenceMatch ? parseInt(confidenceMatch[1]) : 0;
    const poc = pocMatch ? pocMatch[1].trim() : null;

    return {
      isReal,
      confidence,
      verified: isReal && confidence > 70,
      poc,
      originalFinding: finding,
      validatedAt: new Date().toISOString()
    };
  }

  /**
   * Get validation summary
   */
  getSummary() {
    const verified = this.validationResults.filter(r => r.verified).length;
    const total = this.validationResults.length;
    const avgConfidence = this.validationResults.reduce((sum, r) => sum + r.confidence, 0) / total || 0;

    return {
      total,
      verified,
      rejected: total - verified,
      averageConfidence: Math.round(avgConfidence),
      results: this.validationResults
    };
  }

  /**
   * Get false positive rate estimate
   */
  getFalsePositiveRate() {
    const rejected = this.validationResults.filter(r => !r.verified).length;
    const total = this.validationResults.length;
    return total > 0 ? ((rejected / total) * 100).toFixed(1) : 0;
  }
}

module.exports = { ValidatorAgent };
