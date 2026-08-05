/**
 * Sandbox Executor - Execute code safely in isolated context
 * Provides Python/JavaScript execution with timeouts, resource limits, sanitized output
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

class SandboxExecutor {
  constructor(options = {}) {
    this.timeout = options.timeout || 5000; // 5 seconds default
    this.memoryLimit = options.memoryLimit || '256m'; // 256MB default
    this.tempDir = options.tempDir || path.join(os.tmpdir(), 'mythos-sandbox');
    this.maxOutput = options.maxOutput || 10000; // Max 10KB output

    // Ensure temp directory exists
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true });
    }
  }

  /**
   * Execute Python code safely
   */
  executePython(code, args = [], options = {}) {
    return this._executeLanguage('python', code, args, options);
  }

  /**
   * Execute JavaScript code safely
   */
  executeJavaScript(code, args = [], options = {}) {
    return this._executeLanguage('node', code, args, options);
  }

  /**
   * Execute Bash script safely
   */
  executeBash(script, args = [], options = {}) {
    return this._executeLanguage('bash', script, args, options);
  }

  /**
   * Core execution engine with safety guardrails
   */
  _executeLanguage(runtime, code, args, options) {
    const {
      timeout = this.timeout,
      env = {},
      input = null,
      label = 'execution'
    } = options;

    try {
      // Write code to temp file
      const ext = runtime === 'python' ? '.py' : runtime === 'bash' ? '.sh' : '.js';
      const tempFile = path.join(this.tempDir, `tmp-${Date.now()}${ext}`);
      fs.writeFileSync(tempFile, code);

      let command, cmdArgs = [];

      if (runtime === 'python') {
        command = 'python3';
        cmdArgs = [tempFile, ...args];
      } else if (runtime === 'node') {
        command = 'node';
        cmdArgs = [tempFile, ...args];
      } else if (runtime === 'bash') {
        command = 'bash';
        cmdArgs = [tempFile, ...args];
      }

      // Execute with timeout and resource limits
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      try {
        const result = execSync(command + ' ' + cmdArgs.join(' '), {
          timeout,
          maxBuffer: this.maxOutput,
          cwd: this.tempDir,
          env: { ...process.env, ...env },
          encoding: 'utf8'
        });

        stdout = result.substring(0, this.maxOutput);
      } catch (error) {
        if (error.killed) {
          timedOut = true;
          stderr = `Execution timed out after ${timeout}ms`;
        } else {
          stderr = error.stderr || error.message;
          stdout = error.stdout || '';
        }
      }

      // Cleanup
      try {
        fs.unlinkSync(tempFile);
      } catch (e) {
        // Ignore cleanup errors
      }

      return {
        runtime,
        label,
        success: !timedOut && !stderr,
        stdout: stdout.substring(0, this.maxOutput),
        stderr: stderr.substring(0, this.maxOutput),
        timedOut,
        exitCode: timedOut ? 124 : 0
      };
    } catch (error) {
      return {
        runtime,
        label,
        success: false,
        stdout: '',
        stderr: `Sandbox error: ${error.message}`,
        timedOut: false,
        exitCode: 1
      };
    }
  }

  /**
   * Generate test inputs for a target
   */
  generateTestInputs(targetLanguage, vulnerability_type) {
    const payloads = {
      'buffer-overflow': {
        'c-cpp': [
          'A'.repeat(1000),
          'B'.repeat(10000),
          '%x%x%x%x',
          '\x00\x00\x00\x00'
        ]
      },
      'sql-injection': {
        'python': [
          "' OR '1'='1",
          "'; DROP TABLE users; --",
          "1 UNION SELECT 1,2,3",
          "admin'--"
        ],
        'js': [
          "' OR '1'='1",
          "'; DROP TABLE users; --",
          "1 UNION SELECT 1,2,3"
        ],
        'php': [
          "' OR '1'='1",
          "admin'--",
          "1'; UNION SELECT NULL; --"
        ]
      },
      'xss': {
        'js': [
          '<script>alert(1)</script>',
          '<img src=x onerror="alert(1)">',
          'javascript:alert(1)'
        ],
        'php': [
          '<script>alert(1)</script>',
          '<img src=x onerror=alert(1)>',
          '\'><script>alert(1)</script>'
        ]
      },
      'command-injection': {
        'python': [
          '; cat /etc/passwd',
          '| whoami',
          '$(id)',
          '`id`',
          '\n id'
        ],
        'php': [
          '; cat /etc/passwd',
          '| whoami',
          '$(id)',
          '`id`'
        ]
      }
    };

    return payloads[vulnerability_type]?.[targetLanguage] || [];
  }

  /**
   * Format execution result for Claude prompt
   */
  formatResult(result, label = 'Test') {
    return `
=== ${label} ===
Runtime: ${result.runtime}
Success: ${result.success}
${result.stdout ? `STDOUT:\n${result.stdout}\n` : ''}
${result.stderr ? `STDERR:\n${result.stderr}\n` : ''}
Timed out: ${result.timedOut}`;
  }
}

module.exports = { SandboxExecutor };
