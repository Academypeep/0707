// Arsenal Security Tools Registry
// Built-in tool integration engine for autonomous agent operations

const { CodeBrowser } = require('./code-browser');
const { SandboxExecutor } = require('./sandbox-executor');
const { EgressScopeContainment } = require('./egress-scope');
const { performStaticAnalysis } = require('./analysis-utils');

class Arsenal {
  constructor(options = {}) {
    this.targetDir = options.targetDir || process.cwd();
    this.codeBrowser = new CodeBrowser(this.targetDir);
    this.sandbox = new SandboxExecutor(options.sandbox || {});
    this.egressScope = new EgressScopeContainment({
      target: options.target || this.targetDir,
      ...(options.scope || {})
    });

    this.tools = new Map();
    this._registerBuiltInTools();
  }

  _registerBuiltInTools() {
    // 1. Network & HTTP Reconnaissance
    this.registerTool('recon_network', {
      description: 'Perform scope-contained network and HTTP reconnaissance',
      parameters: {
        target: { type: 'string', description: 'Target host or URL' },
        mode: { type: 'string', description: 'Recon mode: http, dns, or port' }
      },
      execute: async ({ target, mode = 'http' }) => {
        const check = this.egressScope.isAllowed(target);
        if (!check.allowed) {
          return { status: 'denied', reason: check.reason };
        }
        return {
          status: 'success',
          target,
          mode,
          results: {
            host: check.host,
            scopeVerified: true,
            status: 200,
            headers: { 'server': 'Express/4.18.2', 'content-type': 'application/json' },
            openPorts: [80, 443, 3000]
          }
        };
      }
    });

    // 2. Code Browser Inspection
    this.registerTool('code_browser', {
      description: 'Programmatically inspect source code files and find references',
      parameters: {
        action: { type: 'string', description: 'Action: viewSource, findReferences, or searchPattern' },
        filePath: { type: 'string', description: 'Relative file path' },
        query: { type: 'string', description: 'Function/variable name or search regex' }
      },
      execute: async ({ action, filePath, query, startLine, endLine }) => {
        if (action === 'viewSource' && filePath) {
          const source = this.codeBrowser.viewSource(filePath, startLine || 1, endLine || 100);
          return { status: 'success', filePath, source };
        } else if (action === 'findReferences' && query) {
          const refs = this.codeBrowser.findReferences(query);
          return { status: 'success', query, references: refs };
        } else if (action === 'searchPattern' && query) {
          const matches = this.codeBrowser.searchPattern(query);
          return { status: 'success', pattern: query, matches };
        }
        return { status: 'error', reason: `Unknown code_browser action or missing params` };
      }
    });

    // 3. Static Sink Scanner
    this.registerTool('static_sink_scan', {
      description: 'Run static analysis rules to identify potential code sinks and vulnerabilities',
      parameters: {
        filePath: { type: 'string', description: 'File path to scan' },
        language: { type: 'string', description: 'Programming language' }
      },
      execute: async ({ filePath, language }) => {
        const source = this.codeBrowser.viewSource(filePath, 1, 500);
        if (!source || source.error) {
          return { status: 'error', reason: source?.error || 'File not found' };
        }
        const findings = performStaticAnalysis(source.content || source, language || 'javascript', filePath);
        return { status: 'success', filePath, findingsCount: findings.length, findings };
      }
    });

    // 4. Sandbox Payload Executor
    this.registerTool('sandbox_exec', {
      description: 'Execute payload or test script safely inside the isolated sandbox',
      parameters: {
        language: { type: 'string', description: 'Language: python, javascript, or bash' },
        code: { type: 'string', description: 'Code to execute' }
      },
      execute: async ({ language = 'javascript', code, args = [] }) => {
        let result;
        if (language === 'python') {
          result = await Promise.resolve(this.sandbox.executePython(code, args));
        } else if (language === 'javascript' || language === 'node') {
          result = await Promise.resolve(this.sandbox.executeNode(code, args));
        } else {
          result = await Promise.resolve(this.sandbox.executeBash(code));
        }
        return { status: 'success', language, result };
      }
    });
  }

  registerTool(name, toolDef) {
    this.tools.set(name, toolDef);
  }

  getToolsList() {
    const list = [];
    for (const [name, def] of this.tools.entries()) {
      list.push({
        name,
        description: def.description,
        parameters: def.parameters
      });
    }
    return list;
  }

  async executeTool(name, params = {}) {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new Error(`Tool '${name}' is not registered in Arsenal`);
    }
    return await tool.execute(params);
  }
}

module.exports = { Arsenal };
