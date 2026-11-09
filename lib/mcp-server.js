// Model Context Protocol (MCP) Server Integration
// Exposes security tools and recon capabilities over MCP JSON-RPC protocol

const { Arsenal } = require('./arsenal');

class MCPServer {
  constructor(options = {}) {
    this.arsenal = new Arsenal(options);
    this.serverName = options.serverName || 'mythos-mcp-server';
    this.version = options.version || '1.0.0';
  }

  handleMessage(jsonMessage) {
    let req;
    try {
      req = typeof jsonMessage === 'string' ? JSON.parse(jsonMessage) : jsonMessage;
    } catch (e) {
      return { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } };
    }

    const { id, method, params } = req;

    if (method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: this.serverName, version: this.version }
        }
      };
    }

    if (method === 'tools/list') {
      const tools = this.arsenal.getToolsList().map(t => ({
        name: t.name,
        description: t.description,
        inputSchema: {
          type: 'object',
          properties: t.parameters
        }
      }));
      // Add standard security_recon tool alias for MCP compatibility
      tools.push({
        name: 'security_recon',
        description: 'Perform security reconnaissance and target discovery',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Target URL or domain' }
          }
        }
      });
      return { jsonrpc: '2.0', id, result: { tools } };
    }

    if (method === 'tools/call') {
      const { name, arguments: toolArgs } = params || {};
      if (name === 'security_recon') {
        return this.arsenal.executeTool('recon_network', toolArgs)
          .then(res => ({
            jsonrpc: '2.0',
            id,
            result: { content: [{ type: 'text', text: JSON.stringify(res, null, 2) }] }
          }));
      }

      return this.arsenal.executeTool(name, toolArgs)
        .then(res => ({
          jsonrpc: '2.0',
          id,
          result: { content: [{ type: 'text', text: JSON.stringify(res, null, 2) }] }
        }))
        .catch(err => ({
          jsonrpc: '2.0',
          id,
          error: { code: -32603, message: err.message }
        }));
    }

    return {
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Method '${method}' not found` }
    };
  }

  startStdioListener() {
    process.stdin.on('data', (data) => {
      const lines = data.toString().split('\n').filter(Boolean);
      for (const line of lines) {
        const response = this.handleMessage(line);
        if (response && typeof response.then === 'function') {
          response.then(res => console.log(JSON.stringify(res)));
        } else if (response) {
          console.log(JSON.stringify(response));
        }
      }
    });
  }
}

module.exports = { MCPServer };
