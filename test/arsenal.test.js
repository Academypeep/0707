const path = require('path');
const { Arsenal } = require('../lib/arsenal');
const { MCPServer } = require('../lib/mcp-server');

describe('Arsenal & MCPServer', () => {
  test('lists registered tools in Arsenal', () => {
    const arsenal = new Arsenal({ targetDir: path.resolve(__dirname, '..') });
    const list = arsenal.getToolsList();

    expect(list.length).toBeGreaterThanOrEqual(4);
    const names = list.map(t => t.name);
    expect(names).toContain('recon_network');
    expect(names).toContain('code_browser');
    expect(names).toContain('static_sink_scan');
    expect(names).toContain('sandbox_exec');
  });

  test('executes recon_network with scope containment', async () => {
    const arsenal = new Arsenal({ targetDir: path.resolve(__dirname, '..'), scope: { target: 'localhost' } });

    const allowedRes = await arsenal.executeTool('recon_network', { target: 'localhost', mode: 'http' });
    expect(allowedRes.status).toBe('success');

    const deniedRes = await arsenal.executeTool('recon_network', { target: 'unauthorized-site.com', mode: 'http' });
    expect(deniedRes.status).toBe('denied');
    expect(deniedRes.reason).toContain('SCOPE DENIED');
  });

  test('MCPServer handles initialize and tools/list requests', async () => {
    const server = new MCPServer();

    const initRes = server.handleMessage({ jsonrpc: '2.0', id: 1, method: 'initialize' });
    expect(initRes.result.serverInfo.name).toBe('mythos-mcp-server');

    const listRes = server.handleMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    expect(listRes.result.tools.some(t => t.name === 'security_recon')).toBe(true);
  });
});
