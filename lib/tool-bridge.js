/**
 * Static analysis tool bridge for Semgrep and CodeQL output.
 *
 * Converts raw static analysis results into concise prompt annotations
 * so the VSP prompt can incorporate sensor-based evidence.
 */
const fs = require('fs');
const path = require('path');

function parseSemgrepJson(raw) {
  const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!data || !Array.isArray(data.results)) {
    return [];
  }

  return data.results.map(result => {
    const pathString = result.path || result.extra?.metadata?.file || 'unknown';
    const line = result.start?.line || result.extra?.lines?.start || (result.extra?.end?.line ?? null);
    return {
      tool: 'semgrep',
      checkId: result.check_id || result.extra?.metadata?.id || 'unknown',
      message: result.extra?.message || result.extra?.metadata?.message || result.check_id || 'Static analysis finding',
      file: pathString,
      line,
      severity: result.extra?.severity || result.severity || 'MEDIUM',
      rule: result.check_id || result.extra?.metadata?.pattern_id || null,
      metadata: result
    };
  });
}

function parseSarif(raw) {
  const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!data || !Array.isArray(data.runs)) {
    return [];
  }

  const findings = [];
  for (const run of data.runs) {
    const toolName = run.tool?.driver?.name || 'codeql';
    for (const result of run.results || []) {
      const message = typeof result.message?.text === 'string'
        ? result.message.text
        : Array.isArray(result.message?.text)
          ? result.message.text.join(' ')
          : 'Static analysis finding';

      const location = result.locations?.[0]?.physicalLocation;
      const file = location?.artifactLocation?.uri || 'unknown';
      const line = location?.region?.startLine || null;
      const rule = result.ruleId || result.rule?.id || 'unknown';
      const severity = result.level || result.severity || 'WARNING';

      findings.push({
        tool: toolName,
        checkId: rule,
        message,
        file,
        line,
        severity,
        metadata: result
      });
    }
  }

  return findings;
}

function buildStaticAnalysisSummary(findings, filePath, maxItems = 5) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return '';
  }

  const fileFindings = findings.filter(item => item.file === filePath || item.file.endsWith(filePath));
  const chosen = fileFindings.length > 0 ? fileFindings : findings;
  const items = chosen.slice(0, maxItems);

  const lines = items.map(item => {
    const location = item.line ? `line ${item.line}` : 'unknown line';
    return `- [${item.tool.toUpperCase()}] ${item.file}:${location} ${item.checkId || ''} — ${item.message}`;
  });

  if (fileFindings.length === 0 && findings.length > 0) {
    lines.unshift(`No static results matched ${filePath}; showing top ${Math.min(maxItems, findings.length)} findings from the project.`);
  } else {
    lines.unshift(`Static analysis annotations for ${filePath}:`);
  }

  return lines.join('\n');
}

function loadStaticAnalysisFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Static analysis file not found: ${filePath}`);
  }

  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw);

  if (parsed.results) {
    return parseSemgrepJson(parsed);
  }

  if (parsed.runs) {
    return parseSarif(parsed);
  }

  throw new Error(`Unrecognized static analysis output format: ${filePath}`);
}

module.exports = {
  parseSemgrepJson,
  parseSarif,
  buildStaticAnalysisSummary,
  loadStaticAnalysisFile
};
