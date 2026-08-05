/**
 * Mythos Agent - CLI Enhancements
 * Progress bars, output formatters, filters, and watch mode
 */

const fs = require('fs');
const path = require('path');

/**
 * Severity levels for filtering
 */
const SEVERITY_ORDER = {
  'CRITICAL': 5,
  'HIGH': 4,
  'MEDIUM': 3,
  'LOW': 2,
  'INFO': 1
};

/**
 * Simple progress bar implementation for terminal
 */
class ProgressBar {
  constructor(total, options = {}) {
    this.total = total;
    this.current = 0;
    this.prefix = options.prefix || '';
    this.suffix = options.suffix || '';
    this.width = options.width || 30;
    this.enabled = options.enabled !== false;
  }

  tick(message = '') {
    this.current++;
    if (this.enabled) {
      const percent = (this.current / this.total) * 100;
      const filled = Math.round((this.width * this.current) / this.total);
      const empty = this.width - filled;
      const bar = '█'.repeat(filled) + '░'.repeat(empty);
      process.stdout.write(`\r${this.prefix}[${bar}] ${percent.toFixed(1)}% ${message}${this.suffix}`);
      if (this.current >= this.total) {
        process.stdout.write('\n');
      }
    }
  }

  update(current, message = '') {
    this.current = current;
    if (this.enabled) {
      const percent = (this.current / this.total) * 100;
      const filled = Math.round((this.width * this.current) / this.total);
      const empty = this.width - filled;
      const bar = '█'.repeat(filled) + '░'.repeat(empty);
      process.stdout.write(`\r${this.prefix}[${bar}] ${percent.toFixed(1)}% ${message}${this.suffix}`);
      if (this.current >= this.total) {
        process.stdout.write('\n');
      }
    }
  }

  done(message = '') {
    this.current = this.total;
    if (this.enabled) {
      const bar = '█'.repeat(this.width);
      process.stdout.write(`\r${this.prefix}[${bar}] 100% ${message}\n`);
    }
  }
}

/**
 * Status indicators for phase output
 */
const StatusIcons = {
  PENDING: '⏳',
  RUNNING: '🔄',
  SUCCESS: '✅',
  ERROR: '❌',
  WARNING: '⚠️',
  INFO: 'ℹ️'
};

/**
 * Format findings as JSON
 */
function formatJSON(findings, options = {}) {
  const {
    includeMetadata = true,
    includeCodeSnippet = true,
    minSeverity = null,
    categories = null
  } = options;

  let filtered = findings;

  if (minSeverity) {
    const minLevel = SEVERITY_ORDER[minSeverity.toUpperCase()] || 0;
    filtered = filtered.filter(f => SEVERITY_ORDER[f.severity] >= minLevel);
  }

  if (categories) {
    const cats = categories.split(',').map(c => c.trim().toLowerCase());
    filtered = filtered.filter(f => cats.includes(f.category?.toLowerCase()));
  }

  return JSON.stringify(filtered, null, 2);
}

/**
 * Format findings as Markdown report
 */
function formatMarkdown(findings, options = {}) {
  const {
    includeMetadata = true,
    includeCodeSnippet = true,
    minSeverity = null,
    categories = null,
    summary = true
  } = options;

  let filtered = findings;

  if (minSeverity) {
    const minLevel = SEVERITY_ORDER[minSeverity.toUpperCase()] || 0;
    filtered = filtered.filter(f => SEVERITY_ORDER[f.severity] >= minLevel);
  }

  if (categories) {
    const cats = categories.split(',').map(c => c.trim().toLowerCase());
    filtered = filtered.filter(f => cats.includes(f.category?.toLowerCase()));
  }

  let md = '# Mythos Agent Vulnerability Report\n\n';
  md += `**Generated:** ${new Date().toISOString()}\n\n`;

  if (summary) {
    md += '## Summary\n\n';
    const bySeverity = {};
    filtered.forEach(f => {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    });

    md += '| Severity | Count |\n';
    md += '|----------|-------|\n';
    Object.entries(bySeverity).sort((a, b) => SEVERITY_ORDER[b[0]] - SEVERITY_ORDER[a[0]]).forEach(([severity, count]) => {
      md += `| ${severity} | ${count} |\n`;
    });
    md += `| **Total** | **${filtered.length}** |\n\n`;

    if (options.costInfo) {
      md += `**Scan Cost:** $${options.costInfo.toFixed(2)}\n\n`;
    }
  }

  if (filtered.length === 0) {
    md += '## Findings\n\n';
    md += 'No vulnerabilities found matching the specified criteria.\n\n';
    return md;
  }

  md += '## Findings\n\n';

  // Group by severity
  const grouped = {};
  filtered.forEach(f => {
    if (!grouped[f.severity]) grouped[f.severity] = [];
    grouped[f.severity].push(f);
  });

  const severityOrder = Object.keys(grouped).sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a]);

  severityOrder.forEach(severity => {
    md += `### ${severity}\n\n`;

    grouped[severity].forEach((finding, idx) => {
      md += `### ${severity} #${idx + 1}: ${finding.name || finding.pattern}\n\n`;

      if (finding.description) {
        md += `**Description:** ${finding.description}\n\n`;
      }

      md += `- **Severity:** ${finding.severity}\n`;
      md += `- **Category:** ${finding.category || 'uncategorized'}\n`;
      md += `- **Confidence:** ${((finding.confidence || 0.5) * 100).toFixed(0)}%\n`;
      md += `- **Location:** \`${finding.file || 'unknown'}\`\n`;

      if (finding.line) {
        md += `- **Line:** ${finding.line}\n`;
      }

      if (finding.cwe) {
        md += `- **CWE:** [${finding.cwe}](https://cwe.mitre.org/data/definitions/${finding.cwe.split('-')[1]}.html)\n`;
      }

      if (finding.remediation) {
        md += `\n**Remediation:** ${finding.remediation}\n`;
      }

      if (includeCodeSnippet && finding.codeSnippet) {
        md += `\n**Code Snippet:**\n\`\`\`javascript\n${finding.codeSnippet}\n\`\`\`\n`;
      }

      if (includeMetadata && finding.metadata) {
        md += `\n**Additional Context:**\n\`\`\`\n${JSON.stringify(finding.metadata, null, 2)}\n\`\`\`\n`;
      }

      md += '\n---\n\n';
    });
  });

  return md;
}

/**
 * Format findings as HTML report
 */
function formatHTML(findings, options = {}) {
  const {
    includeMetadata = true,
    includeCodeSnippet = true,
    minSeverity = null,
    categories = null,
    title = 'Mythos Agent Vulnerability Report'
  } = options;

  let filtered = findings;

  if (minSeverity) {
    const minLevel = SEVERITY_ORDER[minSeverity.toUpperCase()] || 0;
    filtered = filtered.filter(f => SEVERITY_ORDER[f.severity] >= minLevel);
  }

  if (categories) {
    const cats = categories.split(',').map(c => c.trim().toLowerCase());
    filtered = filtered.filter(f => cats.includes(f.category?.toLowerCase()));
  }

  // Group by severity
  const grouped = {};
  filtered.forEach(f => {
    if (!grouped[f.severity]) grouped[f.severity] = [];
    grouped[f.severity].push(f);
  });

  const severityOrder = Object.keys(grouped).sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a]);

  // Count by severity for summary
  const bySeverity = {};
  filtered.forEach(f => {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  });

  const severityColors = {
    'CRITICAL': '#dc3545',
    'HIGH': '#fd7e14',
    'MEDIUM': '#ffc107',
    'LOW': '#28a745',
    'INFO': '#17a2b8'
  };

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 { margin: 0 0 10px 0; }
        .header p { opacity: 0.9; margin: 0; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card.critical { border-left: 4px solid #dc3545; }
        .summary-card.high { border-left: 4px solid #fd7e14; }
        .summary-card.medium { border-left: 4px solid #ffc107; }
        .summary-card.low { border-left: 4px solid #28a745; }
        .summary-card .count {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }
        .summary-card .label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        .finding {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        .finding-header {
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-header.critical { border-left: 4px solid #dc3545; }
        .finding-header.high { border-left: 4px solid #fd7e14; }
        .finding-header.medium { border-left: 4px solid #ffc107; }
        .finding-header.low { border-left: 4px solid ${severityColors.LOW}; }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #28a745; }
        .finding-body {
            padding: 20px;
        }
        .finding-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }
        .meta-item {
            background: #f8f9fa;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .meta-item strong { color: #667eea; }
        .code-snippet {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            margin: 15px 0;
        }
        .remediation {
            background: #e8f5e9;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin-top: 15px;
            border-radius: 0 4px 4px 0;
        }
        .no-findings {
            text-align: center;
            padding: 60px 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .no-findings p {
            font-size: 1.2em;
            color: #666;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
        @media print {
            body { background: white; }
            .summary, .finding { box-shadow: none; border: 1px solid #ddd; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 ${title}</h1>
        <p>Generated: ${new Date().toLocaleString()}</p>
        ${options.costInfo ? `<p style="margin-top:10px;"><strong>Scan Cost:</strong> $${options.costInfo.toFixed(2)}</p>` : ''}
    </div>

    <div class="summary">
        ${severityOrder.map(severity => `
        <div class="summary-card ${severity.toLowerCase()}">
            <div class="count">${bySeverity[severity]}</div>
            <div class="label">${severity}</div>
        </div>
        `).join('')}
    </div>
`;

  if (filtered.length === 0) {
    html += `
    <div class="no-findings">
        <p>✅ No vulnerabilities found matching the specified criteria.</p>
    </div>
    `;
  } else {
    html += `<h2 style="margin-bottom:20px;">Findings</h2>`;

    severityOrder.forEach(severity => {
      grouped[severity].forEach((finding, idx) => {
        const findingId = `${severity.toLowerCase()}-${idx + 1}`;

        html += `
        <div class="finding" id="${findingId}">
            <div class="finding-header ${severity.toLowerCase()}">
                <div>
                    <span class="severity-badge ${severity.toLowerCase()}">${severity}</span>
                    <strong style="margin-left:12px;">${finding.name || finding.pattern || 'Unknown Pattern'}</strong>
                </div>
            </div>
            <div class="finding-body">
                ${finding.description ? `<p>${finding.description}</p>` : ''}

                <div class="finding-meta">
                    <div class="meta-item"><strong>Category:</strong> ${finding.category || 'uncategorized'}</div>
                    <div class="meta-item"><strong>Confidence:</strong> ${((finding.confidence || 0.5) * 100).toFixed(0)}%</div>
                    <div class="meta-item"><strong>Location:</strong> ${finding.file || 'unknown'}</div>
                    ${finding.line ? `<div class="meta-item"><strong>Line:</strong> ${finding.line}</div>` : ''}
                    ${finding.cwe ? `<div class="meta-item"><strong>CWE:</strong> ${finding.cwe}</div>` : ''}
                </div>

                ${includeCodeSnippet && finding.codeSnippet ? `
                <div class="code-snippet">${escapeHtml(finding.codeSnippet)}</div>
                ` : ''}

                ${finding.remediation ? `
                <div class="remediation">
                    <strong>✅ Remediation:</strong> ${finding.remediation}
                </div>
                ` : ''}

                ${includeMetadata && finding.metadata ? `
                <details style="margin-top:15px;">
                    <summary><strong>Additional Metadata</strong></summary>
                    <pre style="background:#f8f9fa;padding:15px;border-radius:4px;overflow-x:auto;font-size:0.85em;">${JSON.stringify(finding.metadata, null, 2)}</pre>
                </details>
                ` : ''}
            </div>
        </div>
        `;
      });
    });
  }

  html += `
    <div class="footer">
        <p>Mythos Agent - 8-Phase Vulnerability Discovery Scaffold</p>
    </div>
</body>
</html>`;

  return html;
}

/**
 * Helper to escape HTML special characters
 */
function escapeHtml(text) {
  const escapeMap = {
    '&': '&',
    '<': '<',
    '>': '>',
    '"': '"',
    "'": '&apos;'
  };
  return text.replace(/[&<>'"]/g, char => escapeMap[char]);
}

/**
 * Filter findings by severity
 */
function filterBySeverity(findings, minSeverity) {
  const minLevel = SEVERITY_ORDER[minSeverity.toUpperCase()];
  if (!minLevel) return findings;

  return findings.filter(f => SEVERITY_ORDER[f.severity] >= minLevel);
}

/**
 * Filter findings by category
 */
function filterByCategory(findings, categories) {
  const cats = categories.split(',').map(c => c.trim().toLowerCase());
  return findings.filter(f => cats.includes(f.category?.toLowerCase()));
}

/**
 * Filter findings by confidence threshold
 */
function filterByConfidence(findings, minConfidence) {
  return findings.filter(f => (f.confidence || 0) >= minConfidence);
}

/**
 * Apply date badge for watch mode
 */
function addTimestamp(findings) {
  const timestamp = new Date().toISOString();
  return findings.map(f => ({
    ...f,
    scannedAt: timestamp
  }));
}

/**
 * Format findings for console output (default format)
 */
function formatConsole(findings, options = {}) {
  const {
    includeCodeSnippet = true,
    minSeverity = null,
    categories = null,
    maxCodeLines = 3
  } = options;

  let filtered = findings;

  if (minSeverity) {
    const minLevel = SEVERITY_ORDER[minSeverity.toUpperCase()] || 0;
    filtered = filtered.filter(f => SEVERITY_ORDER[f.severity] >= minLevel);
  }

  if (categories) {
    const cats = categories.split(',').map(c => c.trim().toLowerCase());
    filtered = filtered.filter(f => cats.includes(f.category?.toLowerCase()));
  }

  if (filtered.length === 0) {
    console.log('\n✅ No vulnerabilities found matching the specified criteria.\n');
    return '';
  }

  // Summary
  const bySeverity = {};
  filtered.forEach(f => {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  });

  console.log('\n📊 Summary:');
  console.log('─'.repeat(50));

  Object.entries(bySeverity).sort((a, b) => SEVERITY_ORDER[b[0]] - SEVERITY_ORDER[a[0]]).forEach(([severity, count]) => {
    const icon = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : severity === 'MEDIUM' ? '🟡' : '🟢';
    console.log(`  ${icon} ${severity}: ${count}`);
  });
  console.log(`  Total: ${filtered.length}`);
  console.log('─'.repeat(50));

  // Findings
  console.log('\n📋 Findings:\n');

  // Group by severity
  const grouped = {};
  filtered.forEach(f => {
    if (!grouped[f.severity]) grouped[f.severity] = [];
    grouped[f.severity].push(f);
  });

  const severityOrder = Object.keys(grouped).sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a]);

  severityOrder.forEach((severity, sIdx) => {
    const icon = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : severity === 'MEDIUM' ? '🟡' : '🟢';
    console.log(`${icon} [${severity}]\n`);

    grouped[severity].forEach((finding, idx) => {
      const id = `${sIdx + 1}.${idx + 1}`;
      console.log(`  ${id}. ${finding.name || finding.pattern || 'Unknown'}`);
      console.log(`     📁 File: ${finding.file || 'unknown'}`);

      if (finding.line) {
        console.log(`     📍 Line: ${finding.line}`);
      }

      console.log(`     🏷️ Category: ${finding.category || 'uncategorized'}`);
      console.log(`     📊 Confidence: ${((finding.confidence || 0.5) * 100).toFixed(0)}%`);

      if (finding.description) {
        console.log(`     💬 ${finding.description}`);
      }

      if (finding.cwe) {
        console.log(`     🔗 CWE: ${finding.cwe}`);
      }

      if (finding.remediation) {
        console.log(`     ✅ ${finding.remediation}`);
      }

      if (includeCodeSnippet && finding.codeSnippet) {
        const lines = finding.codeSnippet.split('\n').slice(0, maxCodeLines);
        console.log(`     [90m${lines.join('\n     ')}${lines.length === maxCodeLines ? '...' : ''}[0m`);
      }

      console.log('');
    });
  });

  return '';
}

/**
 * Save report to file
 */
function saveReport(content, outputPath, format = 'json') {
  const ext = path.extname(outputPath);
  const actualPath = ext ? outputPath : `${outputPath}.${format}`;

  const dir = path.dirname(actualPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(actualPath, content, 'utf-8');
  return actualPath;
}

module.exports = {
  // Classes
  ProgressBar,
  StatusIcons,
  SEVERITY_ORDER,

  // Formatters
  formatJSON,
  formatMarkdown,
  formatHTML,
  formatConsole,

  // Filters
  filterBySeverity,
  filterByCategory,
  filterByConfidence,
  addTimestamp,

  // File operations
  saveReport
};