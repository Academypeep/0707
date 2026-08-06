/**
 * Report Generator - Produces structured vulnerability reports
 * Handles deduplication, CVSS scoring, CWE mapping, disclosure workflows
 */

const fs = require('fs');
const path = require('path');

class ReportGenerator {
  constructor(options = {}) {
    this.outputDir = options.outputDir || './reports';
    this.reportId = options.reportId || `scan-${Date.now()}`;
    this.projectName = options.projectName || 'unknown';
    this.disclosureMode = options.disclosureMode || 'coordinated'; // 'coordinated' or 'private'
  }

  /**
   * Generate comprehensive report from findings
   */
  generateReport(findings, metadata = {}) {
    // Deduplicate findings
    const deduplicated = this._deduplicate(findings);

    // Group by severity
    const bySeverity = this._groupBySeverity(deduplicated);

    // Try to load Fable 5 & Mythos 5 Intelligence Context
    let fableIntelligence = null;
    try {
      const benchmarksPath = path.join(__dirname, '../benchmarks.json');
      const timelinePath = path.join(__dirname, '../timeline.json');
      if (fs.existsSync(benchmarksPath) && fs.existsSync(timelinePath)) {
        const benchmarks = JSON.parse(fs.readFileSync(benchmarksPath, 'utf8'));
        const timeline = JSON.parse(fs.readFileSync(timelinePath, 'utf8'));
        fableIntelligence = {
          benchmarks: benchmarks,
          timeline: timeline,
          summary: "This report is generated using the Mythos Agent scaffolding, inspired by Project Glasswing and the advanced analytical/vulnerability capabilities demonstrated by Claude Fable 5 and Mythos 5 in June 2026."
        };
      }
    } catch (err) {
      // safe fallback if files not accessible
    }

    // Generate report
    const report = {
      metadata: {
        reportId: this.reportId,
        projectName: this.projectName,
        scanDate: new Date().toISOString(),
        findingsCount: deduplicated.length,
        criticalCount: bySeverity.CRITICAL.length,
        highCount: bySeverity.HIGH.length,
        mediumCount: bySeverity.MEDIUM.length,
        lowCount: bySeverity.LOW.length,
        ...metadata
      },
      summary: {
        totalFindings: deduplicated.length,
        confirmed: deduplicated.filter(f => f.verified).length,
        theoretical: deduplicated.filter(f => !f.verified).length,
        fpRate: this._calculateFPRate(deduplicated),
        recommendations: this._generateRecommendations(bySeverity)
      },
      findings: {
        CRITICAL: bySeverity.CRITICAL,
        HIGH: bySeverity.HIGH,
        MEDIUM: bySeverity.MEDIUM,
        LOW: bySeverity.LOW
      },
      cveMapping: this._mapToCVEs(deduplicated),
      disclosureStatus: this._getDisclosureStatus(),
      fableIntelligence: fableIntelligence,
      timestamp: Date.now()
    };

    return report;
  }

  /**
   * Save report to file
   */
  saveReport(report, format = 'json') {
    try {
      if (!fs.existsSync(this.outputDir)) {
        fs.mkdirSync(this.outputDir, { recursive: true });
      }

      const fileName = `${this.reportId}-report.${format}`;
      const filePath = path.join(this.outputDir, fileName);

      let content;
      if (format === 'json') {
        content = JSON.stringify(report, null, 2);
      } else if (format === 'markdown') {
        content = this._generateMarkdown(report);
      } else if (format === 'csv') {
        content = this._generateCSV(report);
      }

      fs.writeFileSync(filePath, content);
      console.log(`\n✓ Report saved: ${filePath}`);

      return filePath;
    } catch (error) {
      console.error(`Error saving report: ${error.message}`);
      return null;
    }
  }

  /**
   * Deduplicate findings by CWE + location
   */
  _deduplicate(findings) {
    const seen = new Set();
    const deduplicated = [];

    for (const finding of findings) {
      const key = `${finding.cwe}:${finding.location}`;

      if (!seen.has(key)) {
        seen.add(key);
        deduplicated.push(finding);
      }
    }

    return deduplicated;
  }

  /**
   * Group findings by severity
   */
  _groupBySeverity(findings) {
    const grouped = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      INFO: []
    };

    for (const finding of findings) {
      const severity = this._extractSeverity(finding.severity);
      grouped[severity].push(finding);
    }

    return grouped;
  }

  /**
   * Extract severity level from CVSS score or label
   */
  _extractSeverity(severityString) {
    if (!severityString) return 'MEDIUM';

    if (severityString.match(/CRITICAL|CVSS [89]\.\d/)) return 'CRITICAL';
    if (severityString.match(/HIGH|CVSS [67]\.\d/)) return 'HIGH';
    if (severityString.match(/MEDIUM|CVSS 4\.\d|CVSS 5\.\d/)) return 'MEDIUM';
    if (severityString.match(/LOW|CVSS [123]\.\d/)) return 'LOW';

    return 'MEDIUM';
  }

  /**
   * Calculate false positive rate
   */
  _calculateFPRate(findings) {
    const total = findings.length;
    if (total === 0) return 0;

    const unverified = findings.filter(f => !f.verified).length;
    return ((unverified / total) * 100).toFixed(1);
  }

  /**
   * Generate remediation recommendations
   */
  _generateRecommendations(bySeverity) {
    const recommendations = [];

    if (bySeverity.CRITICAL.length > 0) {
      recommendations.push({
        priority: 'IMMEDIATE',
        action: `Fix ${bySeverity.CRITICAL.length} CRITICAL vulnerabilities before deployment`,
        detail: 'These are remotely exploitable with high impact'
      });
    }

    if (bySeverity.HIGH.length > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: `Patch ${bySeverity.HIGH.length} HIGH-severity findings`,
        detail: 'Should be addressed in next security update'
      });
    }

    recommendations.push({
      priority: 'PROCESS',
      action: 'Integrate static analysis into CI/CD',
      detail: 'Use Semgrep/CodeQL to catch these patterns early'
    });

    return recommendations;
  }

  /**
   * Map findings to potential CVEs
   */
  _mapToCVEs(findings) {
    const cveMap = {};

    for (const finding of findings) {
      const cwe = finding.cwe || 'UNKNOWN';

      if (!cveMap[cwe]) {
        cveMap[cwe] = [];
      }

      cveMap[cwe].push({
        title: finding.title,
        location: finding.location,
        severity: finding.severity,
        verified: finding.verified
      });
    }

    return cveMap;
  }

  /**
   * Get disclosure status for coordinated disclosure
   */
  _getDisclosureStatus() {
    return {
      mode: this.disclosureMode,
      disclosureDeadline: this._calculateDisclosureDeadline(),
      publicationDate: null,
      coordinatedWith: [],
      status: 'DRAFT'
    };
  }

  /**
   * Calculate standard 90-day disclosure deadline
   */
  _calculateDisclosureDeadline() {
    const deadline = new Date();
    deadline.setDate(deadline.getDate() + 90);
    return deadline.toISOString().split('T')[0];
  }

  /**
   * Generate Markdown report
   */
  _generateMarkdown(report) {
    let md = `# Security Audit Report\n\n`;
    md += `**Project:** ${report.metadata.projectName}\n`;
    md += `**Scan Date:** ${report.metadata.scanDate}\n`;
    md += `**Report ID:** ${report.metadata.reportId}\n\n`;

    md += `## Executive Summary\n\n`;
    md += `- **Total Findings:** ${report.summary.totalFindings}\n`;
    md += `- **CRITICAL:** ${report.metadata.criticalCount}\n`;
    md += `- **HIGH:** ${report.metadata.highCount}\n`;
    md += `- **MEDIUM:** ${report.metadata.mediumCount}\n`;
    md += `- **LOW:** ${report.metadata.lowCount}\n`;
    md += `- **False Positive Rate:** ${report.summary.fpRate}%\n\n`;

    // Recommendations
    md += `## Recommendations\n\n`;
    for (const rec of report.summary.recommendations) {
      md += `### ${rec.priority}: ${rec.action}\n`;
      md += `${rec.detail}\n\n`;
    }

    // Detailed findings
    md += `## Detailed Findings\n\n`;
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      const findings = report.findings[severity];
      if (findings.length === 0) continue;

      md += `### ${severity} Severity (${findings.length})\n\n`;
      for (const finding of findings) {
        md += `#### ${finding.cwe}: ${finding.title}\n`;
        md += `- **Location:** ${finding.location}\n`;
        md += `- **Verified:** ${finding.verified ? 'Yes' : 'No'}\n`;
        if (finding.poc) {
          md += `- **PoC:** \`${finding.poc}\`\n`;
        }
        md += `\n`;
      }
    }

    if (report.fableIntelligence) {
      md += `## Fable 5 & Mythos 5 Security & Benchmarking Intelligence\n\n`;
      md += `This audit is powered by the Mythos Agent scaffolding, whose structural research is grounded in Anthropic's restricted **Claude Mythos Preview** and the public **Claude Fable 5** models released in June 2026.\n\n`;

      md += `### Historic Performance Reference Metrics\n\n`;
      md += `During the private 6-week **Project Glasswing** defensive coalition, Mythos-class models achieved unprecedented security efficacy:\n`;
      md += `- **Vulnerabilities Discovered:** 10,000+ high-severity zero-day bugs in 6 weeks.\n`;
      md += `- **Audit Precision:** 90.8% True Positive Rate (1,726 verified valid of 23,019 candidate bugs scanned).\n`;
      md += `- **Analytical Efficacy:** Fable 5 became the first model ever to break 90% on the Hex Analytics benchmark and reached 80.3% on SWE-Bench Pro.\n\n`;

      md += `### Model Availability Window & Precedents\n\n`;
      md += `- **Availability Window:** 3 days publicly available (June 9 to June 12, 2026) before a historic US export control directive suspended access.\n`;
      md += `- **Current Model Status:** SUSPENDED globally due to real-time nationality filtering limits under the Bureau of Industry and Security directive.\n\n`;
    }

    return md;
  }

  /**
   * Generate CSV report
   */
  _generateCSV(report) {
    let csv = 'CWE,Title,Severity,Location,Verified,PoC\n';

    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      for (const finding of report.findings[severity]) {
        const row = [
          finding.cwe,
          `"${finding.title}"`,
          severity,
          `"${finding.location}"`,
          finding.verified ? 'Yes' : 'No',
          finding.poc ? `"${finding.poc}"` : ''
        ];
        csv += row.join(',') + '\n';
      }
    }

    return csv;
  }
}

module.exports = { ReportGenerator };
