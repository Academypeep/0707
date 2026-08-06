/**
 * Cost Dashboard, Metrics, and Trend Analysis Engine
 * Visualizes/aggregates cost allocations and tracks vulnerability trends over time.
 */

const fs = require('fs');
const path = require('path');

class MetricsDashboard {
  constructor(options = {}) {
    this.historyFile = options.historyFile || './reports/scan_history.json';
  }

  /**
   * Log a new completed scan to tracking history
   */
  logScan(scanSummary) {
    const dir = path.dirname(this.historyFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    let history = [];
    if (fs.existsSync(this.historyFile)) {
      try {
        history = JSON.parse(fs.readFileSync(this.historyFile, 'utf8'));
      } catch (e) {
        history = [];
      }
    }

    const entry = {
      timestamp: new Date().toISOString(),
      findingsCount: scanSummary.findingsCount || 0,
      costUSD: scanSummary.costUSD || 0,
      durationSeconds: scanSummary.durationSeconds || 0,
      severities: scanSummary.severities || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    };

    history.push(entry);
    fs.writeFileSync(this.historyFile, JSON.stringify(history, null, 2), 'utf8');
    return entry;
  }

  /**
   * Generate cost utilization analytics and trend charts
   */
  generateTrendAnalysis() {
    if (!fs.existsSync(this.historyFile)) {
      return { status: 'no_history', message: 'No historical scans logged yet.' };
    }

    const history = JSON.parse(fs.readFileSync(this.historyFile, 'utf8'));
    if (history.length === 0) {
      return { status: 'empty_history' };
    }

    const totalCost = history.reduce((sum, s) => sum + s.costUSD, 0);
    const avgCost = totalCost / history.length;
    const totalFindings = history.reduce((sum, s) => sum + s.findingsCount, 0);

    // Severity growth over time
    const trends = history.map(h => ({
      date: h.timestamp.split('T')[0],
      findings: h.findingsCount,
      cost: h.costUSD
    }));

    return {
      scanCount: history.length,
      aggregateUSD: parseFloat(totalCost.toFixed(4)),
      averageCostUSD: parseFloat(avgCost.toFixed(4)),
      totalFindingsFound: totalFindings,
      trends
    };
  }
}

module.exports = { MetricsDashboard };
