/**
 * CostTracker Class
 * Calculates and manages real-time scan cost based on actual API token usages.
 */

class CostTracker {
  constructor(options = {}) {
    this.total = 0;
    this.tokens = 0;
    this.byPhase = {};
  }

  /**
   * Track usage metrics from an API call response
   */
  trackUsage(phase, usage) {
    if (!usage) return;

    const inputTokens = usage.input_tokens || 0;
    const outputTokens = usage.output_tokens || 0;

    // Approximate cost: $3.00 per million input, $15.00 per million output tokens
    const inputCost = (inputTokens / 1_000_000) * 3;
    const outputCost = (outputTokens / 1_000_000) * 15;
    const cost = inputCost + outputCost;

    this.total += cost;
    this.tokens += inputTokens + outputTokens;

    this.byPhase[phase] = (this.byPhase[phase] || 0) + cost;
  }

  /**
   * Track manual/flat costs for offline phases
   */
  trackFlatCost(phase, amount) {
    this.total += amount;
    this.byPhase[phase] = (this.byPhase[phase] || 0) + amount;
  }
}

module.exports = { CostTracker };
