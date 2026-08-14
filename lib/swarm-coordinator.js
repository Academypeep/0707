// Swarm Coordinator & Multi-Operator Cell Engine
// Orchestrates multi-agent kill chain pipeline for autonomous missions

const { EgressScopeContainment } = require('./egress-scope');
const { LLMProvider } = require('./llm-provider');
const { Arsenal } = require('./arsenal');
const { HunterAgent } = require('./hunter-agent');
const { ValidatorAgent } = require('./validator-agent');
const { ReportGenerator } = require('./report-generator');
const { rankFiles } = require('./file-ranker');

class SwarmCoordinator {
  constructor(options = {}) {
    this.targetDir = options.targetDir || process.cwd();
    this.target = options.target || this.targetDir;
    this.budget = options.budget || 5.00;
    this.passAtK = options.passAtK || 1;

    const allowMock = options.allowMock !== undefined
      ? options.allowMock
      : (!options.apiKey && !process.env.ANTHROPIC_API_KEY);

    this.scope = new EgressScopeContainment({
      target: this.target,
      ...(options.scope || {})
    });

    this.llmProvider = new LLMProvider({
      provider: options.provider,
      model: options.model,
      apiKey: options.apiKey,
      allowMock
    });

    this.arsenal = new Arsenal({
      targetDir: this.targetDir,
      target: this.target,
      scope: options.scope
    });

    this.validator = new ValidatorAgent({
      targetDir: this.targetDir,
      model: options.model,
      apiKey: options.apiKey,
      allowMock
    });

    this.reportGen = new ReportGenerator({
      outputDir: options.reportDir || './reports',
      projectName: options.projectName || 'autonomous-mission'
    });

    this.operators = [
      'recon',
      'scanner',
      'exploiter',
      'infiltrator',
      'exfiltrator',
      'ghost',
      'coordinator',
      'analyst'
    ];
  }

  async executeMission(targetSpec = null) {
    const missionTarget = targetSpec || this.target;
    console.log(`\n======================================================`);
    console.log(`      SWARM COORDINATOR: INITIATING AUTONOMOUS MISSION  `);
    console.log(`======================================================`);
    console.log(`🎯 Target: ${missionTarget}`);
    console.log(`🤖 Provider: ${this.llmProvider.provider} (Model: ${this.llmProvider.model})`);
    console.log(`======================================================\n`);

    // Step 1: Egress Scope Containment Check
    const scopeCheck = this.scope.isAllowed(missionTarget);
    if (!scopeCheck.allowed) {
      console.warn(`[SWARM] Target blocked by scope containment: ${scopeCheck.reason}`);
      return { status: 'denied', reason: scopeCheck.reason, findings: [] };
    }

    const missionResults = {
      target: missionTarget,
      operatorsExecuted: [],
      findings: [],
      verifiedCount: 0
    };

    // Stage 1: Recon & Discovery
    console.log(`🔄 [Stage 1/4] Recon Operator: Target Discovery...`);
    const reconResult = await this.arsenal.executeTool('recon_network', { target: missionTarget });
    missionResults.operatorsExecuted.push('recon');

    // Stage 2: Scanning & VSP Hunt
    console.log(`🔄 [Stage 2/4] Scanner Operator: Static & Dynamic Analysis...`);
    const ranked = rankFiles(this.targetDir, { maxFiles: 5 });
    const hunter = new HunterAgent({
      targetDir: this.targetDir,
      model: this.llmProvider.model,
      apiKey: this.llmProvider.apiKey,
      allowMock: this.llmProvider.allowMock
    });

    const rawFindings = [];
    for (const item of ranked) {
      const fileFindings = await hunter.hunt(item.path, 'javascript');
      rawFindings.push(...fileFindings);
    }
    missionResults.operatorsExecuted.push('scanner');

    // Stage 3: Exploitation & PoC Validation
    console.log(`🔄 [Stage 3/4] Exploiter & Validator Operators: Verifying PoC...`);
    const validatedFindings = await this.validator.validateFindings(rawFindings);
    missionResults.operatorsExecuted.push('exploiter', 'validator');
    missionResults.findings = validatedFindings;
    missionResults.verifiedCount = validatedFindings.length;

    // Stage 4: Analyst Operator - Report Generation
    console.log(`🔄 [Stage 4/4] Analyst Operator: Synthesizing Findings Report...`);
    const reportPath = this.reportGen.saveReport(
      this.reportGen.generateReport(validatedFindings, { targetDir: this.targetDir }),
      'markdown'
    );
    missionResults.operatorsExecuted.push('analyst');
    missionResults.reportPath = reportPath;

    console.log(`\n======================================================`);
    console.log(`         AUTONOMOUS MISSION COMPLETED SUCCESSFULLY    `);
    console.log(`======================================================`);
    console.log(`✅ Operators Executed: ${missionResults.operatorsExecuted.join(', ')}`);
    console.log(`✅ Verified Findings:  ${missionResults.verifiedCount}`);
    console.log(`📝 Report File:        ${reportPath}`);
    console.log(`======================================================\n`);

    return missionResults;
  }
}

module.exports = { SwarmCoordinator };
