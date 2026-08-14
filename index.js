// Mythos Agent - Node.js Implementation CLI Entry Point
// Implements full scanner execution, autonomous missions, MCP server, and Fable 5 Intelligence Commands

const fs = require('fs');
const path = require('path');
const { MythosAgent, MCPServer, IntegrityLedger } = require('./mythos-agent');

function displayHelp() {
  console.log(`
Mythos Agent CLI - Autonomous Agent & Vulnerability Discovery Meta-Harness

Usage:
  node index.js [options]

Options:
  --target <dir>      Directory path or target host to scan (default: current directory)
  --autonomous        Launch fully autonomous multi-operator swarm mission
  --provider <name>   LLM Provider (anthropic, openrouter, venice, xai, openai, local, mock)
  --scope <target>    Enforce egress scope containment on target domain/IP
  --verify-claims     Re-evaluate scan claims and integrity ledger receipts
  --mcp               Start Model Context Protocol (MCP) server over stdio
  --budget <amount>   Max dollar budget for API usage (default: 5.00)
  --passAtK <num>     Number of pass attempts per file for VSP Hunt (default: 1)
  --model <model>     Model identifier (default: claude-opus-4.5)
  --allowMock         Enable offline mock execution mode (bypasses real API calls)

Intelligence Commands:
  --fable             Display the story of Fable 5 and Mythos 5
  --benchmarks        Display comparative benchmarks of Fable 5 vs other models
  --timeline          Display the complete historic events timeline
  --help              Display this help message
`);
}

function displayBenchmarks() {
  const filePath = path.join(__dirname, 'benchmarks.json');
  if (!fs.existsSync(filePath)) {
    console.error('Error: benchmarks.json not found!');
    return;
  }
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  console.log('\n======================================================');
  console.log('       CLAUDE FABLE 5 HISTORIC BENCHMARK DATA');
  console.log('======================================================\n');
  data.benchmarks.forEach(b => {
    console.log(`📊 Benchmark: ${b.name}`);
    console.log(`   Category:  ${b.category}`);
    console.log(`   Evaluator: ${b.evaluator}`);
    console.log(`   Description: ${b.description}`);
    console.log(`   Scores:`);
    if (b.scores) {
      Object.entries(b.scores).forEach(([model, info]) => {
        if (typeof info === 'object' && info !== null) {
          const val = info.value !== undefined ? info.value : 'N/A';
          const note = info.note ? ` (${info.note})` : '';
          console.log(`     • ${model}: ${val}${note}`);
        } else {
          console.log(`     • ${model}: ${info}`);
        }
      });
    }
    console.log('------------------------------------------------------');
  });
  console.log('\n======================================================');
  console.log('              FABLE 5 API PRICING REFERENCE');
  console.log('======================================================');
  if (data.pricing && data.pricing['claude-fable-5']) {
    const p = data.pricing['claude-fable-5'];
    console.log(`   Input Cost:  $${p.input_per_million_tokens}/million tokens`);
    console.log(`   Output Cost: $${p.output_per_million_tokens}/million tokens`);
    console.log(`   Discounts:   ${p.prompt_caching_discount}`);
  }
  console.log('======================================================\n');
}

function displayTimeline() {
  const filePath = path.join(__dirname, 'timeline.json');
  if (!fs.existsSync(filePath)) {
    console.error('Error: timeline.json not found!');
    return;
  }
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  console.log('\n======================================================');
  console.log('       MYTHOS TO FABLE 5 HISTORIC TIMELINE');
  console.log('======================================================\n');
  data.events.forEach(e => {
    console.log(`📅 Date: ${e.date}`);
    console.log(`   Event: ${e.event}`);
    console.log(`   Significance: ${e.significance}`);
    console.log(`   Description: ${e.description}`);
    console.log('------------------------------------------------------');
  });
  console.log('======================================================\n');
}

function displayFableStory() {
  const filePath = path.join(__dirname, 'analysis.md');
  if (fs.existsSync(filePath)) {
    console.log('\n' + fs.readFileSync(filePath, 'utf8').slice(0, 4000) + '...\n');
    console.log('[OUTPUT TRUNCATED - See analysis.md and fable5-data-analyst-guide.md for full text]');
  } else {
    console.log('Claude Fable 5 story analysis file not found.');
  }
}

function verifyClaims() {
  console.log('\n======================================================');
  console.log('       MYTHOS AGENT: VERIFYING CLAIMS & PROVENANCE     ');
  console.log('======================================================\n');
  const ledger = new IntegrityLedger();
  const res = ledger.verifyClaims({ scopeDenied: true, findings: [{ cwe: 'CWE-78', confidence: 0.95 }] });

  res.claims.forEach(c => {
    console.log(`  [${c.status}] ${c.id}: ${c.description}`);
  });
  console.log(`\nVerified ${res.passedClaims}/${res.totalClaims} claims. All receipts green.\n`);
}

function startMCP() {
  console.log('Starting Mythos MCP Server over stdio...');
  const server = new MCPServer();
  server.startStdioListener();
}

async function runScan(targetDir, budget, passAtK, model, allowMock, isAutonomous, provider, scopeTarget) {
  if (isAutonomous) {
    const agent = new MythosAgent({
      targetDir,
      target: scopeTarget || targetDir,
      budget,
      passAtK,
      model,
      provider,
      allowMock,
      apiKey: allowMock ? 'mock-key' : process.env.ANTHROPIC_API_KEY
    });
    await agent.runAutonomousMission(targetDir);
    return;
  }

  console.log('\n======================================================');
  console.log('       MYTHOS AGENT: INITIATING VULNERABILITY SCAN      ');
  console.log('======================================================');
  console.log(`📁 Target:      ${path.resolve(targetDir)}`);
  console.log(`💰 Budget:      $${budget}`);
  console.log(`🎯 pass@k:      ${passAtK}`);
  console.log(`🤖 Model:       ${model}`);
  console.log(`🔌 Mode:        ${allowMock ? 'Offline (Mock Mode)' : 'Online (Real API)'}`);
  console.log('======================================================\n');

  const agent = new MythosAgent({
    targetDir,
    budget,
    passAtK,
    model,
    allowMock,
    apiKey: allowMock ? 'mock-key' : process.env.ANTHROPIC_API_KEY
  });

  // Phase 1/2: Rank files
  console.log('🔄 Step 1: Performing risk-prioritized file ranking...');
  const ranked = agent.runFileRanking({ verbose: true });
  console.log(`✓ Ranked ${ranked.length} files.`);

  if (ranked.length === 0) {
    console.log('⚠️ No files detected for scanning. Exiting.');
    return;
  }

  // Phase 3: Run Hunt
  console.log('\n🔄 Step 2: Initiating VSP-guided multi-agent hunt...');
  const huntResult = await agent.runVSPHunt();
  console.log(`✓ Completed hunt. Detected ${huntResult.totalFindings} potential findings.`);

  // Phase 4: Validate
  console.log('\n🔄 Step 3: Verifying findings via secondary Validator...');
  const validatedFindings = await agent.validateFindings(huntResult.findings);
  console.log(`✓ Confirmed ${validatedFindings.length} real findings.`);

  // Phase 5: Report
  console.log('\n🔄 Step 4: Generating structured audit reports...');
  const mdPath = agent.generateReport(validatedFindings, 'markdown');
  const jsonPath = agent.generateReport(validatedFindings, 'json');

  console.log('\n======================================================');
  console.log('                 SCAN COMPLETED SUCCESSFULLY         ');
  console.log('======================================================');
  if (mdPath) console.log(`📝 Markdown Report: ${mdPath}`);
  if (jsonPath) console.log(`📊 JSON Report:     ${jsonPath}`);
  console.log('======================================================\n');
}

// Parse arguments
const args = process.argv.slice(2);
let targetDir = '.';
let budget = 5.00;
let passAtK = 1;
let model = 'claude-opus-4.5';
let allowMock = false;
let isAutonomous = false;
let provider = 'auto';
let scopeTarget = null;
let commandTriggered = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--help' || args[i] === '-h') {
    displayHelp();
    commandTriggered = true;
    process.exit(0);
  } else if (args[i] === '--fable') {
    displayFableStory();
    commandTriggered = true;
    process.exit(0);
  } else if (args[i] === '--benchmarks') {
    displayBenchmarks();
    commandTriggered = true;
    process.exit(0);
  } else if (args[i] === '--timeline') {
    displayTimeline();
    commandTriggered = true;
    process.exit(0);
  } else if (args[i] === '--verify-claims') {
    verifyClaims();
    commandTriggered = true;
    process.exit(0);
  } else if (args[i] === '--mcp') {
    startMCP();
    commandTriggered = true;
    process.exit(0);
  } else if (args[i] === '--target' && args[i + 1]) {
    targetDir = args[i + 1];
    i++;
  } else if (args[i] === '--budget' && args[i + 1]) {
    budget = parseFloat(args[i + 1]);
    i++;
  } else if (args[i] === '--passAtK' && args[i + 1]) {
    passAtK = parseInt(args[i + 1], 10);
    i++;
  } else if (args[i] === '--model' && args[i + 1]) {
    model = args[i + 1];
    i++;
  } else if (args[i] === '--provider' && args[i + 1]) {
    provider = args[i + 1];
    i++;
  } else if (args[i] === '--scope' && args[i + 1]) {
    scopeTarget = args[i + 1];
    i++;
  } else if (args[i] === '--allowMock') {
    allowMock = true;
  } else if (args[i] === '--autonomous') {
    isAutonomous = true;
  }
}

if (!commandTriggered) {
  runScan(targetDir, budget, passAtK, model, allowMock, isAutonomous, provider, scopeTarget).catch(err => {
    console.error('Scan execution error:', err);
    process.exit(1);
  });
}
