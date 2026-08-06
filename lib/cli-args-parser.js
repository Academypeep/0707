// Optimized CLI argument parser for Mythos Agent
// Parses command line parameters, targets, filters, and formats.

function parseCLIArgs(args = []) {
  const options = {
    targetDir: '.',
    minRank: 1,
    format: 'console',
    output: null,
    files: null,
    budget: 5.00,
    resume: false,
    passAtK: 1,
    entryPoint: null
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--target' || arg === '-t') {
      options.targetDir = args[++i] || '.';
    } else if (arg === '--min-rank' || arg === '-r') {
      options.minRank = parseInt(args[++i], 10) || 1;
    } else if (arg === '--format' || arg === '-f') {
      options.format = (args[++i] || 'console').toLowerCase();
    } else if (arg === '--output' || arg === '-o') {
      options.output = args[++i];
    } else if (arg === '--budget' || arg === '-b') {
      options.budget = parseFloat(args[++i]) || 5.00;
    } else if (arg === '--resume') {
      options.resume = true;
    } else if (arg === '--passAtK' || arg === '-k') {
      options.passAtK = parseInt(args[++i], 10) || 1;
    } else if (arg === '--entry-point' || arg === '-e') {
      options.entryPoint = args[++i];
    } else if (arg === '--files') {
      // Handles list of comma-separated or space-separated files
      const rawFiles = args[++i];
      if (rawFiles) {
        options.files = rawFiles.split(/[\s,]+/).filter(Boolean);
      }
    }
  }

  return options;
}

module.exports = { parseCLIArgs };
