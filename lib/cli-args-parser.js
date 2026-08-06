// Optimized CLI argument parser for Mythos Agent
// Parses command line parameters, targets, filters, and formats.

function parseCLIArgs(args = []) {
  const options = {
    targetDir: '.',
    minRank: 1,
    format: 'console',
    output: null,
    files: null
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
