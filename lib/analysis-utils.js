/**
 * Mythos Agent - Analysis Utilities
 * Sink identification, vulnerability pattern matching, and file scoring
 */

const fs = require('fs');
const path = require('path');

// ─── Known Dangerous Sinks ────────────────────────────────────────────────────

const SINK_DEFINITIONS = {
  // JavaScript / Node.js sinks
  'js': [
    {
      name: 'eval()',
      pattern: /\beval\s*\(/g,
      severity: 'CRITICAL',
      category: 'code-exec',
      cwe: 'CWE-95',
      description: 'eval() executes arbitrary JavaScript code from a string',
      remediation: 'Never use eval(). Use JSON.parse() for JSON, or structured alternatives for dynamic logic'
    },
    {
      name: 'Function() constructor',
      pattern: /\bnew\s+Function\s*\(/g,
      severity: 'CRITICAL',
      category: 'code-exec',
      cwe: 'CWE-95',
      description: 'new Function() is equivalent to eval() — it compiles and executes arbitrary code',
      remediation: 'Avoid dynamic code generation; use closures or higher-order functions instead'
    },
    {
      name: 'child_process.exec()',
      pattern: /\bexec\s*\(/g,
      severity: 'CRITICAL',
      category: 'command-exec',
      cwe: 'CWE-78',
      description: 'child_process.exec() spawns a shell, making it vulnerable to command injection',
      remediation: 'Use child_process.execFile() or child_process.spawn() with argument arrays'
    },
    {
      name: 'child_process.spawn()',
      pattern: /\bspawn\s*\(/g,
      severity: 'HIGH',
      category: 'command-exec',
      cwe: 'CWE-78',
      description: 'spawn() with unsanitized user input can lead to argument injection',
      remediation: 'Validate and sanitize all arguments; use allowlists for executable paths'
    },
    {
      name: 'os.system() / shell',
      pattern: /\bshell\s*\(/g,
      severity: 'HIGH',
      category: 'command-exec',
      cwe: 'CWE-78',
      description: 'Shell execution with unsanitized input',
      remediation: 'Use subprocess with argument lists instead of shell strings'
    },
    {
      name: 'child_process.execSync()',
      pattern: /\bexecSync\s*\(/g,
      severity: 'CRITICAL',
      category: 'command-exec',
      cwe: 'CWE-78',
      description: 'Synchronous shell execution vulnerable to command injection',
      remediation: 'Use execFileSync() with argument arrays, or avoid shell commands entirely'
    },
    {
      name: 'fs.readFile() with path traversal',
      pattern: /\breadFile\s*\(/g,
      severity: 'HIGH',
      category: 'path-traversal',
      cwe: 'CWE-22',
      description: 'File reads with unsanitized paths may allow path traversal attacks',
      remediation: 'Validate and normalize file paths with path.resolve() and path.normalize()'
    },
    {
      name: 'fs.writeFile() with path traversal',
      pattern: /\bwriteFile\s*\(/g,
      severity: 'HIGH',
      category: 'path-traversal',
      cwe: 'CWE-22',
      description: 'File writes with unsanitized paths may allow arbitrary file writes',
      remediation: 'Validate output paths; restrict writes to allowed directories'
    },
    {
      name: 'require() with dynamic path',
      pattern: /\brequire\s*\(\s*(?!['"])/,
      severity: 'HIGH',
      category: 'dynamic-require',
      cwe: 'CWE-427',
      description: 'Dynamic require() with computed paths may load unintended modules',
      remediation: 'Use static require() statements; validate dynamic paths against an allowlist'
    },
    {
      name: 'SQL injection via string concat',
      pattern: /(['"`]\s*\+\s*.*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)|(\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\s*\+\s*['"])/gi,
      severity: 'CRITICAL',
      category: 'sql-injection',
      cwe: 'CWE-89',
      description: 'SQL query built via string concatenation — likely vulnerable to SQL injection',
      remediation: 'Use parameterized queries / prepared statements; never concatenate user input into SQL'
    },
    {
      name: 'Hardcoded credentials',
      pattern: /(?:password|secret|apikey|api_key|token|credential)s?\s*[=:]\s*['"][^'"]{8,}['"]\s*(?:;|,|$)/gi,
      severity: 'CRITICAL',
      category: 'hardcoded-credentials',
      cwe: 'CWE-798',
      description: 'Hardcoded credentials in source code',
      remediation: 'Use environment variables or a secrets manager; never hardcode credentials'
    },
    {
      name: 'JWT signature verification off',
      pattern: /\bnoSignature\s*:\s*true|\bignoreExpiration\s*:\s*true|\balgorithms\s*:\s*\[\s*['"]none['"]/g,
      severity: 'CRITICAL',
      category: 'auth-bypass',
      cwe: 'CWE-347',
      description: 'JWT verification bypass — allowing unsigned or expired tokens',
      remediation: 'Always verify JWT signatures; explicitly specify allowed algorithms'
    },
    {
      name: 'Insecure deserialization',
      pattern: /\beval\s*\(\s*JSON\.parse\b|\bFunction\s*\(\s*['"`]return\s/,
      severity: 'HIGH',
      category: 'deserialization',
      cwe: 'CWE-502',
      description: 'Deserializing untrusted data into executable code',
      remediation: 'Use safe JSON parsing; never deserialize user input into executable code'
    },
    {
      name: 'Prototype pollution',
      pattern: /\b__proto__\b|\bconstructor\s*\[/g,
      severity: 'MEDIUM',
      category: 'prototype-pollution',
      cwe: 'CWE-1321',
      description: 'Unsafe assignment to __proto__ or constructor-prototype chain',
      remediation: 'Use Object.create(null) for user-controllable objects; freeze prototypes'
    },
    {
      name: 'Improper CORS config',
      pattern: /Access-Control-Allow-Origin\s*:\s*\*/,
      severity: 'MEDIUM',
      category: 'cors-misconfig',
      cwe: 'CWE-942',
      description: 'Wildcard CORS origin allows any domain to access resources',
      remediation: 'Restrict CORS to specific trusted origins'
    },
    {
      name: 'Insecure random for security',
      pattern: /\bMath\.random\b/g,
      severity: 'MEDIUM',
      category: 'weak-crypto',
      cwe: 'CWE-338',
      description: 'Math.random() is not cryptographically secure — predictable values',
      remediation: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive randomness'
    },
    {
      name: 'Weak hash for passwords',
      pattern: /\b(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|md5\s*\(|sha1\s*\()/gi,
      severity: 'HIGH',
      category: 'weak-crypto',
      cwe: 'CWE-328',
      description: 'MD5/SHA1 is cryptographically broken for password hashing',
      remediation: 'Use bcrypt, argon2, or scrypt for password hashing'
    },
    {
      name: 'SSRF via HTTP client',
      pattern: /\b(?:\.get|\.post|fetch|axios|request|superagent)\s*\(\s*(?:`|\$\{)/,
      severity: 'HIGH',
      category: 'ssrf',
      cwe: 'CWE-918',
      description: 'HTTP request URL built from user input — potential SSRF',
      remediation: 'Validate and sanitize URLs; use an allowlist of permitted hosts'
    },
    {
      name: 'Unsafe redirect',
      pattern: /\bredirect\s*\(\s*(?:req\.|request\.|params\.)/,
      severity: 'MEDIUM',
      category: 'open-redirect',
      cwe: 'CWE-601',
      description: 'Open redirect from user-controlled input',
      remediation: 'Validate redirect URLs against an allowlist of trusted destinations'
    },
    {
      name: 'XSS via innerHTML',
      pattern: /\binnerHTML\s*=\s*.*(?:\+|`.*\$\{)/,
      severity: 'HIGH',
      category: 'xss',
      cwe: 'CWE-79',
      description: 'Setting innerHTML with user-controlled content — potential XSS',
      remediation: 'Use textContent instead, or sanitize with DOMPurify before setting innerHTML'
    },
    {
      name: 'Missing CSRF protection',
      pattern: /(?:app\.|router\.)(?:post|put|delete|patch)\s*\(/,
      severity: 'MEDIUM',
      category: 'csrf',
      cwe: 'CWE-352',
      description: 'State-changing endpoint without visible CSRF protection',
      remediation: 'Use CSRF tokens or SameSite cookie attribute for state-changing operations'
    },
    {
      name: 'Logging sensitive data',
      pattern: /\bconsole\.(?:log|info|warn|error)\s*\(\s*.*\b(?:password|secret|token|key|credential)/i,
      severity: 'MEDIUM',
      category: 'info-disclosure',
      cwe: 'CWE-532',
      description: 'Sensitive data logged to console — may appear in production logs',
      remediation: 'Redact sensitive fields before logging; use structured logging with PII filtering'
    },
    {
      name: 'Unhandled promise rejection',
      pattern: /\.(?:then|catch)\s*\(\s*(?!\s*(?:\(|function)\s*[^)]*\))/,
      severity: 'LOW',
      category: 'error-handling',
      cwe: 'CWE-754',
      description: 'Potentially unhandled promise — could lead to silent failures',
      remediation: 'Always chain .catch() on promises; use try/catch with async/await'
    },
    {
      name: 'Global RegExp without reset',
      pattern: /\/(?!.*\/[gimsuy]*$)/,
      severity: 'INFO',
      category: 'logic',
      cwe: 'CWE-185',
      description: 'Global regex without reset can cause alternate-results bug when reused',
      remediation: 'Use regex.test() inside a helper that resets lastIndex, or avoid /g flag'
    },
  ],

  // Python sinks
  'py': [
    {
      name: 'eval() / exec()',
      pattern: /\b(?:eval|exec)\s*\(/g,
      severity: 'CRITICAL',
      category: 'code-exec',
      cwe: 'CWE-95',
      description: 'Dynamic code execution of arbitrary strings',
      remediation: 'Never use eval()/exec() with user input; use safe parsing alternatives'
    },
    {
      name: 'os.system() / subprocess shell=True',
      pattern: /\b(?:os\.system\s*\(|subprocess\.\w+\s*\(.*shell\s*=\s*True)/g,
      severity: 'CRITICAL',
      category: 'command-exec',
      cwe: 'CWE-78',
      description: 'Shell execution with unsanitized input',
      remediation: 'Use subprocess.run() with argument lists and shell=False'
    },
    {
      name: 'pickle.loads()',
      pattern: /\bpickle\.(?:loads?|Unpickler)\s*\(/g,
      severity: 'CRITICAL',
      category: 'deserialization',
      cwe: 'CWE-502',
      description: 'Unpickling untrusted data allows arbitrary code execution',
      remediation: 'Never unpickle data from untrusted sources; use JSON instead'
    },
    {
      name: 'yaml.load() unsafe',
      pattern: /\byaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.(?:Safe|CSafe)Loader)/,
      severity: 'HIGH',
      category: 'deserialization',
      cwe: 'CWE-502',
      description: 'yaml.load() without SafeLoader can instantiate arbitrary objects',
      remediation: 'Always use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader)'
    },
    {
      name: 'SQL via string formatting',
      pattern: /\bcursor\.execute\s*\(\s*f['"]/,
      severity: 'CRITICAL',
      category: 'sql-injection',
      cwe: 'CWE-89',
      description: 'SQL query built via f-string — likely SQL injection',
      remediation: 'Use parameterized queries: cursor.execute("SELECT ... WHERE x = %s", (val,))'
    },
    {
      name: 'Hardcoded secrets',
      pattern: /(?:\b(?:SECRET|PASSWORD|API_KEY|TOKEN)\s*=\s*['"][^'"]{8,}['"])/gi,
      severity: 'CRITICAL',
      category: 'hardcoded-credentials',
      cwe: 'CWE-798',
      description: 'Secrets hardcoded in source',
      remediation: 'Use environment variables, config files not tracked in VCS, or a secrets manager'
    },
    {
      name: 'Flask debug mode',
      pattern: /\b(?:DEBUG|debug)\s*=\s*True\b|\bapp\.run\s*\(\s*debug\s*=\s*True/,
      severity: 'HIGH',
      category: 'debug-enabled',
      cwe: 'CWE-489',
      description: 'Debug mode enabled in production — exposes stack traces and interactive debugger',
      remediation: 'Set DEBUG=False in production and use proper error logging'
    },
  ],
};

// ─── Vulnerability Patterns (content-level regex) ────────────────────────────

const VULNERABILITY_PATTERNS = [
  {
    name: 'SQL Injection - string concatenation',
    pattern: /(\w+)\s*=\s*`\s*SELECT[^`]*\$\{|(\w+)\s*=\s*['"]\s*SELECT[^'"]*['"]\s*\+/gi,
    severity: 'CRITICAL',
    category: 'sql-injection',
    cwe: 'CWE-89',
    confidence: 0.85
  },
  {
    name: 'Command Injection - template literal',
    pattern: /exec\s*\(\s*`[^`]*\$\{/g,
    severity: 'CRITICAL',
    category: 'command-exec',
    cwe: 'CWE-78',
    confidence: 0.90
  },
  {
    name: 'Path Traversal - unsanitized input',
    pattern: /path\.(?:join|resolve)\s*\(\s*__dirname\s*,\s*req\./,
    severity: 'HIGH',
    category: 'path-traversal',
    cwe: 'CWE-22',
    confidence: 0.75
  },
  {
    name: 'XSS - unsanitized template injection',
    pattern: /res\.(?:send|write)\s*\(\s*`[^`]*\$\{.*\.(?:body|query|params)/,
    severity: 'HIGH',
    category: 'xss',
    cwe: 'CWE-79',
    confidence: 0.80
  },
  {
    name: 'Insecure JWT config',
    pattern: /jwt\.(?:sign|verify)\s*\([^)]*\{[^}]*algorithms\s*:\s*\[\s*['"]none['"]/,
    severity: 'CRITICAL',
    category: 'auth-bypass',
    cwe: 'CWE-347',
    confidence: 0.95
  },
  {
    name: 'No input validation',
    pattern: /app\.(?:post|put|patch)\s*\([^)]*\)\s*\{[\s\S]{0,200}res\.(?:json|send|status)/,
    severity: 'MEDIUM',
    category: 'missing-validation',
    cwe: 'CWE-20',
    confidence: 0.50
  },
  {
    name: 'Rate limiting missing',
    pattern: /app\.(?:post|put|delete)\s*\(\s*['"]\/(?!.*\brate.*limit)/,
    severity: 'LOW',
    category: 'missing-rate-limit',
    cwe: 'CWE-770',
    confidence: 0.40
  },
  {
    name: 'Sensitive data in URL parameters',
    pattern: /\b(?:token|password|secret|apikey|key)\s*=\s*\$?\{.*params/,
    severity: 'HIGH',
    category: 'info-disclosure',
    cwe: 'CWE-598',
    confidence: 0.80
  },
];

// ─── Internet-facing / auth keyword signatures ───────────────────────────────

const INTERNET_FACING_PATTERNS = [
  // Express/Connect routes
  /\bapp\.(?:get|post|put|delete|patch|use)\s*\(/g,
  /\brouter\.(?:get|post|put|delete|patch|use)\s*\(/g,
  // Fastify routes
  /\.(?:get|post|put|delete|patch|head|options)\s*\(\s*['"]\/[^'"]*['"]/g,
  // Koa
  /\bctx\.(?:request|response|body|query|params)\b/g,
  // Flask/Django
  /\b@app\.route\b|\burlpatterns\s*=|@router\.(?:get|post|put|delete|patch)/g,
  // HTTP handler signatures
  /function\s+\w*\s*\(\s*(?:req|request|res|response)\b/g,
  /\b(?:req|request|res|response)\.(?:body|params|query|headers|method)\b/g,
];

const AUTH_PATTERNS = [
  // Authentication middleware
  /\b(?:authenticate|auth|login|signin|signup|register|logout|token|session)\b/i,
  /\b(?:jwt\.(?:verify|sign|decode)|passport\.|oauth|openid|saml|sso)\b/,
  /\b(?:password|hash|bcrypt|argon2|scrypt)\b/,
  /\b(?:authorize|cors|csrf|helmet|rateLimit|throttle)\b/,
  // Authorization decorators
  /@(?:Roles|Permissions|Authorize|Auth|Guard)/,
  // Middleware patterns
  /\.use\s*\(\s*(?:auth|authenticate|authorize|loginRequired|requireUser)/,
];

// ─── Sink Identification ─────────────────────────────────────────────────────

/**
 * Identify security-relevant sinks (dangerous function calls) in file content.
 * @param {string} content - File content
 * @param {string} filePath - Path to the file
 * @returns {Array<{name, severity, category, cwe, description, remediation, line, file}>}
 */
function identifySinks(content, filePath) {
  const ext = path.extname(filePath).slice(1).toLowerCase();
  const sinks = SINK_DEFINITIONS[ext] || SINK_DEFINITIONS['js'];
  const results = [];

  const lines = content.split('\n');

  for (const sink of sinks) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      sink.pattern.lastIndex = 0; // Reset global regex state
      if (sink.pattern.test(line)) {
        results.push({
          ...sink,
          line: i + 1,
          file: filePath,
          context: line.trim()
        });
        // Only report first occurrence per file for high-severity sinks
        if (sink.severity === 'CRITICAL') break;
      }
    }
  }

  return results;
}

// ─── Vulnerability Pattern Matching ──────────────────────────────────────────

/**
 * Match vulnerability patterns in file content.
 * @param {string} content - File content
 * @param {string} filePath - File path (optional, for context)
 * @returns {Array<{name, severity, category, cwe, confidence, line, file}>}
 */
function matchVulnerabilityPatterns(content, filePath) {
  const results = [];
  const lines = content.split('\n');

  for (const vp of VULNERABILITY_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      vp.pattern.lastIndex = 0;
      if (vp.pattern.test(line)) {
        results.push({
          name: vp.name,
          severity: vp.severity,
          category: vp.category,
          cwe: vp.cwe,
          confidence: vp.confidence,
          line: i + 1,
          file: filePath,
          codeSnippet: lines.slice(Math.max(0, i - 1), Math.min(lines.length, i + 2)).join('\n'),
          timestamp: new Date().toISOString()
        });
      }
    }
  }

  return results;
}

// ─── File Scoring ────────────────────────────────────────────────────────────

/**
 * Score a single file for risk, returning a 1-5 rank.
 *
 * Scoring dimensions:
 * - Internet-facing patterns (routes, handlers)
 * - Auth/authorization code
 * - Known dangerous sink presence
 * - File type (extension)
 *
 * @param {string} content - File content
 * @param {string} filePath - File path
 * @returns {{ score: number, rank: number, breakdown: object }}
 */
function scoreFile(content, filePath) {
  const ext = path.extname(filePath).slice(1).toLowerCase();
  const score = { total: 0, breakdown: {} };

  // 1. Internet-facing weight (0–35 pts) — prioritized
  const internetScore = scoreInternetFacing(content);
  score.breakdown.internetFacing = internetScore;

  // 2. Auth/security weight (0–30 pts) — prioritized
  const authScore = scoreAuthCode(content);
  score.breakdown.auth = authScore;

  // 3. Sink presence (0–30 pts)
  const sinkScore = scoreSinks(content, ext);
  score.breakdown.sinks = sinkScore;

  // 4. File type risk (0–15 pts)
  const typeScore = scoreFileType(ext, filePath);
  score.breakdown.fileType = typeScore;

  score.total = internetScore + authScore + sinkScore + typeScore;

  // Convert 0-110 score to 1-5 rank
  const rank = scoreToRank(score.total);

  return { score: score.total, rank, breakdown: score.breakdown };
}

/**
 * Score internet-facing patterns.
 *
 * Each pattern contributes up to 20 points; overall cap is 35 so that
 * a single route declaration plus req/res access naturally clears the
 * rank-4 threshold.
 */
function scoreInternetFacing(content) {
  let score = 0;
  for (const pattern of INTERNET_FACING_PATTERNS) {
    pattern.lastIndex = 0;
    const matches = content.match(pattern);
    if (matches) {
      score += Math.min(matches.length * 10, 24); // Cap per pattern type
    }
  }
  return Math.min(score, 35);
}

/**
 * Score authentication/authorization code.
 *
 * Auth code is a top-priority indicator (rank 4-5 even before sinks are
 * considered) so we cap aggressively but reward every match.
 */
function scoreAuthCode(content) {
  let score = 0;
  for (const pattern of AUTH_PATTERNS) {
    pattern.lastIndex = 0;
    const matches = content.match(pattern);
    if (matches) {
      score += Math.min(matches.length * 8, 25);
    }
  }
  return Math.min(score, 30);
}

/**
 * Score based on known dangerous sinks in content.
 *
 * Per-sink cap raised to 22 so a critical sink in a route handler is
 * sufficient to push a file to rank 4 even without strong auth signals.
 */
function scoreSinks(content, ext) {
  const sinks = SINK_DEFINITIONS[ext] || SINK_DEFINITIONS['js'];
  let score = 0;

  for (const sink of sinks) {
    sink.pattern.lastIndex = 0;
    const matches = content.match(sink.pattern);
    if (matches) {
      const weight = sink.severity === 'CRITICAL' ? 15
        : sink.severity === 'HIGH' ? 9
        : sink.severity === 'MEDIUM' ? 5
        : 3;
      score += Math.min(matches.length * weight, 22);
    }
  }

  return Math.min(score, 30);
}

/**
 * Score based on file extension and path.
 */
function scoreFileType(ext, filePath) {
  let score = 0;

  // High-risk extensions
  if (['js', 'ts', 'jsx', 'tsx', 'py', 'rb', 'php', 'go', 'java', 'kt', 'swift'].includes(ext)) {
    score += 5;
  }
  if (['c', 'cpp', 'cs', 'rs', 'scala'].includes(ext)) {
    score += 4;
  }
  if (['sh', 'bash', 'zsh', 'bat', 'ps1', 'cmd'].includes(ext)) {
    score += 4;
  }

  // High-risk paths
  const lowerPath = filePath.toLowerCase();
  if (/(?:route|router|controller|handler|middleware|service|api|server|app|index|main)/.test(lowerPath)) {
    score += 6;
  }
  if (/(?:auth|login|signup|register|session|token|password|credential)/.test(lowerPath)) {
    score += 4;
  }

  return Math.min(score, 15);
}

/**
 * Convert a 0-110 score to a 1-5 rank.
 *   1: minimal risk
 *   5: highest risk
 *
 * Thresholds are tuned so that:
 *   - Files that are purely utility/config (no internet-facing, no sinks)
 *     stay at rank 1-2.
 *   - Internet-facing files with at least one known sink cross into rank 4+.
 *   - Files combining internet-facing + auth + sinks hit rank 5.
 */
function scoreToRank(score) {
  if (score >= 60) return 5;
  if (score >= 35) return 4;
  if (score >= 18) return 3;
  if (score >= 6)  return 2;
  return 1;
}

// ─── File Discovery ──────────────────────────────────────────────────────────

/**
 * Discover and read source files in a directory tree.
 * @param {string} targetDir - Root directory
 * @param {Object} options - { maxFiles, excludeDirs, includeExts }
 * @returns {Array<{path, content, ext}>}
 */
function discoverFiles(targetDir, options = {}) {
  const {
    maxFiles = 100,
    excludeDirs = ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', 'venv', '.venv', 'vendor'],
    includeExts = ['js', 'ts', 'jsx', 'tsx', 'py', 'rb', 'php', 'go', 'java', 'kt', 'swift', 'cs', 'rs', 'c', 'cpp', 'h', 'sh', 'bash', 'zsh'],
    includeHiddenDirs = false
  } = options;

  const files = [];
  try {
    const stat = fs.statSync(targetDir);
    if (stat.isFile()) {
      files.push(targetDir);
    } else {
      const rootIsHidden = path.basename(path.resolve(targetDir)).startsWith('.');
      walkDir(targetDir, excludeDirs, includeExts, files, maxFiles, includeHiddenDirs || rootIsHidden);
    }
  } catch (err) {
    // Fallback if stat fails
    const rootIsHidden = path.basename(path.resolve(targetDir)).startsWith('.');
    walkDir(targetDir, excludeDirs, includeExts, files, maxFiles, includeHiddenDirs || rootIsHidden);
  }

  return files.map(f => {
    try {
      const content = fs.readFileSync(f, 'utf-8');
      return { path: f, content, ext: path.extname(f).slice(1).toLowerCase() };
    } catch (err) {
      return { path: f, content: '', ext: path.extname(f).slice(1).toLowerCase(), error: err.message };
    }
  });
}

/**
 * Recursive directory walker.
 */
function walkDir(dir, excludeDirs, includeExts, results, maxFiles, includeHiddenDirs = false) {
  if (results.length >= maxFiles) return;

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // Skip unreadable directories
  }

  for (const entry of entries) {
    if (results.length >= maxFiles) return;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (excludeDirs.includes(entry.name)) continue;
      if (entry.name.startsWith('.') && !includeHiddenDirs) continue;
      walkDir(fullPath, excludeDirs, includeExts, results, maxFiles, includeHiddenDirs);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).slice(1).toLowerCase();
      if (includeExts.includes(ext)) {
        results.push(fullPath);
      }
    }
  }
}

module.exports = {
  // Constants
  SINK_DEFINITIONS,
  VULNERABILITY_PATTERNS,
  INTERNET_FACING_PATTERNS,
  AUTH_PATTERNS,

  // Core functions
  identifySinks,
  matchVulnerabilityPatterns,
  scoreFile,
  discoverFiles,

  // Helpers
  scoreToRank,
  scoreInternetFacing,
  scoreAuthCode,
  scoreSinks,
  scoreFileType,
};