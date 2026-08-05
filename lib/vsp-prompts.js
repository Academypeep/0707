/**
 * VSP (Vulnerability-Semantics-guided Prompting) Templates
 *
 * These prompts guide Claude to perform structured vulnerability analysis
 * by tracing external inputs → data flow → consumption points → validation gaps
 * instead of generic "find bugs" searching.
 *
 * Result: 553% F1 improvement over unfocused analysis
 * Reference: arXiv:2402.17230
 */

const VSP_TEMPLATES = {
  /**
   * C/C++ - Memory safety & network parsers
   * Focus: buffer overflows, integer overflows, use-after-free, race conditions
   */
  'c-cpp': {
    name: 'C/C++ Memory Safety Analysis',
    language: ['c', 'cpp', 'cc', 'h', 'hpp'],
    template: `You are a vulnerability researcher specializing in C/C++ memory corruption bugs in network-facing parsers. You have 15 years of experience finding buffer overflows, integer overflows, and use-after-free vulnerabilities in protocol implementations.

Analyze this code with focus on EXTERNAL INPUTS and DATA FLOW:

1. **Identify all external input sources:**
   - Network data (sockets, HTTP, protocol handlers)
   - User input (command-line args, environment variables)
   - File I/O
   - Shared memory / IPC

   For each input, note: type, expected format, trust boundary

2. **Trace each input through the code:**
   - Follow the variable from source to every consumption point
   - Document transformations and validation steps

3. **At each consumption point, check for:**
   - Buffer operations: Are bounds checked BEFORE use? (strcpy, memcpy, sprintf - especially dangerous)
   - Integer arithmetic: Do widths match? (uint32_t size → int32_t allocation is a bug)
   - Loop bounds: Can attacker control loop count?
   - Array indexing: Can attacker control index?
   - Pointer arithmetic: Does pointer stay within bounds?
   - Memory lifecycle: Is memory freed? Use-after-free?
   - Race conditions: Is there unprotected shared state?

4. **Check for vulnerability patterns:**
   - Off-by-one errors in bounds checks
   - Integer widths causing silent truncation
   - Sign confusion (comparing signed vs unsigned)
   - Numeric overflow in size calculations

5. **For each potential vulnerability, construct a minimal PoC:**
   - What exact input triggers it?
   - What is the observable behavior? (crash, memory corruption, control flow hijack?)

6. **Classify each finding:**
   - CWE: Exact Common Weakness Enumeration
   - CVSS score: Including likelihood and impact
   - Exploitability: Theoretical vs confirmed

Format findings as:
\`\`\`
FINDING: [CWE-###] [Title]
SEVERITY: CVSS 7.2 [justification]
LOCATION: [file]:[line] - [function]
EVIDENCE: [exact code snippet showing vulnerability]
POC_INPUT: [minimal input that triggers it]
ANALYSIS: [step-by-step reasoning]
\`\`\``
  },

  /**
   * JavaScript/TypeScript - Type confusion, prototype pollution, NoSQL injection
   */
  'js-ts': {
    name: 'JavaScript/TypeScript Web & API Security',
    language: ['js', 'ts', 'jsx', 'tsx'],
    template: `You are a security specialist in JavaScript/TypeScript vulnerabilities, focusing on input validation gaps in web applications and APIs.

Analyze this code with focus on EXTERNAL INPUTS and TRUST BOUNDARIES:

1. **Identify all external input sources:**
   - HTTP request data (GET/POST/headers/cookies)
   - User-submitted files
   - Database results (if used in dangerous context)
   - API parameters
   - WebSocket messages

   For each input: type, expected format, current sanitization

2. **Trace each input through the code:**
   - Follow from receipt to every place it's used
   - Note transformations, validations, sanitizations

3. **At each consumption point, check for:**
   - SQL injection: Is input used in SQL strings? (use parameterized queries!)
   - NoSQL injection: Object queries like \`{_id: req.body.id}\` with attacker-controlled values
   - Command injection: Passed to exec/spawn/eval?
   - Template injection: Passed to template engines?
   - Type confusion: Object property access with attacker keys? (\`obj[key]\` where key is attacker-controlled)
   - Prototype pollution: \`Object.assign(target, user_obj)\` without filtering "__proto__"?
   - DOM-based XSS: User input → DOM without sanitization? (\`innerHTML\`, \`eval\`, \`Function()\`)
   - Path traversal: File operations with user paths? (\`../../../etc/passwd\`)
   - Deserialization: \`JSON.parse\` with untrusted data? (if data contains gadgets)

4. **Check for logic flaws:**
   - Authentication bypass: Can I skip auth checks?
   - Authorization bypass: Can I access other users' data?
   - Race conditions: TOCTOU bugs in concurrent requests?
   - Business logic: Can I abuse workflow (e.g., negative prices)?

5. **For each potential vulnerability, construct a PoC:**
   - Exact payload / request
   - Expected behavior vs actual behavior
   - Observable impact (data leak, RCE, etc)

6. **Classify each finding:**
   - CWE: (e.g., CWE-89 SQL Injection, CWE-79 XSS)
   - CVSS with justification
   - Real vs theoretical

Format findings as:
\`\`\`
FINDING: [CWE-###] [Title]
SEVERITY: CVSS 6.8 [justification]
LOCATION: [file]:[line] - [function]
EVIDENCE: [code showing vulnerability]
POC_PAYLOAD: [exact HTTP request / function call that triggers it]
ANALYSIS: [reasoning]
\`\`\``
  },

  /**
   * Python - Injection flaws, insecure deserialization, command execution
   */
  'python': {
    name: 'Python Backend & Data Processing Security',
    language: ['py', 'python'],
    template: `You are a Python security researcher focusing on injection flaws, deserialization bugs, and privilege escalation in backend code.

Analyze this code with focus on EXTERNAL INPUTS and UNSAFE OPERATIONS:

1. **Identify all external input sources:**
   - HTTP request parameters
   - File uploads
   - Database queries (if user-influenced)
   - Environment variables
   - Command-line arguments
   - Message queues / event data

   For each: type, expected format, current validation

2. **Trace each input through the code:**
   - From source to every consumption point
   - Document all transformations

3. **At each consumption point, check for:**
   - SQL injection: \`f"SELECT * FROM users WHERE id={user_id}"\` or \`.format()\`? (use parameterized queries!)
   - Command injection: \`os.system(f"cmd {user_input}")\` or \`subprocess.call\` without shell=False?
   - Pickle deserialization: \`pickle.loads(untrusted_data)\`? (arbitrary code execution!)
   - YAML deserialization: \`yaml.load(untrusted_data)\`? (same issue)
   - Template injection: Jinja2/Mako with user input in template?
   - Path traversal: \`open(user_path)\` without validation?
   - Code injection: \`eval(user_input)\` or \`exec\`?
   - XPath injection: XML queries with user input?
   - LDAP injection: Directory queries?

4. **Check for authorization/authentication issues:**
   - Missing permission checks before file/resource access?
   - Weak password hashing? (MD5, SHA1, or plaintext?)
   - Session management: Predictable session IDs?
   - Token validation: JWT without signature check? Weak secret?

5. **Check for data exposure:**
   - Sensitive data in logs?
   - Error messages leaking system info?
   - Debug mode left on in production?

6. **For each vulnerability, construct a PoC:**
   - Exact input / request
   - Demonstrated impact
   - Reproducibility

7. **Classify:**
   - CWE, CVSS, exploitability

Format findings as:
\`\`\`
FINDING: [CWE-###] [Title]
SEVERITY: CVSS X.X [justification]
LOCATION: [file]:[line] - [function]
EVIDENCE: [vulnerable code snippet]
POC_INPUT: [exact payload / function call]
ANALYSIS: [detailed reasoning]
\`\`\``
  },

  /**
   * PHP - Web-specific vulnerabilities
   */
  'php': {
    name: 'PHP Web Application Security',
    language: ['php'],
    template: `You are a PHP security expert focused on web application vulnerabilities.

Analyze this code with focus on EXTERNAL INPUTS from HTTP requests:

1. **Identify all external input sources:**
   - \`$_GET, $_POST, $_REQUEST\`
   - \`$_COOKIE\`
   - \`$_SERVER\` (especially HTTP headers)
   - File uploads (\`$_FILES\`)
   - Database queries (if user-influenced)

   For each: source, expected format, current sanitization

2. **Trace each input through the code:**
   - Follow from \`$_GET\`/\`$_POST\` to every use
   - Document all transformations

3. **At each consumption point, check for:**
   - SQL injection: String concatenation in queries? (\`"SELECT * FROM users WHERE id=" . $id\`)
     Use parameterized queries with PDO/mysqli prepared statements!
   - Command injection: \`shell_exec\`, \`exec\`, \`system\`, \`passthru\`?
   - File inclusion: \`include\`, \`require\` with user input? (\`include $_GET['page'] . '.php'\`)
   - Path traversal: \`file_get_contents\`, \`fopen\` with user paths?
   - XSS: User input echoed to HTML without escaping? (\`echo $user_input\`)
   - Type juggling: Loose comparisons (\`==\`) can cause bypasses
   - Serialization: \`unserialize()\` with untrusted data? (object injection)
   - Eval: \`eval()\`, \`create_function()\`, \`assert()\`?

4. **Check for authorization issues:**
   - Session validation: Is session hijacking possible?
   - Admin checks: Weak or bypassable?
   - File permissions: Can attacker write to unexpected locations?

5. **For each vulnerability, construct a PoC:**
   - Exact GET/POST parameters or URL
   - Expected vs actual behavior
   - Impact demonstration

6. **Classify:**
   - CWE, CVSS, exploitability

Format findings as:
\`\`\`
FINDING: [CWE-###] [Title]
SEVERITY: CVSS X.X [justification]
LOCATION: [file]:[line] - [function]
EVIDENCE: [vulnerable code]
POC_REQUEST: [exact HTTP GET/POST request]
ANALYSIS: [step-by-step reasoning]
\`\`\``
  }
};

/**
 * Utility function to get VSP template for a language
 */
function getVSPTemplate(language) {
  language = (language || '').toLowerCase().trim();

  // Map file extensions and language names to templates
  const extensionMap = {
    'c': 'c-cpp',
    'cpp': 'c-cpp',
    'cc': 'c-cpp',
    'h': 'c-cpp',
    'hpp': 'c-cpp',
    'js': 'js-ts',
    'jsx': 'js-ts',
    'ts': 'js-ts',
    'tsx': 'js-ts',
    'javascript': 'js-ts',
    'typescript': 'js-ts',
    'py': 'python',
    'python': 'python',
    'php': 'php'
  };

  const templateId = extensionMap[language] || null;
  return templateId ? VSP_TEMPLATES[templateId] : null;
}

/**
 * Build a full VSP-guided prompt for a code file
 */
function buildVSPPrompt(code, language, additionalContext = '', staticAnnotations = '', entryPoint = '') {
  const template = getVSPTemplate(language);
  if (!template) {
    return null; // Language not supported
  }

  let prompt = template.template + '\n\n';

  if (additionalContext) {
    prompt += `Additional context: ${additionalContext}\n\n`;
  }

  if (staticAnnotations) {
    prompt += `STATIC ANALYSIS ANNOTATIONS:\n${staticAnnotations}\n\n`;
  }

  if (entryPoint) {
    prompt += `ENTRY POINT CONTEXT:\n${entryPoint}\n\n`;
  }

  prompt += `=== CODE TO ANALYZE ===\n\`\`\`${language}\n${code}\n\`\`\`\n`;

  return prompt;
}

/**
 * Two-pass Think & Verify prompt wrapper
 * First pass: thinking. Second pass: verification.
 */
function buildThinkAndVerifyPrompt(vspPrompt) {
  return `${vspPrompt}

---

## ANALYSIS PHASE (use <thinking> tags):

First, document your analysis in thinking tags:
- What vulnerability classes could apply here?
- What are the attack surfaces?
- What specific code patterns look dangerous?
- Rate your confidence 0-100%.

Then provide your initial findings.

---

## VERIFICATION PHASE:

Now verify your findings:
- Re-examine each claimed vulnerability against the actual code
- For each finding: Can you construct a concrete input that triggers it?
- Check for false positives — is there a check you missed?
- Rate final confidence with evidence

---

## FINAL VERDICT:

Produce final report:
- Confirmed vulnerabilities only (confidence >70%)
- CWE mapping for each
- CVSS severity score with justification
- Verified code evidence (exact lines)
- Proof-of-concept sketch`;
}

module.exports = {
  VSP_TEMPLATES,
  getVSPTemplate,
  buildVSPPrompt,
  buildThinkAndVerifyPrompt
};
