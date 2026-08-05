/**
 * Code Browser - Tool for Claude agent to inspect code
 * Provides functions to browse source, find references, inspect call graphs
 */

const fs = require('fs');
const path = require('path');

class CodeBrowser {
  constructor(rootPath, options = {}) {
    this.rootPath = rootPath;
    this.fileCache = {}; // Cache parsed files to avoid re-reading
    this.includeHiddenDirs = options.includeHiddenDirs === true || path.basename(path.resolve(rootPath)).startsWith('.');
  }

  /**
   * Resolve file path robustly
   */
  _resolvePath(filePath) {
    let fullPath = path.join(this.rootPath, filePath);
    if (fs.existsSync(fullPath)) return fullPath;
    if (fs.existsSync(filePath)) return filePath;
    const absolutePath = path.resolve(filePath);
    if (fs.existsSync(absolutePath)) return absolutePath;

    // Check if we can strip targetDir prefix from filePath
    const cleanRoot = this.rootPath.replace(/^\.+[/\\]+/, '');
    if (cleanRoot && filePath.startsWith(cleanRoot)) {
      const strippedPath = filePath.substring(cleanRoot.length).replace(/^[/\\]+/, '');
      const strippedFullPath = path.join(this.rootPath, strippedPath);
      if (fs.existsSync(strippedFullPath)) return strippedFullPath;
    }

    // Try relative path subtraction
    try {
      const relativePart = path.relative(this.rootPath, filePath);
      const relativeFullPath = path.join(this.rootPath, relativePart);
      if (fs.existsSync(relativeFullPath)) return relativeFullPath;
    } catch (e) {}

    return null;
  }

  /**
   * View source code for a function or file
   * Returns snippet with line numbers
   */
  viewSource(filePath, startLine = null, endLine = null) {
    try {
      const fullPath = this._resolvePath(filePath);

      if (!fullPath) {
        return { error: `File not found: ${filePath}` };
      }

      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.split('\n');

      if (startLine === null) {
        // Return whole file with line numbers
        return {
          file: filePath,
          lines: lines.map((line, idx) => ({
            number: idx + 1,
            content: line
          }))
        };
      }

      // Return specific range
      const start = Math.max(0, startLine - 1);
      const end = Math.min(lines.length, (endLine || startLine) + 1);

      return {
        file: filePath,
        range: `${startLine}-${endLine || startLine}`,
        lines: lines.slice(start, end).map((line, idx) => ({
          number: start + idx + 1,
          content: line
        }))
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Find all references to a function/variable name across codebase
   */
  findReferences(name, filePattern = '**/*.{js,ts,py,c,cpp,h,java,go}') {
    try {
      const references = [];
      this._walkDir(this.rootPath, (filePath) => {
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const lines = content.split('\n');

          lines.forEach((line, idx) => {
            // Simple regex: word boundary match
            const regex = new RegExp(`\\b${name}\\b`);
            if (regex.test(line)) {
              references.push({
                file: path.relative(this.rootPath, filePath),
                line: idx + 1,
                content: line.trim().substring(0, 100)
              });
            }
          });
        } catch (e) {
          // Skip binary/unreadable files
        }
      });

      return { name, referenceCount: references.length, references };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * List function/class definitions in a file
   */
  getDefinitions(filePath) {
    try {
      const fullPath = this._resolvePath(filePath);
      if (!fullPath) {
        return { error: `File not found: ${filePath}` };
      }
      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.split('\n');

      const definitions = [];

      // Simple patterns for common languages
      const patterns = [
        { lang: 'function', regex: /^\s*(?:function|const|let|var)\s+(\w+)\s*[=\(]/, type: 'function' },
        { lang: 'class', regex: /^\s*(?:class|struct|interface)\s+(\w+)/, type: 'class' },
        { lang: 'async', regex: /^\s*(?:async\s+)?function\s+(\w+)/, type: 'async_function' }
      ];

      lines.forEach((line, idx) => {
        patterns.forEach(pattern => {
          const match = line.match(pattern.regex);
          if (match) {
            definitions.push({
              line: idx + 1,
              name: match[1],
              type: pattern.type,
              preview: line.trim().substring(0, 80)
            });
          }
        });
      });

      return { file: filePath, definitions };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Get file metadata: size, type, imports/requires
   */
  getFileMetadata(filePath) {
    try {
      const fullPath = this._resolvePath(filePath);
      if (!fullPath) {
        return { error: `File not found: ${filePath}` };
      }
      const stats = fs.statSync(fullPath);
      const content = fs.readFileSync(fullPath, 'utf8');

      // Extract imports
      const imports = [];
      content.split('\n').forEach(line => {
        if (line.match(/^\s*(import|require)\s+/)) {
          imports.push(line.trim());
        }
      });

      return {
        file: filePath,
        size: stats.size,
        lines: content.split('\n').length,
        mtime: stats.mtime,
        imports: imports.slice(0, 20) // First 20 imports
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Search for usage patterns (e.g., eval calls, dangerous functions)
   */
  searchPattern(pattern, fileGlob = '**/*') {
    try {
      const results = [];
      const regex = new RegExp(pattern, 'gi');

      this._walkDir(this.rootPath, (filePath) => {
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const lines = content.split('\n');

          lines.forEach((line, idx) => {
            if (regex.test(line)) {
              results.push({
                file: path.relative(this.rootPath, filePath),
                line: idx + 1,
                content: line.trim().substring(0, 120),
                match: line.match(regex)
              });
            }
          });
        } catch (e) {
          // Skip
        }
      });

      return { pattern, matches: results.length, results: results.slice(0, 50) };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Walk directory recursively
   */
  _walkDir(dir, callback) {
    const files = fs.readdirSync(dir);

    files.forEach(file => {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        // Skip node_modules by default, but preserve hidden directories when the root path is hidden.
        if (file === 'node_modules') return;
        if (file.startsWith('.') && !this.includeHiddenDirs) return;
        this._walkDir(fullPath, callback);
      } else {
        callback(fullPath);
      }
    });
  }
}

module.exports = { CodeBrowser };
