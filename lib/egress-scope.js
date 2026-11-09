// Egress Scope Containment Module
// Restricts network tools and agent requests to authorized targets only

const { URL } = require('url');

class EgressScopeContainment {
  constructor(options = {}) {
    this.primaryTarget = options.target || options.primaryTarget || 'localhost';
    this.allowedDomains = new Set((options.allowedDomains || []).map(d => d.toLowerCase()));
    this.allowedIPs = new Set(options.allowedIPs || []);
    this.allowSubdomains = options.allowSubdomains !== false;
    this.allowLoopback = options.allowLoopback !== false;
    this.strictMode = options.strictMode !== false;

    // Normalize primary target
    this._addScopeTarget(this.primaryTarget);
  }

  _addScopeTarget(targetStr) {
    if (!targetStr) return;
    let normalized = targetStr.trim().toLowerCase();

    // Remove protocol if present
    if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
      try {
        const u = new URL(normalized);
        normalized = u.hostname;
      } catch (e) {
        normalized = normalized.replace(/^https?:\/\//, '').split('/')[0];
      }
    } else {
      normalized = normalized.split('/')[0];
    }

    if (normalized.startsWith('[')) {
      const idx = normalized.indexOf(']');
      if (idx !== -1) normalized = normalized.substring(1, idx);
    } else if ((normalized.match(/:/g) || []).length === 1) {
      normalized = normalized.split(':')[0];
    }

    if (normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1' || normalized === '0.0.0.0' || normalized === '::') {
      this.allowedIPs.add('127.0.0.1');
      this.allowedIPs.add('::1');
      this.allowedDomains.add('localhost');
    } else if (this._isIPAddress(normalized)) {
      this.allowedIPs.add(normalized);
    } else {
      this.allowedDomains.add(normalized);
    }
  }

  _isIPAddress(str) {
    const cleanStr = str.replace(/^\[|\]$/g, '');
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
    return ipv4Regex.test(cleanStr) || ipv6Regex.test(cleanStr) || cleanStr === '::1';
  }

  isAllowed(hostOrUrl) {
    if (!hostOrUrl || typeof hostOrUrl !== 'string') {
      return { allowed: false, reason: 'SCOPE DENIED: Invalid or empty host/URL' };
    }

    let host = hostOrUrl.trim();

    // Relative path or file path local access
    if (host.startsWith('/') || host.startsWith('./') || host.startsWith('../') || host.startsWith('file://')) {
      return { allowed: true, host: 'local-file' };
    }

    // Extract hostname from URL
    if (host.startsWith('http://') || host.startsWith('https://') || host.startsWith('ws://') || host.startsWith('wss://')) {
      try {
        const parsed = new URL(host);
        host = parsed.hostname;
      } catch (err) {
        return { allowed: false, reason: `SCOPE DENIED: Malformed URL ${hostOrUrl}` };
      }
    } else {
      host = host.split('/')[0];
      if (host.startsWith('[')) {
        const idx = host.indexOf(']');
        if (idx !== -1) host = host.substring(1, idx);
      } else if ((host.match(/:/g) || []).length === 1) {
        host = host.split(':')[0];
      }
    }

    host = host.toLowerCase().replace(/^\[|\]$/g, '');

    // Check loopback
    if (this.allowLoopback && (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0' || host === '::')) {
      return { allowed: true, host };
    }

    // Check IP match
    if (this._isIPAddress(host)) {
      if (this.allowedIPs.has(host)) {
        return { allowed: true, host };
      }
      return { allowed: false, reason: `SCOPE DENIED: IP ${host} is not in allowed target scope` };
    }

    // Check exact domain match
    if (this.allowedDomains.has(host)) {
      return { allowed: true, host };
    }

    // Check subdomain match
    if (this.allowSubdomains) {
      for (const domain of this.allowedDomains) {
        if (host.endsWith('.' + domain)) {
          return { allowed: true, host };
        }
      }
    }

    return { allowed: false, reason: `SCOPE DENIED: Host ${host} is out of target scope` };
  }

  assertAllowed(hostOrUrl) {
    const res = this.isAllowed(hostOrUrl);
    if (!res.allowed) {
      throw new Error(res.reason);
    }
    return res;
  }
}

module.exports = { EgressScopeContainment };
