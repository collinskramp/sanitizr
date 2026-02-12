/**
 * Sanitizer Engine - Core pattern detection and replacement logic
 * Handles text and JSON sanitization with rule-based pattern matching
 */

class SanitizerEngine {
  constructor() {
    // Rule type priority order (lower number = higher priority)
    this.rulePriority = {
      'kv': 1,      // Key-value patterns
      'literal': 2,  // Literal text matches
      'builtin': 3,  // Built-in patterns
      'regex': 4     // Custom regex patterns
    };
    
    // Built-in pattern priority (more specific patterns first)
    this.builtinPriority = {
      'ssn': 1,
      'credit_card': 2,
      'github_token': 3,
      'github_client_id': 4,
      'stripe_secret_key': 5,
      'stripe_publishable_key': 6,
      'stripe_webhook_secret': 7,
      'sendgrid_api_key': 8,
      'twilio_account_sid': 9,
      'twilio_auth_token': 10,
      'gitlab_pat': 11,
      'gitlab_runner_token': 12,
      'aws_access_key': 13,
      'aws_secret_key': 14,
      'jwt_token': 15,
      'private_key': 16,
      'hex_key': 17,
      'ip': 18,
      'email': 19,
      'phone': 20, // Phone should be lower priority to avoid conflicts
      'database_url': 21,
      'repository_url': 22,
      'gcp_kms_path': 23,
      'slack_token': 24,
      'discord_token': 25,
      'api_key': 26
    };
    
    // Maximum processing depth for JSON to prevent stack overflow
    this.maxDepth = 100;
    
    // Timeout for regex operations (1 second)
    this.regexTimeout = 1000;
    
    // Built-in pattern definitions
    this.builtinPatterns = this.initializeBuiltinPatterns();
    
    // Deterministic replacement cache
    this.replacementCache = new Map();
    
    // Initialize SeededRNG class
    this.SeededRNG = class SeededRNG {
      constructor(seed) {
        this.seed = Math.abs(seed); // Ensure positive seed
        this.current = this.seed;
      }

      next() {
        // Linear congruential generator
        this.current = (this.current * 1664525 + 1013904223) % Math.pow(2, 32);
        // Ensure positive result
        const result = Math.abs(this.current) / Math.pow(2, 32);
        return result;
      }

      nextInt(min, max) {
        return Math.floor(this.next() * (max - min + 1)) + min;
      }

      nextChar(chars) {
        return chars[this.nextInt(0, chars.length - 1)];
      }

      nextLetter() {
        return this.nextChar('abcdefghijklmnopqrstuvwxyz');
      }

      nextUpperLetter() {
        return this.nextChar('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
      }

      nextDigit() {
        return this.nextChar('0123456789');
      }

      nextAlphaNumeric(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
          result += this.nextChar(chars);
        }
        return result;
      }
    };
  }

  /**
   * Initialize built-in pattern definitions with comprehensive regex patterns
   * @returns {Object.<string, {pattern: RegExp, generator: Function}>}
   */
  initializeBuiltinPatterns() {
    return {
      // Email addresses - RFC 5322 compliant pattern with common variations
      email: {
        pattern: /\b[A-Za-z0-9](?:[A-Za-z0-9._%-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b/g,
        generator: (match) => this.generateEmail(match)
      },
      
      // Phone numbers - International and US formats with proper word boundaries
      phone: {
        pattern: /\b(?:\+?1[-.\s]?\(?[2-9][0-9]{2}\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}(?:\s?(?:ext|x|extension)\.?\s?\d{1,5})?|\([2-9][0-9]{2}\)\s?[2-9][0-9]{2}[-.\s]?[0-9]{4}|[2-9][0-9]{2}[-.\s][2-9][0-9]{2}[-.\s][0-9]{4}|\+[1-9]\d{0,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{4,9})\b/g,
        generator: (match) => this.generatePhone(match)
      },
      
      // IP addresses - IPv4 and IPv6 with proper validation
      ip: {
        pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/g,
        generator: (match) => this.generateIP(match)
      },
      
      // AWS Access Keys - AKIA format with proper length validation
      aws_access_key: {
        pattern: /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b/g,
        generator: (match) => this.generateAWSKey(match)
      },
      
      // AWS Secret Keys - 40 character base64-like strings (more specific pattern)
      aws_secret_key: {
        pattern: /\b[A-Za-z0-9/+]{39}[A-Za-z0-9/+=]\b/g,
        generator: (match) => this.generateAWSSecret(match)
      },
      
      // JWT Tokens - Standard JWT format with three base64url parts
      jwt_token: {
        pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b/g,
        generator: (match) => this.generateJWT(match)
      },
      
      // GitHub Client IDs - Iv1. prefix with 16 hex characters
      github_client_id: {
        pattern: /\bIv1\.[a-f0-9]{16}\b/g,
        generator: (match) => this.generateGitHubClientId(match)
      },
      
      // GitHub Personal Access Tokens - ghp_ prefix
      github_token: {
        pattern: /\bghp_[A-Za-z0-9_]{36,40}\b/g,
        generator: (match) => this.generateGitHubToken(match)
      },
      
      // GitHub App Installation Access Tokens - ghs_ prefix
      github_app_token: {
        pattern: /\bghs_[A-Za-z0-9]{36}\b/g,
        generator: (match) => this.generateGitHubAppToken(match)
      },
      
      // GitHub OAuth Access Tokens - gho_ prefix
      github_oauth_token: {
        pattern: /\bgho_[A-Za-z0-9]{36}\b/g,
        generator: (match) => this.generateGitHubOAuthToken(match)
      },
      
      // GitHub User-to-Server Tokens - ghu_ prefix
      github_user_token: {
        pattern: /\bghu_[A-Za-z0-9]{36}\b/g,
        generator: (match) => this.generateGitHubUserToken(match)
      },
      
      // GitHub Server-to-Server Tokens - ghs_ prefix
      github_server_token: {
        pattern: /\bghr_[A-Za-z0-9]{36}\b/g,
        generator: (match) => this.generateGitHubServerToken(match)
      },
      
      // GCP KMS Paths - Full resource path format
      gcp_kms_path: {
        pattern: /projects\/[a-z0-9][a-z0-9\-]{4,28}[a-z0-9]\/locations\/[a-z0-9\-]+\/keyRings\/[a-zA-Z0-9_\-]+\/cryptoKeys\/[a-zA-Z0-9_\-]+(?:\/cryptoKeyVersions\/[0-9]+)?/g,
        generator: (match) => this.generateGCPKMSPath(match)
      },
      
      // GCP Service Account Keys - JSON key format
      gcp_service_key: {
        pattern: /\b[A-Za-z0-9_-]{40,}\b(?=.*"type":\s*"service_account")/g,
        generator: (match) => this.generateGCPServiceKey(match)
      },
      
      // Repository URLs - GitHub, GitLab, Bitbucket with various formats
      repository_url: {
        pattern: /(?:https?:\/\/|git@)(?:github\.com|gitlab\.com|bitbucket\.org)(?:\/|:)[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(?:\.git)?(?:\/[A-Za-z0-9._\/-]*)?/g,
        generator: (match) => this.generateRepoURL(match)
      },
      
      // API Keys - Generic API key patterns
      api_key: {
        pattern: /\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer[_-]?token)[\s=:'"]*([A-Za-z0-9_\-\.]{20,})\b/gi,
        generator: (match) => this.generateAPIKey(match)
      },
      
      // Database Connection Strings
      database_url: {
        pattern: /(?:mongodb|mysql|postgresql|postgres|redis|sqlite):\/\/(?:[A-Za-z0-9._%-]+(?::[A-Za-z0-9._%-]*)?@)?[A-Za-z0-9.-]+(?::[0-9]+)?(?:\/[A-Za-z0-9._%-]*)?(?:\?[A-Za-z0-9._%-=&]*)?/g,
        generator: (match) => this.generateDatabaseURL(match)
      },
      
      // Credit Card Numbers - Major card types with Luhn validation
      credit_card: {
        pattern: /\b(?:4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|3[47]\d{1}[-\s]?\d{6}[-\s]?\d{5}|3[0-9]\d{2}[-\s]?\d{6}[-\s]?\d{4}|6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b/g,
        generator: (match) => this.generateCreditCard(match)
      },
      
      // Social Security Numbers - US format with various separators
      ssn: {
        pattern: /\b(?!000|666|9\d{2})\d{3}[-.\s](?!00)\d{2}[-.\s](?!0000)\d{4}\b/g,
        generator: (match) => this.generateSSN(match)
      },
      
      // Private Keys - PEM format detection
      private_key: {
        pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
        generator: (match) => this.generatePrivateKey(match)
      },
      
      // Slack Tokens - Various Slack token formats
      slack_token: {
        pattern: /\bxox[bpars]-[A-Za-z0-9\-]+/g,
        generator: (match) => this.generateSlackToken(match)
      },
      
      // Discord Tokens
      discord_token: {
        pattern: /\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}\b/g,
        generator: (match) => this.generateDiscordToken(match)
      },
      
      // GitLab Tokens - CRITICAL MISSING PATTERNS
      gitlab_pat: {
        pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/g,
        generator: (match) => this.generateGitLabPAT(match)
      },
      
      gitlab_runner_token: {
        pattern: /\bGR[A-Za-z0-9]{40}\b/g,
        generator: (match) => this.generateGitLabRunnerToken(match)
      },
      
      // Stripe API Keys - CRITICAL MISSING PATTERNS
      stripe_secret_key: {
        pattern: /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/g,
        generator: (match) => this.generateStripeSecretKey(match)
      },
      
      stripe_publishable_key: {
        pattern: /\bpk_(live|test)_[A-Za-z0-9]{24,}\b/g,
        generator: (match) => this.generateStripePublishableKey(match)
      },
      
      stripe_webhook_secret: {
        pattern: /\bwhsec_[A-Za-z0-9]{32,}\b/g,
        generator: (match) => this.generateStripeWebhookSecret(match)
      },
      
      // SendGrid API Keys - CRITICAL MISSING PATTERNS
      sendgrid_api_key: {
        pattern: /\bSG\.[A-Za-z0-9_-]{20,25}\.[A-Za-z0-9_-]{40,50}\b/g,
        generator: (match) => this.generateSendGridAPIKey(match)
      },
      
      // Twilio Credentials - CRITICAL MISSING PATTERNS
      twilio_account_sid: {
        pattern: /\bAC[a-f0-9]{32}\b/g,
        generator: (match) => this.generateTwilioAccountSID(match)
      },
      
      twilio_auth_token: {
        pattern: /\bSK[a-f0-9]{32}\b/g,
        generator: (match) => this.generateTwilioAuthToken(match)
      },
      
      // Generic Hex Keys - CRITICAL MISSING PATTERNS
      hex_key: {
        pattern: /\b[a-fA-F0-9]{32,}\b/g,
        generator: (match) => this.generateHexKey(match)
      }
    };
  }

  /**
   * Detect sensitive patterns in text
   * @param {string} text - Input text to analyze
   * @param {DetectOptions} options - Detection options
   * @returns {Detection[]} Array of detected patterns
   */
  detect(text, options = {}) {
    const { rules = [], includeContext = false, contextLength = 20 } = options;
    const detections = [];
    
    if (!text || typeof text !== 'string') {
      return detections;
    }
    
    // Sort rules by priority
    const sortedRules = this.sortRulesByPriority(rules.filter(rule => rule.enabled));
    
    // Apply each rule
    for (const rule of sortedRules) {
      try {
        const ruleDetections = this.detectWithRule(text, rule, includeContext, contextLength);
        detections.push(...ruleDetections);
      } catch (error) {
        console.error(`Error applying rule ${rule.id}:`, error);
      }
    }
    
    // Resolve conflicts between overlapping detections
    const resolvedDetections = this.resolveConflicts(detections, sortedRules);
    
    // Sort final detections by priority, then by position
    return resolvedDetections.sort((a, b) => {
      const priorityA = this.getRulePriorityByRuleId(a.ruleId, sortedRules);
      const priorityB = this.getRulePriorityByRuleId(b.ruleId, sortedRules);
      
      // First sort by priority (lower number = higher priority)
      if (priorityA !== priorityB) {
        return priorityA - priorityB;
      }
      
      // If same priority, sort by position
      return a.startIndex - b.startIndex;
    });
  }

  /**
   * Detect patterns using a specific rule
   * @param {string} text 
   * @param {Rule} rule 
   * @param {boolean} includeContext 
   * @param {number} contextLength 
   * @returns {Detection[]}
   */
  detectWithRule(text, rule, includeContext, contextLength) {
    const detections = [];
    
    switch (rule.type) {
      case 'literal':
        return this.detectLiteral(text, rule, includeContext, contextLength);
      
      case 'regex':
        return this.detectRegex(text, rule, includeContext, contextLength);
      
      case 'builtin':
        return this.detectBuiltin(text, rule, includeContext, contextLength);
      
      case 'kv':
        return this.detectKeyValue(text, rule, includeContext, contextLength);
      
      default:
        console.warn(`Unknown rule type: ${rule.type}`);
        return detections;
    }
  }

  /**
   * Detect literal text matches
   * @param {string} text 
   * @param {Rule} rule 
   * @param {boolean} includeContext 
   * @param {number} contextLength 
   * @returns {Detection[]}
   */
  detectLiteral(text, rule, includeContext, contextLength) {
    const detections = [];
    const pattern = rule.pattern;
    let index = 0;
    
    while ((index = text.indexOf(pattern, index)) !== -1) {
      const detection = {
        ruleId: rule.id,
        ruleName: rule.name || rule.pattern,
        category: rule.category,
        pattern: rule.pattern,
        match: pattern,
        startIndex: index,
        endIndex: index + pattern.length,
        replacement: this.generateReplacementSync(pattern, rule),
        selected: true
      };
      
      if (includeContext) {
        detection.context = this.extractContext(text, index, pattern.length, contextLength);
      }
      
      detections.push(detection);
      index += pattern.length;
    }
    
    return detections;
  }

  /**
   * Detect regex pattern matches
   * @param {string} text 
   * @param {Rule} rule 
   * @param {boolean} includeContext 
   * @param {number} contextLength 
   * @returns {Detection[]}
   */
  detectRegex(text, rule, includeContext, contextLength) {
    const detections = [];
    
    try {
      const regex = new RegExp(rule.pattern, rule.flags || 'g');
      let match;
      
      const startTime = Date.now();
      
      while ((match = regex.exec(text)) !== null) {
        // Timeout protection
        if (Date.now() - startTime > this.regexTimeout) {
          console.warn(`Regex timeout for rule ${rule.id}`);
          break;
        }
        
        const detection = {
          ruleId: rule.id,
          ruleName: rule.name || rule.pattern,
          category: rule.category,
          pattern: rule.pattern,
          match: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
          replacement: this.generateReplacementSync(match[0], rule),
          selected: true
        };
        
        if (includeContext) {
          detection.context = this.extractContext(text, match.index, match[0].length, contextLength);
        }
        
        detections.push(detection);
        
        // Prevent infinite loop on zero-length matches
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    } catch (error) {
      console.error(`Invalid regex in rule ${rule.id}:`, error);
    }
    
    return detections;
  }

  /**
   * Detect built-in pattern matches
   * @param {string} text 
   * @param {Rule} rule 
   * @param {boolean} includeContext 
   * @param {number} contextLength 
   * @returns {Detection[]}
   */
  detectBuiltin(text, rule, includeContext, contextLength) {
    const detections = [];
    const builtinPattern = this.builtinPatterns[rule.pattern];
    
    if (!builtinPattern) {
      console.warn(`Unknown builtin pattern: ${rule.pattern}`);
      return detections;
    }
    
    // Reset regex lastIndex
    builtinPattern.pattern.lastIndex = 0;
    
    let match;
    while ((match = builtinPattern.pattern.exec(text)) !== null) {
      const detection = {
        ruleId: rule.id,
        ruleName: rule.name || rule.pattern,
        category: rule.category,
        pattern: rule.pattern,
        match: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        replacement: this.generateReplacementSync(match[0], rule),
        selected: true
      };
      
      if (includeContext) {
        detection.context = this.extractContext(text, match.index, match[0].length, contextLength);
      }
      
      detections.push(detection);
    }
    
    return detections;
  }

  /**
   * Detect key-value pattern matches
   * @param {string} text 
   * @param {Rule} rule 
   * @param {boolean} includeContext 
   * @param {number} contextLength 
   * @returns {Detection[]}
   */
  detectKeyValue(text, rule, includeContext, contextLength) {
    const detections = [];
    
    // Key-value patterns for different formats
    const kvPatterns = [
      // YAML format: key: value
      new RegExp(`${rule.pattern}\\s*:\\s*([^\\n\\r]+)`, 'gi'),
      // JSON format: "key": "value"
      new RegExp(`"${rule.pattern}"\\s*:\\s*"([^"]+)"`, 'gi'),
      // Environment variable format: KEY=value
      new RegExp(`${rule.pattern}\\s*=\\s*([^\\s\\n\\r]+)`, 'gi')
    ];
    
    for (const pattern of kvPatterns) {
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const fullMatch = match[0];
        const valueMatch = match[1];
        
        const detection = {
          ruleId: rule.id,
          ruleName: rule.name || rule.pattern,
          category: rule.category,
          pattern: rule.pattern,
          match: valueMatch, // Only the value part
          startIndex: match.index + fullMatch.indexOf(valueMatch),
          endIndex: match.index + fullMatch.indexOf(valueMatch) + valueMatch.length,
          replacement: this.generateReplacementSync(valueMatch, rule),
          selected: true
        };
        
        if (includeContext) {
          detection.context = this.extractContext(text, match.index, fullMatch.length, contextLength);
        }
        
        detections.push(detection);
      }
    }
    
    return detections;
  }

  /**
   * Extract context around a match
   * @param {string} text 
   * @param {number} startIndex 
   * @param {number} matchLength 
   * @param {number} contextLength 
   * @returns {string}
   */
  extractContext(text, startIndex, matchLength, contextLength) {
    const beforeStart = Math.max(0, startIndex - contextLength);
    const afterEnd = Math.min(text.length, startIndex + matchLength + contextLength);
    
    const before = text.substring(beforeStart, startIndex);
    const match = text.substring(startIndex, startIndex + matchLength);
    const after = text.substring(startIndex + matchLength, afterEnd);
    
    return `${before}[${match}]${after}`;
  }

  /**
   * Sort rules by priority
   * @param {Rule[]} rules 
   * @returns {Rule[]}
   */
  sortRulesByPriority(rules) {
    return rules.sort((a, b) => {
      const priorityA = a.priority || this.rulePriority[a.type] || 999;
      const priorityB = b.priority || this.rulePriority[b.type] || 999;
      
      // If same type priority, use builtin pattern priority for builtin rules
      if (priorityA === priorityB && a.type === 'builtin' && b.type === 'builtin') {
        const builtinPriorityA = this.builtinPriority[a.pattern] || 999;
        const builtinPriorityB = this.builtinPriority[b.pattern] || 999;
        return builtinPriorityA - builtinPriorityB;
      }
      
      return priorityA - priorityB;
    });
  }

  /**
   * Resolve conflicts between overlapping detections
   * @param {Detection[]} detections 
   * @param {Rule[]} rules - The rules array for priority lookup
   * @returns {Detection[]}
   */
  resolveConflicts(detections, rules = []) {
    if (detections.length <= 1) {
      return detections;
    }
    
    // Sort by start index
    const sorted = detections.sort((a, b) => a.startIndex - b.startIndex);
    const resolved = [];
    
    for (const detection of sorted) {
      const conflicts = resolved.filter(r => this.detectionsOverlap(r, detection));
      
      if (conflicts.length === 0) {
        resolved.push(detection);
      } else {
        // Handle conflicts based on rule priority
        const shouldReplace = conflicts.every(conflict => {
          const conflictPriority = this.getRulePriorityByRuleId(conflict.ruleId, rules);
          const detectionPriority = this.getRulePriorityByRuleId(detection.ruleId, rules);
          return detectionPriority < conflictPriority;
        });
        
        if (shouldReplace) {
          // Remove conflicting detections and add new one
          conflicts.forEach(conflict => {
            const index = resolved.indexOf(conflict);
            if (index > -1) {
              resolved.splice(index, 1);
            }
          });
          resolved.push(detection);
        }
      }
    }
    
    return resolved.sort((a, b) => a.startIndex - b.startIndex);
  }

  /**
   * Check if two detections overlap
   * @param {Detection} a 
   * @param {Detection} b 
   * @returns {boolean}
   */
  detectionsOverlap(a, b) {
    return !(a.endIndex <= b.startIndex || b.endIndex <= a.startIndex);
  }

  /**
   * Get rule priority by rule ID
   * @param {string} ruleId 
   * @returns {number}
   */
  getRulePriority(ruleId) {
    // Extract rule type from ruleId or use stored rule information
    // For now, we'll need to pass rules to resolveConflicts method
    return 999;
  }

  /**
   * Get rule priority by rule ID using the rules array
   * @param {string} ruleId 
   * @param {Rule[]} rules 
   * @returns {number}
   */
  getRulePriorityByRuleId(ruleId, rules) {
    const rule = rules.find(r => r.id === ruleId);
    if (!rule) {
      return 999; // Default priority for unknown rules
    }
    
    const basePriority = rule.priority || this.rulePriority[rule.type] || 999;
    
    // For builtin rules, add sub-priority
    if (rule.type === 'builtin') {
      const builtinPriority = this.builtinPriority[rule.pattern] || 999;
      return basePriority + (builtinPriority / 1000); // Add fractional priority
    }
    
    return basePriority;
  }

  /**
   * Check if text is valid JSON
   * @param {string} text 
   * @returns {boolean}
   */
  isJSON(text) {
    try {
      const trimmed = text.trim();
      if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
        return false;
      }
      JSON.parse(trimmed);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Sanitize text by replacing detected patterns (synchronous version)
   * @param {string} text - Input text
   * @param {SanitizeOptions} options - Sanitization options
   * @returns {string} Sanitized text
   */
  sanitize(text, options = {}) {
    const { rules = [], deterministicReplacement = true, selectedDetections = null } = options;
    
    if (!text || typeof text !== 'string') {
      return text;
    }
    
    // Check if input is JSON
    if (this.isJSON(text)) {
      return this.sanitizeJSONSync(text, options);
    } else {
      return this.sanitizeTextSync(text, options);
    }
  }

  /**
   * Sanitize plain text (synchronous version)
   * @param {string} text 
   * @param {SanitizeOptions} options 
   * @returns {string}
   */
  sanitizeTextSync(text, options) {
    const detections = this.detect(text, { rules: options.rules });
    
    // Filter detections if selective sanitization is enabled
    let activeDetections = detections;
    if (options.selectedDetections && options.selectedDetections.length > 0) {
      activeDetections = detections.filter(d => 
        options.selectedDetections.includes(d.ruleId)
      );
    }
    
    // Sort by start index in reverse order to avoid index shifting
    activeDetections.sort((a, b) => b.startIndex - a.startIndex);
    
    let result = text;
    
    // Process replacements synchronously
    for (const detection of activeDetections) {
      const rule = options.rules.find(r => r.id === detection.ruleId);
      let replacement;
      
      if (detection.replacement) {
        replacement = detection.replacement;
      } else if (rule) {
        replacement = this.generateReplacementSync(
          detection.match, 
          rule, 
          options.deterministicReplacement !== false
        );
      } else {
        replacement = detection.match;
      }
      
      result = result.substring(0, detection.startIndex) + 
               replacement + 
               result.substring(detection.endIndex);
    }
    
    return result;
  }

  /**
   * Sanitize JSON while preserving structure (synchronous version)
   * @param {string} jsonText 
   * @param {SanitizeOptions} options 
   * @returns {string}
   */
  sanitizeJSONSync(jsonText, options) {
    try {
      const parsed = JSON.parse(jsonText);
      const sanitized = this.sanitizeJSONObjectSync(parsed, options, 0, new WeakSet());
      return JSON.stringify(sanitized, null, 2);
    } catch (error) {
      console.warn('Failed to parse JSON, falling back to text sanitization:', error);
      return this.sanitizeTextSync(jsonText, options);
    }
  }

  /**
   * Recursively sanitize JSON object (synchronous version)
   * @param {any} obj 
   * @param {SanitizeOptions} options 
   * @param {number} depth 
   * @param {WeakSet} visited 
   * @returns {any}
   */
  sanitizeJSONObjectSync(obj, options, depth = 0, visited = new WeakSet()) {
    // Prevent infinite recursion and stack overflow
    if (depth > this.maxDepth) {
      console.warn('Maximum JSON depth exceeded');
      return '[Max Depth Exceeded]';
    }
    
    if (visited.has(obj)) {
      return '[Circular Reference]';
    }
    
    if (typeof obj === 'string') {
      return this.sanitizeTextSync(obj, options);
    }
    
    if (Array.isArray(obj)) {
      visited.add(obj);
      const result = [];
      for (const item of obj) {
        result.push(this.sanitizeJSONObjectSync(item, options, depth + 1, visited));
      }
      visited.delete(obj);
      return result;
    }
    
    if (obj && typeof obj === 'object') {
      visited.add(obj);
      const result = {};
      for (const [key, value] of Object.entries(obj)) {
        // Check for key-value rules that match this key
        const kvRules = options.rules.filter(r => r.type === 'kv' && r.enabled);
        let sanitizedValue = value;
        
        // Check if any KV rule matches this key
        for (const rule of kvRules) {
          if (key.toLowerCase().includes(rule.pattern.toLowerCase()) || 
              rule.pattern.toLowerCase().includes(key.toLowerCase()) ||
              key === rule.pattern) {
            // This key matches a KV rule, sanitize the value
            if (typeof value === 'string') {
              sanitizedValue = rule.replacement || this.generateReplacementSync(
                value, 
                rule, 
                options.deterministicReplacement !== false
              );
              break; // Use first matching rule
            }
          }
        }
        
        // If no KV rule matched, recursively sanitize the value
        if (sanitizedValue === value) {
          result[key] = this.sanitizeJSONObjectSync(value, options, depth + 1, visited);
        } else {
          result[key] = sanitizedValue;
        }
      }
      visited.delete(obj);
      return result;
    }
    
    // Numbers, booleans, null remain unchanged
    return obj;
  }

  /**
   * Generate replacement text for a detected pattern (sync version for detection phase)
   * @param {string} originalValue 
   * @param {Rule} rule 
   * @param {boolean} deterministicReplacement - Whether to use deterministic replacement
   * @returns {string}
   */
  generateReplacementSync(originalValue, rule, deterministicReplacement = true) {
    // Use fixed replacement if specified
    if (rule.replacement !== null) {
      return rule.replacement;
    }
    
    // For deterministic replacement, use synchronous hash-based generation
    if (deterministicReplacement) {
      return this.generateDeterministicReplacementSync(originalValue, rule);
    }
    
    // Generate replacement based on rule type
    if (rule.type === 'builtin') {
      const builtinPattern = this.builtinPatterns[rule.pattern];
      if (builtinPattern && builtinPattern.generator) {
        return builtinPattern.generator(originalValue);
      }
    }
    
    // Default: preserve shape of original value
    return this.preservePatternShape(originalValue);
  }

  /**
   * Generate deterministic replacement using simple hash seeding (synchronous)
   * @param {string} originalValue 
   * @param {Rule} rule 
   * @returns {string}
   */
  generateDeterministicReplacementSync(originalValue, rule) {
    const cacheKey = `${originalValue}:${rule.type}:${rule.pattern}`;
    
    // Check cache first
    if (this.replacementCache.has(cacheKey)) {
      return this.replacementCache.get(cacheKey);
    }
    
    try {
      const seed = this.simpleHash(originalValue + rule.pattern);
      const rng = new this.SeededRNG(seed);
      let replacement;
      
      // Generate replacement based on rule type and pattern
      if (rule.type === 'builtin') {
        replacement = this.generateBuiltinDeterministicReplacementSync(originalValue, rule.pattern, rng);
      } else {
        // For other rule types, use advanced shape preservation
        replacement = this.preservePatternShapeAdvanced(originalValue, rng);
      }
      
      // Cache the result with LRU eviction
      this.addToCache(cacheKey, replacement);
      return replacement;
      
    } catch (error) {
      console.warn('Error generating deterministic replacement:', error);
      // Fallback to simple replacement
      return this.preservePatternShape(originalValue);
    }
  }

  /**
   * Add to cache with LRU eviction
   * @param {string} key 
   * @param {string} value 
   */
  addToCache(key, value) {
    const maxCacheSize = 1000; // Limit cache size
    if (this.replacementCache.size >= maxCacheSize) {
      const firstKey = this.replacementCache.keys().next().value;
      this.replacementCache.delete(firstKey);
    }
    this.replacementCache.set(key, value);
  }

  /**
   * Generate deterministic replacement for built-in patterns (synchronous)
   * @param {string} originalValue 
   * @param {string} patternType 
   * @param {SeededRNG} rng 
   * @returns {string}
   */
  generateBuiltinDeterministicReplacementSync(originalValue, patternType, rng) {
    switch (patternType) {
      case 'email':
        return `user${rng.nextInt(1000, 9999)}@example.com`;
      
      case 'phone':
        return `+1-555-${rng.nextInt(100, 999)}-${rng.nextInt(1000, 9999)}`;
      
      case 'ip':
        return `${rng.nextInt(1, 254)}.${rng.nextInt(1, 254)}.${rng.nextInt(1, 254)}.${rng.nextInt(1, 254)}`;
      
      case 'aws_access_key':
        return `AKIA${rng.nextAlphaNumeric(16)}`;
      
      case 'aws_secret_key':
        return rng.nextAlphaNumeric(40);
      
      case 'jwt_token':
        return this.generateJWTStructure(rng);
      
      case 'github_client_id':
        let clientId = 'Iv1.';
        for (let i = 0; i < 16; i++) {
          clientId += rng.nextChar('abcdef0123456789');
        }
        return clientId;
      
      case 'github_token':
        return `ghp_${rng.nextAlphaNumeric(36)}`;
      
      case 'gcp_kms_path':
        const projectId = `project-${rng.nextInt(1000, 9999)}`;
        const keyRing = `keyring-${rng.nextInt(100, 999)}`;
        const cryptoKey = `key-${rng.nextInt(100, 999)}`;
        return `projects/${projectId}/locations/us-central1/keyRings/${keyRing}/cryptoKeys/${cryptoKey}`;
      
      case 'repository_url':
        const user = `user${rng.nextInt(1000, 9999)}`;
        const repo = `repo${rng.nextInt(1000, 9999)}`;
        return `https://github.com/${user}/${repo}.git`;
      
      case 'credit_card':
        return '4111111111111111'; // Safe test credit card number
      
      case 'ssn':
        const area = rng.nextInt(100, 665);
        const group = rng.nextInt(10, 99);
        const serial = rng.nextInt(1000, 9999);
        const separator = originalValue.includes('-') ? '-' : 
                         originalValue.includes('.') ? '.' : 
                         originalValue.includes(' ') ? ' ' : '';
        return `${area.toString().padStart(3, '0')}${separator}${group.toString().padStart(2, '0')}${separator}${serial.toString().padStart(4, '0')}`;
      
      default:
        // For unknown patterns, use advanced shape preservation
        return this.preservePatternShapeAdvanced(originalValue, rng);
    }
  }

  /**
   * Generate replacement text for a detected pattern
   * @param {string} originalValue 
   * @param {Rule} rule 
   * @param {boolean} deterministicReplacement - Whether to use deterministic replacement
   * @returns {Promise<string>}
   */
  async generateReplacement(originalValue, rule, deterministicReplacement = true) {
    // Use fixed replacement if specified
    if (rule.replacement !== null) {
      return rule.replacement;
    }
    
    // For deterministic replacement, use async SHA-256 based generation
    if (deterministicReplacement) {
      return await this.generateDeterministicReplacement(originalValue, rule);
    }
    
    // Generate replacement based on rule type
    if (rule.type === 'builtin') {
      const builtinPattern = this.builtinPatterns[rule.pattern];
      if (builtinPattern && builtinPattern.generator) {
        return builtinPattern.generator(originalValue);
      }
    }
    
    // Default: preserve shape of original value
    return this.preservePatternShape(originalValue);
  }

  /**
   * Generate deterministic replacement using SHA-256 seeding
   * @param {string} originalValue 
   * @param {Rule} rule 
   * @returns {Promise<string>}
   */
  async generateDeterministicReplacement(originalValue, rule) {
    const cacheKey = `${originalValue}:${rule.type}:${rule.pattern}`;
    
    // Check cache first
    if (this.replacementCache.has(cacheKey)) {
      return this.replacementCache.get(cacheKey);
    }
    
    try {
      const seed = await this.sha256Hash(originalValue, rule.pattern);
      const rng = new this.SeededRNG(seed);
      let replacement;
      
      // Generate replacement based on rule type and pattern
      if (rule.type === 'builtin') {
        replacement = await this.generateBuiltinDeterministicReplacement(originalValue, rule.pattern, rng);
      } else {
        // For other rule types, use advanced shape preservation
        replacement = this.preservePatternShapeAdvanced(originalValue, rng);
      }
      
      // Cache the result
      this.replacementCache.set(cacheKey, replacement);
      return replacement;
      
    } catch (error) {
      console.warn('Error generating deterministic replacement:', error);
      // Fallback to simple replacement
      return this.preservePatternShape(originalValue);
    }
  }

  /**
   * Generate JWT structure with deterministic content
   * @param {SeededRNG} rng 
   * @returns {string}
   */
  generateJWTStructure(rng) {
    const header = this.base64UrlEncode(JSON.stringify({
      "alg": "HS256",
      "typ": "JWT"
    }));
    
    const payload = this.base64UrlEncode(JSON.stringify({
      "sub": `user${rng.nextInt(1000, 9999)}`,
      "iat": Math.floor(Date.now() / 1000),
      "exp": Math.floor(Date.now() / 1000) + 3600
    }));
    
    const signature = rng.nextAlphaNumeric(43);
    
    return `${header}.${payload}.${signature}`;
  }

  /**
   * Preserve the shape/structure of the original pattern with enhanced logic
   * @param {string} original 
   * @param {number} seed - Optional seed for deterministic generation
   * @returns {string}
   */
  preservePatternShape(original, seed = null) {
    if (seed !== null) {
      const rng = new this.SeededRNG(seed);
      return original
        .replace(/[a-z]/g, () => rng.nextLetter())
        .replace(/[A-Z]/g, () => rng.nextUpperLetter())
        .replace(/[0-9]/g, () => rng.nextDigit());
    } else {
      // Fallback to simple replacement
      return original
        .replace(/[a-z]/g, 'x')
        .replace(/[A-Z]/g, 'X')
        .replace(/[0-9]/g, '0');
    }
  }

  /**
   * Enhanced shape preservation that maintains character classes and structural elements
   * @param {string} original 
   * @param {SeededRNG} rng 
   * @returns {string}
   */
  preservePatternShapeAdvanced(original, rng) {
    let result = '';
    
    for (let i = 0; i < original.length; i++) {
      const char = original[i];
      
      if (/[a-z]/.test(char)) {
        result += rng.nextLetter();
      } else if (/[A-Z]/.test(char)) {
        result += rng.nextUpperLetter();
      } else if (/[0-9]/.test(char)) {
        result += rng.nextDigit();
      } else if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(char)) {
        // Preserve special characters but potentially randomize similar ones
        const specialChars = '!@#$%^&*';
        result += rng.nextChar(specialChars);
      } else {
        // Preserve structural characters (spaces, dots, dashes, etc.)
        result += char;
      }
    }
    
    return result;
  }

  /**
   * Generate deterministic email replacement
   * @param {string} original 
   * @returns {string}
   */
  generateEmail(original) {
    const hash = this.simpleHash(original);
    return `user${Math.abs(hash) % 10000}@example.com`;
  }

  /**
   * Generate deterministic phone replacement
   * @param {string} original 
   * @returns {string}
   */
  generatePhone(original) {
    const hash = this.simpleHash(original);
    const num = Math.abs(hash) % 10000000;
    return `+1-555-${String(num).padStart(7, '0').substring(0, 3)}-${String(num).padStart(7, '0').substring(3, 7)}`;
  }

  /**
   * Generate deterministic IP replacement
   * @param {string} original 
   * @returns {string}
   */
  generateIP(original) {
    const hash = this.simpleHash(original);
    const a = (Math.abs(hash) % 254) + 1;
    const b = (Math.abs(hash >> 8) % 254) + 1;
    const c = (Math.abs(hash >> 16) % 254) + 1;
    const d = (Math.abs(hash >> 24) % 254) + 1;
    return `${a}.${b}.${c}.${d}`;
  }

  /**
   * Generate deterministic AWS key replacement
   * @param {string} original 
   * @returns {string}
   */
  generateAWSKey(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = 'AKIA';
    
    for (let i = 0; i < 16; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic JWT replacement
   * @param {string} original 
   * @returns {string}
   */
  generateJWT(original) {
    const parts = original.split('.');
    const hash = this.simpleHash(original);
    
    // Generate fake JWT structure
    const header = this.base64UrlEncode(JSON.stringify({
      "alg": "HS256",
      "typ": "JWT"
    }));
    
    const payload = this.base64UrlEncode(JSON.stringify({
      "sub": `user${Math.abs(hash) % 10000}`,
      "iat": Math.floor(Date.now() / 1000),
      "exp": Math.floor(Date.now() / 1000) + 3600
    }));
    
    const signature = this.generateRandomBase64Url(43);
    
    return `${header}.${payload}.${signature}`;
  }

  /**
   * Generate deterministic GitHub client ID replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGitHubClientId(original) {
    const hash = this.simpleHash(original);
    const chars = 'abcdef0123456789';
    let result = 'Iv1.';
    
    for (let i = 0; i < 16; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic GCP KMS path replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGCPKMSPath(original) {
    const hash = this.simpleHash(original);
    const projectId = `project-${Math.abs(hash) % 10000}`;
    const location = 'us-central1';
    const keyRing = `keyring-${Math.abs(hash >> 8) % 1000}`;
    const cryptoKey = `key-${Math.abs(hash >> 16) % 1000}`;
    
    return `projects/${projectId}/locations/${location}/keyRings/${keyRing}/cryptoKeys/${cryptoKey}`;
  }

  /**
   * Generate deterministic AWS secret key replacement
   * @param {string} original 
   * @returns {string}
   */
  generateAWSSecret(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+=';
    let result = '';
    
    for (let i = 0; i < 40; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic GitHub token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGitHubToken(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = 'ghp_';
    
    for (let i = 0; i < 36; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic GitHub app token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGitHubAppToken(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = 'ghs_';
    
    for (let i = 0; i < 36; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic GitHub OAuth token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGitHubOAuthToken(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = 'gho_';
    
    for (let i = 0; i < 36; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic GitHub user token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGitHubUserToken(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = 'ghu_';
    
    for (let i = 0; i < 36; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic GitHub server token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGitHubServerToken(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = 'ghr_';
    
    for (let i = 0; i < 36; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic GCP service key replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGCPServiceKey(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
    let result = '';
    
    for (let i = 0; i < 40; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic API key replacement
   * @param {string} original 
   * @returns {string}
   */
  generateAPIKey(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.';
    let result = '';
    
    // Preserve original length if reasonable, otherwise use 32 characters
    const length = Math.min(Math.max(original.length, 20), 64);
    
    for (let i = 0; i < length; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic database URL replacement
   * @param {string} original 
   * @returns {string}
   */
  generateDatabaseURL(original) {
    const hash = this.simpleHash(original);
    const protocol = original.split('://')[0];
    const dbName = `db${Math.abs(hash) % 10000}`;
    const host = `host${Math.abs(hash >> 8) % 1000}.example.com`;
    const port = 5432 + (Math.abs(hash >> 16) % 1000);
    
    return `${protocol}://user:pass@${host}:${port}/${dbName}`;
  }

  /**
   * Generate deterministic credit card replacement
   * @param {string} original 
   * @returns {string}
   */
  generateCreditCard(original) {
    // Always return a safe test credit card number
    return '4111111111111111'; // Visa test number
  }

  /**
   * Generate deterministic SSN replacement
   * @param {string} original 
   * @returns {string}
   */
  generateSSN(original) {
    const hash = this.simpleHash(original);
    const area = 100 + (Math.abs(hash) % 665); // Valid area codes 001-665
    const group = 10 + (Math.abs(hash >> 8) % 90); // Valid group codes 01-99
    const serial = 1000 + (Math.abs(hash >> 16) % 8999); // Valid serial 0001-9999
    
    const separator = original.includes('-') ? '-' : 
                     original.includes('.') ? '.' : 
                     original.includes(' ') ? ' ' : '';
    
    return `${area.toString().padStart(3, '0')}${separator}${group.toString().padStart(2, '0')}${separator}${serial.toString().padStart(4, '0')}`;
  }

  /**
   * Generate deterministic private key replacement
   * @param {string} original 
   * @returns {string}
   */
  generatePrivateKey(original) {
    const keyType = original.includes('RSA') ? 'RSA' : 
                   original.includes('EC') ? 'EC' : 
                   original.includes('DSA') ? 'DSA' : '';
    
    return `-----BEGIN ${keyType} PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
[REDACTED PRIVATE KEY CONTENT]
-----END ${keyType} PRIVATE KEY-----`;
  }

  /**
   * Generate deterministic Slack token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateSlackToken(original) {
    const hash = this.simpleHash(original);
    const prefix = original.substring(0, 4); // Keep xoxb, xoxp, etc.
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-';
    let result = prefix + '-';
    
    // Generate remaining characters
    for (let i = 0; i < 20; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic Discord token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateDiscordToken(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    
    // Discord token format: [MN][23 chars].[6 chars].[27 chars]
    const prefix = original.charAt(0); // M or N
    let part1 = prefix;
    let part2 = '';
    let part3 = '';
    
    for (let i = 0; i < 23; i++) {
      part1 += chars[Math.abs(hash + i) % chars.length];
    }
    
    for (let i = 0; i < 6; i++) {
      part2 += chars[Math.abs(hash + i + 23) % chars.length];
    }
    
    for (let i = 0; i < 27; i++) {
      part3 += chars[Math.abs(hash + i + 29) % chars.length];
    }
    
    return `${part1}.${part2}.${part3}`;
  }

  /**
   * Generate deterministic GitLab PAT replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGitLabPAT(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
    let result = 'glpat-';
    
    for (let i = 0; i < 20; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic GitLab runner token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateGitLabRunnerToken(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = 'GR';
    
    for (let i = 0; i < 40; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic Stripe secret key replacement
   * @param {string} original 
   * @returns {string}
   */
  generateStripeSecretKey(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const mode = original.includes('live') ? 'live' : 'test';
    let result = `sk_${mode}_`;
    
    for (let i = 0; i < 24; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic Stripe publishable key replacement
   * @param {string} original 
   * @returns {string}
   */
  generateStripePublishableKey(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const mode = original.includes('live') ? 'live' : 'test';
    let result = `pk_${mode}_`;
    
    for (let i = 0; i < 24; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic Stripe webhook secret replacement
   * @param {string} original 
   * @returns {string}
   */
  generateStripeWebhookSecret(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = 'whsec_';
    
    for (let i = 0; i < 32; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic SendGrid API key replacement
   * @param {string} original 
   * @returns {string}
   */
  generateSendGridAPIKey(original) {
    const hash = this.simpleHash(original);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
    let part1 = '';
    let part2 = '';
    
    for (let i = 0; i < 22; i++) {
      part1 += chars[Math.abs(hash + i) % chars.length];
    }
    
    for (let i = 0; i < 43; i++) {
      part2 += chars[Math.abs(hash + i + 22) % chars.length];
    }
    
    return `SG.${part1}.${part2}`;
  }

  /**
   * Generate deterministic Twilio Account SID replacement
   * @param {string} original 
   * @returns {string}
   */
  generateTwilioAccountSID(original) {
    const hash = this.simpleHash(original);
    const chars = 'abcdef0123456789';
    let result = 'AC';
    
    for (let i = 0; i < 32; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic Twilio Auth Token replacement
   * @param {string} original 
   * @returns {string}
   */
  generateTwilioAuthToken(original) {
    const hash = this.simpleHash(original);
    const chars = 'abcdef0123456789';
    let result = 'SK';
    
    for (let i = 0; i < 32; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic hex key replacement
   * @param {string} original 
   * @returns {string}
   */
  generateHexKey(original) {
    const hash = this.simpleHash(original);
    const chars = 'abcdef0123456789';
    let result = '';
    
    // Preserve original length
    for (let i = 0; i < original.length; i++) {
      result += chars[Math.abs(hash + i) % chars.length];
    }
    
    return result;
  }

  /**
   * Generate deterministic repository URL replacement
   * @param {string} original 
   * @returns {string}
   */
  generateRepoURL(original) {
    const hash = this.simpleHash(original);
    const domain = original.includes('github.com') ? 'github.com' : 
                  original.includes('gitlab.com') ? 'gitlab.com' : 
                  original.includes('bitbucket.org') ? 'bitbucket.org' : 'github.com';
    
    const user = `user${Math.abs(hash) % 10000}`;
    const repo = `repo${Math.abs(hash >> 8) % 10000}`;
    
    return `https://${domain}/${user}/${repo}.git`;
  }

  /**
   * Simple hash function for deterministic replacement (fallback)
   * @param {string} str 
   * @returns {number}
   */
  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash;
  }

  /**
   * Generate SHA-256 based deterministic hash for replacement
   * @param {string} input - Input string to hash
   * @param {string} patternType - Type of pattern for additional entropy
   * @returns {Promise<number>} - Deterministic hash value
   */
  async sha256Hash(input, patternType = '') {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(input + patternType);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = new Uint8Array(hashBuffer);
      
      // Convert first 4 bytes to a 32-bit integer
      let hash = 0;
      for (let i = 0; i < 4; i++) {
        hash = (hash << 8) | hashArray[i];
      }
      return hash;
    } catch (error) {
      console.warn('SHA-256 not available, falling back to simple hash:', error);
      return this.simpleHash(input + patternType);
    }
  }

  /**
   * Base64 URL encode
   * @param {string} str 
   * @returns {string}
   */
  base64UrlEncode(str) {
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Generate random base64 URL string
   * @param {number} length 
   * @returns {string}
   */
  generateRandomBase64Url(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
    }
    return result;
  }
}

// Create global instance
window.sanitizer = new SanitizerEngine();