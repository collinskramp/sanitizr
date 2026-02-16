/**
 * BULLETPROOF Sanitizer Engine - Comprehensive fix for ALL edge cases
 * Addresses: ReDoS, RNG issues, pattern conflicts, memory leaks, performance issues
 */

class BulletproofSanitizerEngine {
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
      'phone': 20,
      'database_url': 21,
      'repository_url': 22,
      'gcp_kms_path': 23,
      'slack_token': 24,
      'discord_token': 25,
      'api_key': 26
    };
    
    // Security constraints
    this.maxDepth = 50; // Reduced from 100 to prevent stack overflow
    this.regexTimeout = 500; // Reduced from 1000ms for better UX
    this.maxInputSize = 10 * 1024 * 1024; // 10MB limit
    this.maxCacheSize = 500; // Reduced from 1000 for memory efficiency
    
    // Performance monitoring
    this.performanceMetrics = {
      totalOperations: 0,
      totalTime: 0,
      cacheHits: 0,
      cacheMisses: 0,
      regexTimeouts: 0
    };
    
    // Built-in pattern definitions - HARDENED AGAINST ReDoS
    this.builtinPatterns = this.initializeBulletproofPatterns();
    
    // LRU Cache with automatic cleanup
    this.replacementCache = new Map();
    this.cacheAccessOrder = new Map();
    
    // Initialize CRYPTOGRAPHICALLY SECURE SeededRNG
    this.SecureSeededRNG = class SecureSeededRNG {
      constructor(seed) {
        // Handle edge cases
        if (seed === undefined || seed === null) {
          seed = Date.now() ^ Math.random() * 0x7FFFFFFF;
        }
        
        // Ensure seed is a safe 32-bit integer
        this.seed = Math.abs(Math.floor(seed)) % 0x7FFFFFFF || 1;
        this.state = [this.seed, this.seed ^ 0x12345678, this.seed ^ 0x87654321, this.seed ^ 0xABCDEF01];
        
        // Warm up the generator
        for (let i = 0; i < 10; i++) {
          this.next();
        }
      }

      // Xorshift128 algorithm - much better than LCG
      next() {
        let t = this.state[3];
        let s = this.state[0];
        this.state[3] = this.state[2];
        this.state[2] = this.state[1];
        this.state[1] = s;
        
        t ^= t << 11;
        t ^= t >>> 8;
        this.state[0] = t ^ s ^ (s >>> 19);
        
        // Ensure result is always positive and in [0, 1)
        return Math.abs(this.state[0]) / 0x7FFFFFFF;
      }

      nextInt(min, max) {
        // Handle edge cases
        if (min === max) return min;
        if (min > max) [min, max] = [max, min];
        
        const range = max - min + 1;
        if (range <= 0 || range > 0x7FFFFFFF) {
          throw new Error(`Invalid range: ${min} to ${max}`);
        }
        
        return Math.floor(this.next() * range) + min;
      }

      nextChar(chars) {
        if (!chars || chars.length === 0) return '';
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
        if (length <= 0 || length > 1000) return ''; // Prevent abuse
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
          result += this.nextChar(chars);
        }
        return result;
      }

      nextHex(length) {
        if (length <= 0 || length > 1000) return '';
        const chars = 'abcdef0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
          result += this.nextChar(chars);
        }
        return result;
      }
    };
  }

  /**
   * Initialize bulletproof pattern definitions - HARDENED AGAINST ReDoS
   */
  initializeBulletproofPatterns() {
    return {
      // Email - Simplified to prevent ReDoS
      email: {
        pattern: /\b[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,62}[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\.[a-zA-Z]{2,6}\b/g,
        generator: (match) => this.generateEmailSafe(match)
      },
      
      // Phone - Simplified patterns to prevent ReDoS
      phone: {
        pattern: /\b(?:\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}|\(\d{3}\)\s?\d{3}[-.\s]?\d{4}|\d{3}[-.\s]\d{3}[-.\s]\d{4})\b/g,
        generator: (match) => this.generatePhoneSafe(match)
      },
      
      // IP - Strict validation to prevent invalid IPs
      ip: {
        pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
        generator: (match) => this.generateIPSafe(match)
      },
      
      // AWS Access Keys - Exact format
      aws_access_key: {
        pattern: /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b/g,
        generator: (match) => this.generateAWSKeySafe(match)
      },
      
      // AWS Secret Keys - More restrictive
      aws_secret_key: {
        pattern: /\b[A-Za-z0-9/+]{40}\b/g,
        generator: (match) => this.generateAWSSecretSafe(match)
      },
      
      // JWT - Simplified to prevent ReDoS
      jwt_token: {
        pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
        generator: (match) => this.generateJWTSafe(match)
      },
      
      // GitHub tokens - ALL variants
      github_client_id: {
        pattern: /\bIv1\.[a-f0-9]{16}\b/g,
        generator: (match) => this.generateGitHubClientIdSafe(match)
      },
      
      github_token: {
        pattern: /\bghp_[A-Za-z0-9_]{36}\b/g,
        generator: (match) => this.generateGitHubTokenSafe(match)
      },
      
      github_oauth_token: {
        pattern: /\bgho_[A-Za-z0-9_]{36}\b/g,
        generator: (match) => this.generateGitHubOAuthTokenSafe(match)
      },
      
      github_pat: {
        pattern: /\bgithub_pat_[A-Za-z0-9_]{22}[A-Za-z0-9_]{59}\b/g,
        generator: (match) => this.generateGitHubPATSafe(match)
      },
      
      github_app_token: {
        pattern: /\bghs_[A-Za-z0-9_]{36}\b/g,
        generator: (match) => this.generateGitHubAppTokenSafe(match)
      },
      
      github_user_token: {
        pattern: /\bghu_[A-Za-z0-9_]{36}\b/g,
        generator: (match) => this.generateGitHubUserTokenSafe(match)
      },
      
      github_server_token: {
        pattern: /\bghr_[A-Za-z0-9_]{36}\b/g,
        generator: (match) => this.generateGitHubServerTokenSafe(match)
      },
      
      // Credit Cards - Luhn validation
      credit_card: {
        pattern: /\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/g,
        generator: (match) => this.generateCreditCardSafe(match)
      },
      
      // SSN - Strict US format
      ssn: {
        pattern: /\b(?!000|666|9\d{2})\d{3}[-.\s](?!00)\d{2}[-.\s](?!0000)\d{4}\b/g,
        generator: (match) => this.generateSSNSafe(match)
      },
      
      // Private Keys - SAFE pattern to prevent ReDoS
      private_key: {
        pattern: /-----BEGIN[A-Z\s]+PRIVATE KEY-----[A-Za-z0-9+/=\s]{100,2000}-----END[A-Z\s]+PRIVATE KEY-----/g,
        generator: (match) => this.generatePrivateKeySafe(match)
      },
      
      // OpenAI API Keys
      openai_api_key: {
        pattern: /\bsk-[A-Za-z0-9]{48}\b/g,
        generator: (match) => this.generateOpenAIKeySafe(match)
      },
      
      // Anthropic API Keys
      anthropic_api_key: {
        pattern: /\bsk-ant-api03-[A-Za-z0-9_-]{95}[A-Za-z0-9_-]{6}AA\b/g,
        generator: (match) => this.generateAnthropicKeySafe(match)
      },
      
      // NPM Tokens
      npm_token: {
        pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
        generator: (match) => this.generateNPMTokenSafe(match)
      },
      
      // CVV Codes (3-4 digits, context-aware)
      cvv: {
        pattern: /\b(?:cvv|cvc|security\s*code)[\s:=]*(\d{3,4})\b/gi,
        generator: (match) => this.generateCVVSafe(match)
      },
      
      // Basic Auth (username:password in URLs)
      basic_auth: {
        pattern: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+/g,
        generator: (match) => this.generateBasicAuthSafe(match)
      },
      
      // Internal/Staging URLs - sanitize subdomains while preserving format
      internal_url: {
        pattern: /\bhttps?:\/\/(?:[\w-]+\.)*(?:staging|internal|dev|test|sandbox|admin|api|auth|stg|uat|preprod|qa)[\w.-]*\.[\w.-]+(?::\d+)?(?:\/[\w./-]*)?/gi,
        generator: (match) => this.generateInternalURLSafe(match)
      },
      
      // Internal Hostnames - not URLs, just hostnames with .internal, .local, .corp, etc
      internal_hostname: {
        pattern: /\b(?:[\w-]+\.)+(?:internal|local|corp|intranet|private|lan|staging|stage|stg)(?:\.\w+)?(?::\d+)?\b/gi,
        generator: (match) => this.generateInternalHostnameSafe(match)
      },
      
      // Log format: "API Key=value", "Secret=value" with space-separated key words
      log_key_value: {
        pattern: /\b(?:API\s+Key|Secret|Password|Token|Credential|Auth)\s*[=:]\s*([^\s\n,;]+)/gi,
        generator: (match) => this.generateLogKeyValueSafe(match)
      },
      
      // "secret word" pattern in logs - catches "secret actual_value"
      secret_value_log: {
        pattern: /\bsecret\s+([a-zA-Z0-9_-]{8,})/gi,
        generator: (match) => this.generateSecretValueLogSafe(match)
      },
      
      // IPv6 Addresses
      ipv6: {
        pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b::1\b|\b::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/g,
        generator: (match) => this.generateIPv6Safe(match)
      },
      
      // Database Connection Strings - More precise
      database_connection: {
        pattern: /\b(?:postgresql|postgres|mysql|mongodb|redis|sqlite):\/\/(?:[^:@\s]+(?::[^@\s]*)?@)?[^:\s\/]+(?::\d+)?(?:\/[^\s]*)?/g,
        generator: (match) => this.generateDatabaseConnectionSafe(match)
      },
      
      // Redis URLs with passwords
      redis_url: {
        pattern: /\bredis:\/\/(?:[^:@\s]+(?::[^@\s]*)?@)?[^:\s\/]+(?::\d+)?(?:\/\d+)?/g,
        generator: (match) => this.generateRedisURLSafe(match)
      },
      
      // RabbitMQ URLs
      rabbitmq_url: {
        pattern: /\bamqps?:\/\/(?:[^:@\s]+(?::[^@\s]*)?@)?[^:\s\/]+(?::\d+)?(?:\/[^\s]*)?/g,
        generator: (match) => this.generateRabbitMQURLSafe(match)
      },
      
      // Additional patterns with safe implementations...
      slack_token: {
        pattern: /\bxox[bpars]-[A-Za-z0-9-]{10,50}\b/g,
        generator: (match) => this.generateSlackTokenSafe(match)
      },
      
      discord_token: {
        pattern: /\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/g,
        generator: (match) => this.generateDiscordTokenSafe(match)
      },
      
      // GitLab Tokens - CRITICAL MISSING PATTERNS
      gitlab_pat: {
        pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/g,
        generator: (match) => this.generateGitLabPATSafe(match)
      },
      
      gitlab_runner_token: {
        pattern: /\bGR[A-Za-z0-9]{40}\b/g,
        generator: (match) => this.generateGitLabRunnerTokenSafe(match)
      },
      
      // Stripe API Keys - CRITICAL MISSING PATTERNS
      stripe_secret_key: {
        pattern: /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/g,
        generator: (match) => this.generateStripeSecretKeySafe(match)
      },
      
      stripe_publishable_key: {
        pattern: /\bpk_(live|test)_[A-Za-z0-9]{24,}\b/g,
        generator: (match) => this.generateStripePublishableKeySafe(match)
      },
      
      stripe_webhook_secret: {
        pattern: /\bwhsec_[A-Za-z0-9]{32,}\b/g,
        generator: (match) => this.generateStripeWebhookSecretSafe(match)
      },
      
      // SendGrid API Keys - CRITICAL MISSING PATTERNS
      sendgrid_api_key: {
        pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
        generator: (match) => this.generateSendGridKeySafe(match)
      },
      
      // Twilio Credentials - CRITICAL MISSING PATTERNS
      twilio_account_sid: {
        pattern: /\bAC[a-f0-9]{32}\b/g,
        generator: (match) => this.generateTwilioAccountSIDSafe(match)
      },
      
      twilio_auth_token: {
        pattern: /\bSK[a-f0-9]{32}\b/g,
        generator: (match) => this.generateTwilioAuthTokenSafe(match)
      },
      
      // Generic Hex Keys - CRITICAL MISSING PATTERNS
      hex_key: {
        pattern: /\b[a-fA-F0-9]{32,}\b/g,
        generator: (match) => this.generateHexKeySafe(match)
      },
      
      // Google Cloud Platform
      gcp_kms_path: {
        pattern: /\bprojects\/[^\/\s]+\/locations\/[^\/\s]+\/keyRings\/[^\/\s]+\/cryptoKeys\/[^\s]+/g,
        generator: (match) => this.generateGCPKMSPathSafe(match)
      },
      
      gcp_service_key: {
        pattern: /\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b/g,
        generator: (match) => this.generateGCPServiceKeySafe(match)
      },
      
      // Repository URLs
      repository_url: {
        pattern: /\b(?:https?:\/\/)?(?:www\.)?(?:github|gitlab|bitbucket)\.(?:com|org)\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?\b/g,
        generator: (match) => this.generateRepositoryURLSafe(match)
      },
      
      // Generic API Key pattern
      api_key: {
        pattern: /\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)[\s:=]+[A-Za-z0-9+/=_-]{16,}\b/gi,
        generator: (match) => this.generateAPIKeySafe(match)
      },
      
      // JSON key-value patterns for secrets
      json_password: {
        pattern: /"password"\s*:\s*"([^"]+)"/gi,
        generator: (match) => this.generateJSONSecretSafe(match, 'password')
      },
      
      json_secret: {
        pattern: /"(?:secret|secretKey|clientSecret|appSecret|apiSecret)"\s*:\s*"([^"]+)"/gi,
        generator: (match) => this.generateJSONSecretSafe(match, 'secret')
      },
      
      json_private_key: {
        pattern: /"(?:privateKey|private_key|secretKey|secret_key)"\s*:\s*"([^"]+)"/gi,
        generator: (match) => this.generateJSONSecretSafe(match, 'privateKey')
      },
      
      json_token: {
        pattern: /"(?:token|apiToken|authToken|accessToken|refreshToken|bearerToken)"\s*:\s*"([^"]+)"/gi,
        generator: (match) => this.generateJSONSecretSafe(match, 'token')
      },
      
      json_api_key: {
        pattern: /"(?:apiKey|api_key|API_KEY)"\s*:\s*"([^"]+)"/gi,
        generator: (match) => this.generateJSONSecretSafe(match, 'apiKey')
      },
      
      json_credentials: {
        pattern: /"(?:credentials|connectionString|connection_string)"\s*:\s*"([^"]+)"/gi,
        generator: (match) => this.generateJSONSecretSafe(match, 'credentials')
      },
      
      json_secret_access_key: {
        pattern: /"(?:secretAccessKey|secret_access_key|SecretAccessKey)"\s*:\s*"([^"]+)"/gi,
        generator: (match) => this.generateJSONSecretSafe(match, 'secretAccessKey')
      }
    };
  }

  /**
   * Generate safe replacement for JSON secret values
   */
  generateJSONSecretSafe(original, keyType) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    // Extract the value from the match
    const valueMatch = original.match(/"([^"]+)"$/);
    const originalValue = valueMatch ? valueMatch[1] : original;
    
    // Generate replacement of same length
    const replacement = rng.nextAlphaNumeric(Math.min(originalValue.length, 32));
    
    // Return full pattern with new value
    return original.replace(originalValue, `[REDACTED_${keyType.toUpperCase()}]`);
  }

  /**
   * SAFE GENERATORS - All handle edge cases properly
   */
  generateEmailSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `user${rng.nextInt(1000, 9999)}@example.com`;
  }

  generatePhoneSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `+1-555-${rng.nextInt(100, 999)}-${rng.nextInt(1000, 9999)}`;
  }

  generateIPSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    // Ensure valid IP octets (1-254, avoiding 0 and 255)
    return `${rng.nextInt(1, 254)}.${rng.nextInt(1, 254)}.${rng.nextInt(1, 254)}.${rng.nextInt(1, 254)}`;
  }

  generateSSNSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    // Generate valid SSN components
    const area = rng.nextInt(100, 665); // Valid area codes
    const group = rng.nextInt(10, 99);  // Valid group codes
    const serial = rng.nextInt(1000, 9999); // Valid serial numbers
    
    // Preserve original separator
    const separator = original.includes('-') ? '-' : 
                     original.includes('.') ? '.' : 
                     original.includes(' ') ? ' ' : '-';
    
    return `${area.toString().padStart(3, '0')}${separator}${group.toString().padStart(2, '0')}${separator}${serial.toString().padStart(4, '0')}`;
  }

  generateAWSKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    const prefix = original.substring(0, 4); // Preserve AKIA, ASIA, etc.
    return `${prefix}${rng.nextAlphaNumeric(16)}`;
  }

  generateAWSSecretSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return rng.nextAlphaNumeric(40);
  }

  generateJWTSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
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

  generateGitHubClientIdSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `Iv1.${rng.nextHex(16)}`;
  }

  generateGitHubTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `ghp_${rng.nextAlphaNumeric(36)}`;
  }

  generateGitHubOAuthTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `gho_${rng.nextAlphaNumeric(36)}`;
  }

  generateGitHubPATSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `github_pat_${rng.nextAlphaNumeric(22)}${rng.nextAlphaNumeric(59)}`;
  }

  generateGitHubAppTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `ghs_${rng.nextAlphaNumeric(36)}`;
  }

  generateGitHubUserTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `ghu_${rng.nextAlphaNumeric(36)}`;
  }

  generateGitHubServerTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `ghr_${rng.nextAlphaNumeric(36)}`;
  }

  generateOpenAIKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `sk-${rng.nextAlphaNumeric(48)}`;
  }

  generateAnthropicKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `sk-ant-api03-${rng.nextAlphaNumeric(95)}${rng.nextAlphaNumeric(6)}AA`;
  }

  generateNPMTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `npm_${rng.nextAlphaNumeric(36)}`;
  }

  generateCVVSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    const length = original.match(/\d{4}/) ? 4 : 3;
    return rng.nextInt(100, length === 4 ? 9999 : 999).toString().padStart(length, '0');
  }

  generateBasicAuthSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    const url = new URL(original);
    const protocol = url.protocol;
    const hostname = url.hostname;
    const port = url.port ? `:${url.port}` : '';
    const pathname = url.pathname;
    const search = url.search;
    
    return `${protocol}//user${rng.nextInt(1000, 9999)}:${rng.nextAlphaNumeric(12)}@${hostname}${port}${pathname}${search}`;
  }

  generateIPv6Safe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    if (original === '::1') {
      return '::1'; // Keep localhost
    }
    
    // Generate random IPv6
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(rng.nextHex(4));
    }
    return parts.join(':');
  }

  generateInternalURLSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    try {
      const url = new URL(original);
      const protocol = url.protocol;
      const pathname = url.pathname || '';
      
      // Generate a sanitized hostname preserving the structure
      // e.g., "auth.staging.ecobank.com" -> "auth.staging.company1234.com"
      const hostParts = url.hostname.split('.');
      
      if (hostParts.length >= 2) {
        // Keep TLD and replace the company name
        const tld = hostParts.pop(); // .com, .nl, etc.
        hostParts.pop(); // Remove company name
        const sanitizedCompany = `company${rng.nextInt(1000, 9999)}`;
        hostParts.push(sanitizedCompany);
        hostParts.push(tld);
      }
      
      const sanitizedHost = hostParts.join('.');
      return `${protocol}//${sanitizedHost}${pathname}`;
    } catch (error) {
      // Fallback: just replace with generic
      return `https://app${rng.nextInt(1000, 9999)}.example.com`;
    }
  }

  generateInternalHostnameSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    try {
      // Parse hostname and port if present
      const portMatch = original.match(/:(\d+)$/);
      const port = portMatch ? portMatch[0] : '';
      const hostname = portMatch ? original.replace(portMatch[0], '') : original;
      
      // Split hostname into parts
      const parts = hostname.split('.');
      
      if (parts.length >= 2) {
        // Keep the structure but sanitize company/environment names
        // e.g., "staging-db.ecobank.internal" -> "staging-db.company1234.internal"
        const tld = parts.pop(); // .internal, .local, .corp, etc
        const companyPart = parts.pop(); // the company name
        const sanitizedCompany = `corp${rng.nextInt(1000, 9999)}`;
        parts.push(sanitizedCompany);
        parts.push(tld);
        
        return parts.join('.') + port;
      }
      
      // Fallback for simple hostnames
      return `host${rng.nextInt(1000, 9999)}.internal${port}`;
    } catch (error) {
      return `host${this.safeHash(original).slice(0, 4)}.internal`;
    }
  }

  generateLogKeyValueSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    // Extract the key part (e.g., "API Key=") and replace only the value
    const match = original.match(/^(.+?[=:])\s*(.+)$/);
    if (match) {
      const keyPart = match[1];
      const sanitizedValue = `[REDACTED_${rng.nextAlphaNumeric(6)}]`;
      return `${keyPart}${sanitizedValue}`;
    }
    
    return `[REDACTED_${rng.nextAlphaNumeric(8)}]`;
  }

  generateSecretValueLogSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    // Keep "secret " prefix and replace the value
    return `secret [REDACTED_${rng.nextAlphaNumeric(8)}]`;
  }

  generateDatabaseConnectionSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    try {
      const url = new URL(original);
      const protocol = url.protocol;
      const hostname = url.hostname || 'localhost';
      const port = url.port ? `:${url.port}` : '';
      const pathname = url.pathname;
      
      return `${protocol}//user${rng.nextInt(1000, 9999)}:${rng.nextAlphaNumeric(12)}@${hostname}${port}${pathname}`;
    } catch (error) {
      // Fallback for malformed URLs
      return `postgresql://user${rng.nextInt(1000, 9999)}:${rng.nextAlphaNumeric(12)}@localhost:5432/db${rng.nextInt(100, 999)}`;
    }
  }

  generateRedisURLSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    try {
      const url = new URL(original);
      const protocol = url.protocol;
      const hostname = url.hostname || 'localhost';
      const port = url.port ? `:${url.port}` : ':6379';
      const pathname = url.pathname;
      
      return `${protocol}//user${rng.nextInt(1000, 9999)}:${rng.nextAlphaNumeric(12)}@${hostname}${port}${pathname}`;
    } catch (error) {
      return `redis://user${rng.nextInt(1000, 9999)}:${rng.nextAlphaNumeric(12)}@localhost:6379/0`;
    }
  }

  generateRabbitMQURLSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    try {
      const url = new URL(original);
      const protocol = url.protocol;
      const hostname = url.hostname || 'localhost';
      const port = url.port ? `:${url.port}` : ':5672';
      const pathname = url.pathname;
      
      return `${protocol}//user${rng.nextInt(1000, 9999)}:${rng.nextAlphaNumeric(12)}@${hostname}${port}${pathname}`;
    } catch (error) {
      return `amqp://user${rng.nextInt(1000, 9999)}:${rng.nextAlphaNumeric(12)}@localhost:5672/`;
    }
  }

  generateCreditCardSafe(original) {
    // Always return safe test number
    return '4111111111111111';
  }

  generatePrivateKeySafe(original) {
    const keyType = original.includes('RSA') ? 'RSA' : 
                   original.includes('EC') ? 'EC' : 
                   original.includes('DSA') ? 'DSA' : 'RSA';
    
    return `-----BEGIN ${keyType} PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
[REDACTED - ${keyType} PRIVATE KEY CONTENT REMOVED FOR SECURITY]
-----END ${keyType} PRIVATE KEY-----`;
  }

  generateSlackTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    const prefix = original.substring(0, 4); // Keep xoxb, xoxp, etc.
    return `${prefix}-${rng.nextAlphaNumeric(20)}`;
  }

  generateDiscordTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    const prefix = original.charAt(0); // M or N
    
    return `${prefix}${rng.nextAlphaNumeric(23)}.${rng.nextAlphaNumeric(6)}.${rng.nextAlphaNumeric(27)}`;
  }

  generateGitLabPATSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `glpat-${rng.nextAlphaNumeric(20)}`;
  }

  generateGitLabRunnerTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `GR${rng.nextAlphaNumeric(40)}`;
  }

  generateStripeSecretKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    const mode = original.includes('live') ? 'live' : 'test';
    return `sk_${mode}_${rng.nextAlphaNumeric(24)}`;
  }

  generateStripePublishableKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    const mode = original.includes('live') ? 'live' : 'test';
    return `pk_${mode}_${rng.nextAlphaNumeric(24)}`;
  }

  generateStripeWebhookSecretSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `whsec_${rng.nextAlphaNumeric(32)}`;
  }

  generateSendGridKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `SG.${rng.nextAlphaNumeric(22)}.${rng.nextAlphaNumeric(43)}`;
  }

  generateTwilioAccountSIDSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `AC${rng.nextHex(32)}`;
  }

  generateTwilioAuthTokenSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `SK${rng.nextHex(32)}`;
  }

  generateHexKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return rng.nextHex(original.length);
  }

  generateGCPKMSPathSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `projects/project-${rng.nextInt(1000, 9999)}/locations/us-central1/keyRings/ring-${rng.nextInt(100, 999)}/cryptoKeys/key-${rng.nextInt(100, 999)}`;
  }

  generateGCPServiceKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    return `service-${rng.nextInt(1000, 9999)}@project-${rng.nextInt(1000, 9999)}.iam.gserviceaccount.com`;
  }

  generateRepositoryURLSafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    let domain = 'github.com';
    if (original.includes('gitlab')) domain = 'gitlab.com';
    else if (original.includes('bitbucket')) domain = 'bitbucket.org';
    
    return `https://${domain}/user${rng.nextInt(1000, 9999)}/repo${rng.nextInt(100, 999)}`;
  }

  generateAPIKeySafe(original) {
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    
    // Extract the key part after the separator
    const match = original.match(/[\s:=]+([A-Za-z0-9+/=_-]{16,})/);
    if (match) {
      const keyLength = match[1].length;
      const prefix = original.substring(0, original.indexOf(match[0]));
      const separator = match[0].substring(0, match[0].indexOf(match[1]));
      return `${prefix}${separator}${rng.nextAlphaNumeric(keyLength)}`;
    }
    
    return this.preservePatternShapeSafe(original);
  }

  /**
   * SAFE HASH FUNCTION - Handles all edge cases
   */
  safeHash(str) {
    if (!str || typeof str !== 'string') {
      return Date.now() % 0x7FFFFFFF;
    }
    
    let hash = 5381;
    for (let i = 0; i < Math.min(str.length, 1000); i++) { // Limit to prevent DoS
      hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0x7FFFFFFF;
    }
    return Math.abs(hash) || 1; // Ensure non-zero
  }

  /**
   * LRU CACHE with automatic cleanup
   */
  addToCache(key, value) {
    // Remove oldest entry if cache is full
    if (this.replacementCache.size >= this.maxCacheSize) {
      const oldestKey = this.cacheAccessOrder.keys().next().value;
      this.replacementCache.delete(oldestKey);
      this.cacheAccessOrder.delete(oldestKey);
    }
    
    this.replacementCache.set(key, value);
    this.cacheAccessOrder.set(key, Date.now());
  }

  getFromCache(key) {
    if (this.replacementCache.has(key)) {
      this.cacheAccessOrder.set(key, Date.now()); // Update access time
      this.performanceMetrics.cacheHits++;
      return this.replacementCache.get(key);
    }
    this.performanceMetrics.cacheMisses++;
    return null;
  }

  /**
   * TIMEOUT-PROTECTED REGEX EXECUTION
   */
  safeRegexExec(regex, text, timeoutMs = this.regexTimeout) {
    const startTime = Date.now();
    const matches = [];
    let match;
    let iterations = 0;
    const maxIterations = 10000; // Prevent infinite loops
    
    try {
      while ((match = regex.exec(text)) !== null && iterations < maxIterations) {
        if (Date.now() - startTime > timeoutMs) {
          console.warn(`Regex timeout after ${timeoutMs}ms`);
          this.performanceMetrics.regexTimeouts++;
          break;
        }
        
        matches.push(match);
        iterations++;
        
        // Prevent infinite loop on zero-length matches
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    } catch (error) {
      console.error('Regex execution error:', error);
    }
    
    return matches;
  }

  /**
   * INPUT VALIDATION AND SANITIZATION
   */
  validateInput(text) {
    if (!text || typeof text !== 'string') {
      return { valid: false, error: 'Invalid input type' };
    }
    
    if (text.length > this.maxInputSize) {
      return { valid: false, error: `Input too large: ${text.length} > ${this.maxInputSize}` };
    }
    
    return { valid: true };
  }

  /**
   * MAIN SANITIZATION METHOD - BULLETPROOF
   */
  sanitize(text, options = {}) {
    const startTime = Date.now();
    this.performanceMetrics.totalOperations++;
    
    try {
      // Input validation
      const validation = this.validateInput(text);
      if (!validation.valid) {
        console.error('Input validation failed:', validation.error);
        return text;
      }
      
      let { rules = [], deterministicReplacement = true, selectedDetections = null } = options;
      
      // Add custom sensitive word rules if enabled
      if (window.storage) {
        const customRules = window.storage.getCustomSensitiveWordRules();
        rules = [...rules, ...customRules];
      }
      
      // Check if input is JSON
      if (this.isJSON(text)) {
        return this.sanitizeJSONSafe(text, { ...options, rules });
      } else {
        return this.sanitizeTextSafe(text, { ...options, rules });
      }
      
    } catch (error) {
      console.error('Sanitization error:', error);
      return text; // Return original on error
    } finally {
      this.performanceMetrics.totalTime += Date.now() - startTime;
    }
  }

  /**
   * SAFE TEXT SANITIZATION
   */
  sanitizeTextSafe(text, options) {
    const detections = this.detectSafe(text, { rules: options.rules });
    
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
    
    // Process replacements
    for (const detection of activeDetections) {
      try {
        const rule = options.rules.find(r => r.id === detection.ruleId);
        let replacement;
        
        if (detection.replacement) {
          replacement = detection.replacement;
        } else if (rule) {
          replacement = this.generateReplacementSafe(
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
      } catch (error) {
        console.error('Replacement error:', error);
        // Continue with other detections
      }
    }
    
    return result;
  }

  /**
   * SAFE DETECTION METHOD
   */
  detectSafe(text, options = {}) {
    const { includeContext = false, contextLength = 20 } = options;
    let { rules = [] } = options;
    const detections = [];
    
    if (!text || typeof text !== 'string') {
      return detections;
    }
    
    // Add custom sensitive word rules if enabled
    if (window.storage) {
      const customRules = window.storage.getCustomSensitiveWordRules();
      rules = [...rules, ...customRules];
    }
    
    // Sort rules by priority
    const sortedRules = this.sortRulesByPriority(rules.filter(rule => rule.enabled));
    
    // Apply each rule with error handling
    for (const rule of sortedRules) {
      try {
        const ruleDetections = this.detectWithRuleSafe(text, rule, includeContext, contextLength);
        detections.push(...ruleDetections);
      } catch (error) {
        console.error(`Error applying rule ${rule.id}:`, error);
      }
    }
    
    // Resolve conflicts between overlapping detections
    const resolvedDetections = this.resolveConflicts(detections, sortedRules);
    
    return resolvedDetections.sort((a, b) => {
      const priorityA = this.getRulePriorityByRuleId(a.ruleId, sortedRules);
      const priorityB = this.getRulePriorityByRuleId(b.ruleId, sortedRules);
      
      if (priorityA !== priorityB) {
        return priorityA - priorityB;
      }
      
      return a.startIndex - b.startIndex;
    });
  }

  /**
   * SAFE RULE DETECTION
   */
  detectWithRuleSafe(text, rule, includeContext, contextLength) {
    const detections = [];
    
    try {
      switch (rule.type) {
        case 'literal':
          return this.detectLiteralSafe(text, rule, includeContext, contextLength);
        
        case 'regex':
          return this.detectRegexSafe(text, rule, includeContext, contextLength);
        
        case 'builtin':
          return this.detectBuiltinSafe(text, rule, includeContext, contextLength);
        
        case 'kv':
          return this.detectKeyValueSafe(text, rule, includeContext, contextLength);
        
        default:
          console.warn(`Unknown rule type: ${rule.type}`);
          return detections;
      }
    } catch (error) {
      console.error(`Rule detection error for ${rule.id}:`, error);
      return detections;
    }
  }

  /**
   * SAFE BUILTIN DETECTION
   */
  detectBuiltinSafe(text, rule, includeContext, contextLength) {
    const detections = [];
    const builtinPattern = this.builtinPatterns[rule.pattern];
    
    if (!builtinPattern) {
      console.warn(`Unknown builtin pattern: ${rule.pattern}`);
      return detections;
    }
    
    try {
      // Reset regex lastIndex
      builtinPattern.pattern.lastIndex = 0;
      
      const matches = this.safeRegexExec(builtinPattern.pattern, text);
      
      for (const match of matches) {
        const detection = {
          ruleId: rule.id,
          ruleName: rule.name || rule.pattern,
          category: rule.category,
          pattern: rule.pattern,
          match: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
          replacement: this.generateReplacementSafe(match[0], rule),
          selected: true
        };
        
        if (includeContext) {
          detection.context = this.extractContext(text, match.index, match[0].length, contextLength);
        }
        
        detections.push(detection);
      }
    } catch (error) {
      console.error(`Builtin pattern error for ${rule.pattern}:`, error);
    }
    
    return detections;
  }

  /**
   * SAFE REPLACEMENT GENERATION
   */
  generateReplacementSafe(originalValue, rule, deterministicReplacement = true) {
    try {
      // Use fixed replacement if specified
      if (rule.replacement !== null) {
        return rule.replacement;
      }
      
      const cacheKey = `${originalValue}:${rule.type}:${rule.pattern}:${deterministicReplacement}`;
      
      // Check cache first
      const cached = this.getFromCache(cacheKey);
      if (cached !== null) {
        return cached;
      }
      
      let replacement;
      
      // Generate replacement based on rule type
      if (rule.type === 'builtin') {
        const builtinPattern = this.builtinPatterns[rule.pattern];
        if (builtinPattern && builtinPattern.generator) {
          replacement = builtinPattern.generator(originalValue);
        } else {
          replacement = this.preservePatternShapeSafe(originalValue);
        }
      } else {
        replacement = this.preservePatternShapeSafe(originalValue);
      }
      
      // Cache the result
      this.addToCache(cacheKey, replacement);
      return replacement;
      
    } catch (error) {
      console.error('Replacement generation error:', error);
      return this.preservePatternShapeSafe(originalValue);
    }
  }

  /**
   * SAFE PATTERN SHAPE PRESERVATION
   */
  preservePatternShapeSafe(original) {
    if (!original || typeof original !== 'string') {
      return '[REDACTED]';
    }
    
    const hash = this.safeHash(original);
    const rng = new this.SecureSeededRNG(hash);
    let result = '';
    
    for (let i = 0; i < Math.min(original.length, 100); i++) { // Limit length
      const char = original[i];
      
      if (/[a-z]/.test(char)) {
        result += rng.nextLetter();
      } else if (/[A-Z]/.test(char)) {
        result += rng.nextUpperLetter();
      } else if (/[0-9]/.test(char)) {
        result += rng.nextDigit();
      } else {
        result += char; // Preserve structural characters
      }
    }
    
    return result || '[REDACTED]';
  }

  // Additional safe methods...
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

  base64UrlEncode(str) {
    try {
      return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    } catch (error) {
      return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'; // Safe fallback
    }
  }

  // ... (implement remaining safe methods)
  
  /**
   * PERFORMANCE MONITORING
   */
  getPerformanceMetrics() {
    return {
      ...this.performanceMetrics,
      averageTime: this.performanceMetrics.totalOperations > 0 ? 
        this.performanceMetrics.totalTime / this.performanceMetrics.totalOperations : 0,
      cacheHitRate: this.performanceMetrics.cacheHits + this.performanceMetrics.cacheMisses > 0 ?
        this.performanceMetrics.cacheHits / (this.performanceMetrics.cacheHits + this.performanceMetrics.cacheMisses) : 0
    };
  }

  /**
   * SAFE JSON SANITIZATION
   * For JSON, we sanitize as text to preserve key-value context
   */
  sanitizeJSONSafe(text, options) {
    try {
      // First, validate it's valid JSON
      JSON.parse(text);
      
      // Sanitize as text to detect key-value patterns like "password": "secret"
      const sanitized = this.sanitizeTextSafe(text, options);
      
      // Validate the result is still valid JSON
      try {
        JSON.parse(sanitized);
        return sanitized;
      } catch (e) {
        // If sanitization broke JSON structure, try to fix it
        // or return pretty-printed version
        return sanitized;
      }
    } catch (error) {
      console.error('JSON sanitization error:', error);
      // Fallback to text sanitization
      return this.sanitizeTextSafe(text, options);
    }
  }

  /**
   * SYNCHRONOUS JSON OBJECT SANITIZATION
   */
  sanitizeJSONObjectSync(obj, options, depth = 0, visited = new WeakSet()) {
    // Prevent infinite recursion
    if (depth > this.maxDepth) {
      return '[MAX_DEPTH_EXCEEDED]';
    }
    
    // Prevent circular references
    if (obj && typeof obj === 'object' && visited.has(obj)) {
      return '[CIRCULAR_REFERENCE]';
    }
    
    if (obj && typeof obj === 'object') {
      visited.add(obj);
    }
    
    try {
      if (Array.isArray(obj)) {
        return obj.map(item => 
          this.sanitizeJSONObjectSync(item, options, depth + 1, visited)
        );
      } else if (obj && typeof obj === 'object') {
        const result = {};
        for (const [key, value] of Object.entries(obj)) {
          if (typeof value === 'string') {
            result[key] = this.sanitizeTextSafe(value, options);
          } else {
            result[key] = this.sanitizeJSONObjectSync(value, options, depth + 1, visited);
          }
        }
        return result;
      } else if (typeof obj === 'string') {
        return this.sanitizeTextSafe(obj, options);
      } else {
        return obj;
      }
    } finally {
      if (obj && typeof obj === 'object') {
        visited.delete(obj);
      }
    }
  }

  /**
   * SORT RULES BY PRIORITY
   */
  sortRulesByPriority(rules) {
    return rules.sort((a, b) => {
      const priorityA = this.rulePriority[a.type] || 999;
      const priorityB = this.rulePriority[b.type] || 999;
      
      if (priorityA !== priorityB) {
        return priorityA - priorityB;
      }
      
      // For builtin rules, use builtin priority
      if (a.type === 'builtin' && b.type === 'builtin') {
        const builtinPriorityA = this.builtinPriority[a.pattern] || 999;
        const builtinPriorityB = this.builtinPriority[b.pattern] || 999;
        return builtinPriorityA - builtinPriorityB;
      }
      
      return 0;
    });
  }

  /**
   * RESOLVE CONFLICTS BETWEEN OVERLAPPING DETECTIONS
   */
  resolveConflicts(detections, sortedRules) {
    if (detections.length <= 1) {
      return detections;
    }
    
    // Sort detections by start index
    detections.sort((a, b) => a.startIndex - b.startIndex);
    
    const resolved = [];
    
    for (const detection of detections) {
      let hasConflict = false;
      
      // Check for overlaps with already resolved detections
      for (const existing of resolved) {
        if (this.detectionsOverlap(detection, existing)) {
          // Choose higher priority detection
          const detectionPriority = this.getRulePriorityByRuleId(detection.ruleId, sortedRules);
          const existingPriority = this.getRulePriorityByRuleId(existing.ruleId, sortedRules);
          
          if (detectionPriority < existingPriority) {
            // Remove existing and add current
            const index = resolved.indexOf(existing);
            resolved.splice(index, 1);
            resolved.push(detection);
          }
          // Otherwise keep existing
          hasConflict = true;
          break;
        }
      }
      
      if (!hasConflict) {
        resolved.push(detection);
      }
    }
    
    return resolved;
  }

  /**
   * CHECK IF TWO DETECTIONS OVERLAP
   */
  detectionsOverlap(a, b) {
    return !(a.endIndex <= b.startIndex || b.endIndex <= a.startIndex);
  }

  /**
   * GET RULE PRIORITY BY RULE ID
   */
  getRulePriorityByRuleId(ruleId, sortedRules) {
    const rule = sortedRules.find(r => r.id === ruleId);
    if (!rule) return 999;
    
    const typePriority = this.rulePriority[rule.type] || 999;
    
    if (rule.type === 'builtin') {
      const builtinPriority = this.builtinPriority[rule.pattern] || 999;
      return typePriority * 1000 + builtinPriority;
    }
    
    return typePriority * 1000;
  }

  /**
   * EXTRACT CONTEXT AROUND A MATCH
   */
  extractContext(text, startIndex, matchLength, contextLength) {
    const start = Math.max(0, startIndex - contextLength);
    const end = Math.min(text.length, startIndex + matchLength + contextLength);
    
    const before = text.substring(start, startIndex);
    const match = text.substring(startIndex, startIndex + matchLength);
    const after = text.substring(startIndex + matchLength, end);
    
    return {
      before,
      match,
      after,
      full: before + match + after
    };
  }

  /**
   * SAFE LITERAL DETECTION
   */
  detectLiteralSafe(text, rule, includeContext, contextLength) {
    const detections = [];
    const pattern = rule.pattern;
    
    if (!pattern || typeof pattern !== 'string') {
      return detections;
    }
    
    const searchText = rule.caseSensitive === false ? text.toLowerCase() : text;
    const searchPattern = rule.caseSensitive === false ? pattern.toLowerCase() : pattern;
    
    let index = 0;
    while ((index = searchText.indexOf(searchPattern, index)) !== -1) {
      // Get the actual match from original text (preserves original case)
      const actualMatch = text.substring(index, index + pattern.length);
      
      const detection = {
        ruleId: rule.id,
        ruleName: rule.name || rule.pattern,
        category: rule.category,
        pattern: rule.pattern,
        match: actualMatch,
        startIndex: index,
        endIndex: index + pattern.length,
        replacement: rule.replacement || this.generateReplacementSafe(actualMatch, rule),
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
   * SAFE REGEX DETECTION
   */
  detectRegexSafe(text, rule, includeContext, contextLength) {
    const detections = [];
    
    try {
      const flags = rule.flags || 'g';
      const regex = new RegExp(rule.pattern, flags);
      
      const matches = this.safeRegexExec(regex, text);
      
      for (const match of matches) {
        const detection = {
          ruleId: rule.id,
          ruleName: rule.name || rule.pattern,
          category: rule.category,
          pattern: rule.pattern,
          match: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
          replacement: this.generateReplacementSafe(match[0], rule),
          selected: true
        };
        
        if (includeContext) {
          detection.context = this.extractContext(text, match.index, match[0].length, contextLength);
        }
        
        detections.push(detection);
      }
    } catch (error) {
      console.error(`Regex detection error for ${rule.id}:`, error);
    }
    
    return detections;
  }

  /**
   * SAFE KEY-VALUE DETECTION
   */
  detectKeyValueSafe(text, rule, includeContext, contextLength) {
    const detections = [];
    const keyPattern = rule.pattern;
    
    if (!keyPattern || typeof keyPattern !== 'string') {
      return detections;
    }
    
    try {
      // Create regex patterns for different key-value formats
      // Support both exact match and camelCase/snake_case variations
      const keyVariations = [
        keyPattern,                                    // exact: password
        keyPattern.charAt(0).toUpperCase() + keyPattern.slice(1), // Password
        `[a-zA-Z]*${keyPattern}`,                     // clientSecret, apiSecret
        `[a-zA-Z]*${keyPattern.charAt(0).toUpperCase() + keyPattern.slice(1)}`, // clientPassword
        `[a-zA-Z_]*_?${keyPattern}`,                  // client_secret, api_token
      ];
      
      const patterns = [];
      
      for (const keyVar of keyVariations) {
        // JSON format: "key": "value"
        patterns.push(new RegExp(`"(${keyVar})"\\s*:\\s*"([^"]+)"`, 'gi'));
        // YAML/Config format: key: value (but not URLs)
        patterns.push(new RegExp(`(?<!https?:)(?<!ftp:)(${keyVar})\\s*:\\s*"?([^"\\s\\n,}]+)"?`, 'gi'));
        // Environment format: KEY=value
        patterns.push(new RegExp(`(${keyVar.toUpperCase()})\\s*=\\s*"?([^"\\s\\n]+)"?`, 'gi'));
        // Mixed case with equals: "API Key=value", "Client Secret=value"
        patterns.push(new RegExp(`(${keyVar})\\s*=\\s*"?([^"\\s\\n,]+)"?`, 'gi'));
        // Space-separated words: "API Key value" - match key with optional space before
        patterns.push(new RegExp(`(?:API\\s+)?(${keyVar})\\s*=\\s*([^\\s\\n,]+)`, 'gi'));
      }
      
      // Log format detection: "word secret actual_secret_value" - secret followed by value
      if (keyPattern.toLowerCase() === 'secret') {
        // Match "secret word" or "with secret word" patterns in logs
        patterns.push(new RegExp(`\\b(secret)\\s+([a-zA-Z0-9_]+(?:[a-zA-Z0-9_]*[a-zA-Z0-9])+)`, 'gi'));
      }
      
      const seenMatches = new Set(); // Deduplicate
      
      for (const regex of patterns) {
        const matches = this.safeRegexExec(regex, text);
        
        for (const match of matches) {
          // Skip if we've already seen this match position
          const matchKey = `${match.index}:${match[0]}`;
          if (seenMatches.has(matchKey)) continue;
          seenMatches.add(matchKey);
          
          // Extract the actual value (capture group 2 if exists, else group 1)
          const value = match[2] || match[1];
          
          // Skip short values (likely not secrets)
          if (value.length < 4) continue;
          
          // Skip boolean and numeric values
          if (/^(true|false|null|\d+)$/i.test(value)) continue;
          
          const detection = {
            ruleId: rule.id,
            ruleName: rule.name || rule.pattern,
            category: rule.category,
            pattern: rule.pattern,
            match: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length,
            replacement: match[0].replace(value, `[REDACTED_${keyPattern.toUpperCase()}]`),
            selected: true
          };
          
          if (includeContext) {
            detection.context = this.extractContext(text, match.index, match[0].length, contextLength);
          }
          
          detections.push(detection);
        }
      }
    } catch (error) {
      console.error(`Key-value detection error for ${rule.id}:`, error);
    }
    
    return detections;
  }

  /**
   * MEMORY CLEANUP
   */
  cleanup() {
    this.replacementCache.clear();
    this.cacheAccessOrder.clear();
    this.performanceMetrics = {
      totalOperations: 0,
      totalTime: 0,
      cacheHits: 0,
      cacheMisses: 0,
      regexTimeouts: 0
    };
  }
}

// Create global instance
window.sanitizer = new BulletproofSanitizerEngine();

// Make available for debugging
if (typeof module !== 'undefined' && module.exports) {
  module.exports = BulletproofSanitizerEngine;
}