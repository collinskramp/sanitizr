/**
 * Storage Module - Handles localStorage operations and data persistence
 * Provides abstraction layer over browser storage with quota monitoring and error handling
 */

class StorageModule {
  constructor() {
    this.namespace = 'data-sanitizer-';
    this.keys = {
      rules: this.namespace + 'rules',
      profiles: this.namespace + 'profiles',
      settings: this.namespace + 'settings',
      history: this.namespace + 'history',
      currentProfile: this.namespace + 'current-profile'
    };
    
    // Storage constraints
    this.maxInputSize = 1024 * 1024; // 1MB
    this.quotaWarningThreshold = 0.8; // 80%
    this.quotaCriticalThreshold = 0.9; // 90%
    
    // Initialize storage
    this.initializeStorage();
  }

  /**
   * Initialize storage with default values if not present
   */
  initializeStorage() {
    try {
      // Check if localStorage is available
      if (!this.isStorageAvailable()) {
        console.warn('localStorage not available, using in-memory storage');
        this.useInMemoryStorage();
        return;
      }

      // Initialize default settings if not present
      if (!this.getItem(this.keys.settings)) {
        this.saveSettings(this.getDefaultSettings());
      }

      // Initialize default rules if not present
      if (!this.getItem(this.keys.rules)) {
        this.resetToDefaults();
      }

      // Initialize default profile if not present
      if (!this.getItem(this.keys.profiles)) {
        this.initializeDefaultProfile();
      }

      // Initialize empty history if not present
      if (!this.getItem(this.keys.history)) {
        this.setItem(this.keys.history, []);
      }

      // Set current profile to default if not set
      if (!this.getItem(this.keys.currentProfile)) {
        this.setItem(this.keys.currentProfile, 'default');
      }

    } catch (error) {
      console.error('Failed to initialize storage:', error);
      this.handleStorageError(error);
    }
  }

  /**
   * Check if localStorage is available and functional
   * @returns {boolean}
   */
  isStorageAvailable() {
    try {
      const testKey = this.namespace + 'test';
      localStorage.setItem(testKey, 'test');
      localStorage.removeItem(testKey);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Fallback to in-memory storage when localStorage is unavailable
   */
  useInMemoryStorage() {
    this.inMemoryStorage = new Map();
    this.storageMode = 'memory';
    
    // Override storage methods to use in-memory storage
    this.getItem = (key) => {
      const value = this.inMemoryStorage.get(key);
      return value ? JSON.parse(value) : null;
    };
    
    this.setItem = (key, value) => {
      this.inMemoryStorage.set(key, JSON.stringify(value));
    };
    
    this.removeItem = (key) => {
      this.inMemoryStorage.delete(key);
    };
    
    // Initialize with defaults
    this.saveSettings(this.getDefaultSettings());
    this.resetToDefaults();
    this.initializeDefaultProfile();
    this.setItem(this.keys.history, []);
    this.setItem(this.keys.currentProfile, 'default');
  }

  /**
   * Get item from storage with error handling
   * @param {string} key 
   * @returns {any|null}
   */
  getItem(key) {
    try {
      const value = localStorage.getItem(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      console.error(`Failed to get item ${key}:`, error);
      return null;
    }
  }

  /**
   * Set item in storage with error handling and quota monitoring
   * @param {string} key 
   * @param {any} value 
   * @returns {boolean} Success status
   */
  setItem(key, value) {
    try {
      const serialized = JSON.stringify(value);
      
      // Check if this would exceed storage quota
      if (this.wouldExceedQuota(serialized)) {
        this.handleQuotaExceeded();
        return false;
      }
      
      localStorage.setItem(key, serialized);
      return true;
    } catch (error) {
      if (error.name === 'QuotaExceededError') {
        this.handleQuotaExceeded();
      } else {
        console.error(`Failed to set item ${key}:`, error);
      }
      return false;
    }
  }

  /**
   * Remove item from storage
   * @param {string} key 
   */
  removeItem(key) {
    try {
      localStorage.removeItem(key);
    } catch (error) {
      console.error(`Failed to remove item ${key}:`, error);
    }
  }

  /**
   * Check if storing a value would exceed quota
   * @param {string} serializedValue 
   * @returns {boolean}
   */
  wouldExceedQuota(serializedValue) {
    try {
      // Estimate current usage
      let currentSize = 0;
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(this.namespace)) {
          currentSize += localStorage.getItem(key).length;
        }
      }
      
      // Add size of new value
      const newSize = currentSize + serializedValue.length;
      
      // Rough estimate of localStorage limit (5MB for most browsers)
      const estimatedLimit = 5 * 1024 * 1024;
      
      return newSize > estimatedLimit * this.quotaCriticalThreshold;
    } catch (error) {
      console.error('Failed to check quota:', error);
      return false;
    }
  }

  /**
   * Handle storage quota exceeded
   */
  handleQuotaExceeded() {
    console.warn('Storage quota exceeded, attempting cleanup');
    
    // Try to free up space by removing old history entries
    const history = this.getHistory();
    if (history.length > 10) {
      const reducedHistory = history.slice(-10); // Keep only last 10 entries
      this.setItem(this.keys.history, reducedHistory);
      console.log(`Reduced history from ${history.length} to ${reducedHistory.length} entries`);
    }
    
    // Notify user about storage issues
    this.notifyStorageIssue('Storage quota exceeded. Some history entries were removed to free up space.');
  }

  /**
   * Handle storage errors
   * @param {Error} error 
   */
  handleStorageError(error) {
    console.error('Storage error:', error);
    
    if (error.name === 'SecurityError') {
      this.notifyStorageIssue('Storage access denied. The application will use temporary storage.');
      this.useInMemoryStorage();
    } else {
      this.notifyStorageIssue('Storage error occurred. Some data may not be saved.');
    }
  }

  /**
   * Notify user about storage issues
   * @param {string} message 
   */
  notifyStorageIssue(message) {
    // This will be called by the UI controller to show user notifications
    if (window.app && window.app.showNotification) {
      window.app.showNotification(message, 'warning');
    } else {
      console.warn('Storage notification:', message);
    }
  }

  /**
   * Get current storage usage statistics
   * @returns {StorageQuota}
   */
  getStorageUsage() {
    try {
      let used = 0;
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(this.namespace)) {
          used += localStorage.getItem(key).length;
        }
      }
      
      // Rough estimate of available storage (5MB for most browsers)
      const available = 5 * 1024 * 1024;
      const percentage = Math.round((used / available) * 100);
      
      return {
        used,
        available,
        percentage: Math.min(percentage, 100)
      };
    } catch (error) {
      console.error('Failed to get storage usage:', error);
      return { used: 0, available: 0, percentage: 0 };
    }
  }

  /**
   * Get default application settings
   * @returns {Settings}
   */
  getDefaultSettings() {
    return {
      theme: 'system',
      realTimeProcessing: true,
      deterministicReplacement: true,
      preserveFormatting: true,
      maxHistoryEntries: 100,
      showWarnings: true,
      enableKeyValueDetection: true,
      debounceDelay: 300,
      customSensitiveWords: {
        enabled: true,
        companyName: '',
        competitorNames: [],
        projectNames: [],
        customWords: [],
        replacementStrategy: 'generic' // 'generic', 'competitor', 'custom'
      }
    };
  }

  /**
   * Get current settings
   * @returns {Settings}
   */
  getSettings() {
    const settings = this.getItem(this.keys.settings);
    return settings || this.getDefaultSettings();
  }

  /**
   * Save settings
   * @param {Settings} settings 
   * @returns {boolean}
   */
  saveSettings(settings) {
    return this.setItem(this.keys.settings, settings);
  }

  /**
   * Get all rules
   * @returns {Rule[]}
   */
  getRules() {
    const rules = this.getItem(this.keys.rules);
    return rules || [];
  }

  /**
   * Add a new rule
   * @param {Rule} rule 
   * @returns {boolean}
   */
  addRule(rule) {
    const rules = this.getRules();
    
    // Generate unique ID if not provided
    if (!rule.id) {
      rule.id = this.generateRuleId();
    }
    
    // Validate rule
    const validation = this.validateRule(rule);
    if (!validation.isValid) {
      console.error('Invalid rule:', validation.errors);
      return false;
    }
    
    rules.push(rule);
    return this.setItem(this.keys.rules, rules);
  }

  /**
   * Update an existing rule
   * @param {number} index 
   * @param {Rule} rule 
   * @returns {boolean}
   */
  updateRule(index, rule) {
    const rules = this.getRules();
    
    if (index < 0 || index >= rules.length) {
      console.error('Invalid rule index:', index);
      return false;
    }
    
    // Validate rule
    const validation = this.validateRule(rule);
    if (!validation.isValid) {
      console.error('Invalid rule:', validation.errors);
      return false;
    }
    
    rules[index] = rule;
    return this.setItem(this.keys.rules, rules);
  }

  /**
   * Delete a rule
   * @param {number} index 
   * @returns {boolean}
   */
  deleteRule(index) {
    const rules = this.getRules();
    
    if (index < 0 || index >= rules.length) {
      console.error('Invalid rule index:', index);
      return false;
    }
    
    rules.splice(index, 1);
    return this.setItem(this.keys.rules, rules);
  }

  /**
   * Reset rules to defaults with comprehensive built-in patterns
   */
  resetToDefaults() {
    const defaultRules = this.getDefaultRules();
    
    // Ensure all rules have proper validation and structure
    const validatedRules = defaultRules.map(rule => {
      const validation = this.validateRule(rule);
      if (!validation.isValid) {
        console.warn(`Invalid default rule ${rule.id}:`, validation.errors);
        // Fix common issues
        if (!rule.enabled) rule.enabled = true;
        if (!rule.category) rule.category = 'custom';
      }
      return rule;
    });
    
    const success = this.setItem(this.keys.rules, validatedRules);
    
    if (success) {
      console.log(`Initialized ${validatedRules.length} default rules`);
    } else {
      console.error('Failed to reset rules to defaults');
    }
    
    return success;
  }

  /**
   * Generate a unique rule ID
   * @returns {string}
   */
  generateRuleId() {
    return 'rule_' + Date.now() + '_' + Math.random().toString(36).substring(2, 11);
  }

  /**
   * Validate a rule object
   * @param {Rule} rule 
   * @returns {ValidationResult}
   */
  validateRule(rule) {
    const errors = [];
    const warnings = [];
    
    // Required fields
    if (!rule.type || !['literal', 'regex', 'builtin', 'kv'].includes(rule.type)) {
      errors.push('Rule type must be one of: literal, regex, builtin, kv');
    }
    
    if (!rule.pattern || typeof rule.pattern !== 'string') {
      errors.push('Rule pattern is required and must be a string');
    }
    
    if (!rule.category || !['secrets', 'pii', 'company', 'custom'].includes(rule.category)) {
      errors.push('Rule category must be one of: secrets, pii, company, custom');
    }
    
    if (typeof rule.enabled !== 'boolean') {
      errors.push('Rule enabled must be a boolean');
    }
    
    // Type-specific validation
    if (rule.type === 'regex') {
      try {
        new RegExp(rule.pattern, rule.flags || '');
      } catch (error) {
        errors.push('Invalid regex pattern: ' + error.message);
      }
    }
    
    // Replacement validation
    if (rule.replacement !== null && typeof rule.replacement !== 'string') {
      errors.push('Rule replacement must be a string or null');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Get default rules for common sensitive patterns
   * @returns {Rule[]}
   */
  getDefaultRules() {
    return [
      // Personal Identifiable Information (PII)
      {
        id: 'builtin_email',
        type: 'builtin',
        pattern: 'email',
        replacement: null,
        category: 'pii',
        enabled: true,
        name: 'Email Address',
        description: 'Detects email addresses in RFC 5322 compliant format'
      },
      
      {
        id: 'builtin_phone',
        type: 'builtin',
        pattern: 'phone',
        replacement: null,
        category: 'pii',
        enabled: true,
        name: 'Phone Number',
        description: 'Detects phone numbers in various international and US formats'
      },
      
      {
        id: 'builtin_ssn',
        type: 'builtin',
        pattern: 'ssn',
        replacement: null,
        category: 'pii',
        enabled: true,
        name: 'Social Security Number',
        description: 'Detects US Social Security Numbers with various separators'
      },
      
      {
        id: 'builtin_credit_card',
        type: 'builtin',
        pattern: 'credit_card',
        replacement: null,
        category: 'pii',
        enabled: true,
        name: 'Credit Card Number',
        description: 'Detects major credit card numbers (Visa, MasterCard, Amex, etc.)'
      },
      
      // Network and Infrastructure
      {
        id: 'builtin_ip',
        type: 'builtin',
        pattern: 'ip',
        replacement: null,
        category: 'company',
        enabled: true,
        name: 'IP Address',
        description: 'Detects IPv4 and IPv6 addresses'
      },
      
      {
        id: 'builtin_database_url',
        type: 'builtin',
        pattern: 'database_url',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Database Connection String',
        description: 'Detects database connection URLs for MongoDB, MySQL, PostgreSQL, etc.'
      },
      
      // AWS Credentials
      {
        id: 'builtin_aws_access_key',
        type: 'builtin',
        pattern: 'aws_access_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'AWS Access Key',
        description: 'Detects AWS access key IDs (AKIA, ASIA, AROA, etc.)'
      },
      
      {
        id: 'builtin_aws_secret_key',
        type: 'builtin',
        pattern: 'aws_secret_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'AWS Secret Key',
        description: 'Detects AWS secret access keys (40-character base64 strings)'
      },
      
      // JWT and API Tokens
      {
        id: 'builtin_jwt_token',
        type: 'builtin',
        pattern: 'jwt_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'JWT Token',
        description: 'Detects JSON Web Tokens in standard format'
      },
      
      {
        id: 'builtin_api_key',
        type: 'builtin',
        pattern: 'api_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Generic API Key',
        description: 'Detects generic API keys and access tokens'
      },
      
      // GitHub Credentials - Comprehensive Coverage
      {
        id: 'builtin_github_client_id',
        type: 'builtin',
        pattern: 'github_client_id',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitHub Client ID',
        description: 'Detects GitHub OAuth client IDs (Iv1. prefix)'
      },
      
      {
        id: 'builtin_github_token',
        type: 'builtin',
        pattern: 'github_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitHub Personal Access Token',
        description: 'Detects GitHub personal access tokens (ghp_ prefix)'
      },
      
      {
        id: 'builtin_github_app_token',
        type: 'builtin',
        pattern: 'github_app_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitHub App Token',
        description: 'Detects GitHub app installation tokens (ghs_ prefix)'
      },
      
      {
        id: 'builtin_github_oauth_token',
        type: 'builtin',
        pattern: 'github_oauth_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitHub OAuth Token',
        description: 'Detects GitHub OAuth access tokens (gho_ prefix)'
      },
      
      {
        id: 'builtin_github_user_token',
        type: 'builtin',
        pattern: 'github_user_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitHub User Token',
        description: 'Detects GitHub user-to-server tokens (ghu_ prefix)'
      },
      
      {
        id: 'builtin_github_server_token',
        type: 'builtin',
        pattern: 'github_server_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitHub Server Token',
        description: 'Detects GitHub server-to-server tokens (ghr_ prefix)'
      },
      
      {
        id: 'builtin_github_pat',
        type: 'builtin',
        pattern: 'github_pat',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitHub PAT (New Format)',
        description: 'Detects GitHub personal access tokens (github_pat_ prefix)'
      },
      
      // AI API Keys
      {
        id: 'builtin_openai_api_key',
        type: 'builtin',
        pattern: 'openai_api_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'OpenAI API Key',
        description: 'Detects OpenAI API keys (sk- prefix)'
      },
      
      {
        id: 'builtin_anthropic_api_key',
        type: 'builtin',
        pattern: 'anthropic_api_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Anthropic API Key',
        description: 'Detects Anthropic Claude API keys'
      },
      
      // Package Manager Tokens
      {
        id: 'builtin_npm_token',
        type: 'builtin',
        pattern: 'npm_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'NPM Token',
        description: 'Detects NPM authentication tokens'
      },
      
      // Financial Data
      {
        id: 'builtin_cvv',
        type: 'builtin',
        pattern: 'cvv',
        replacement: null,
        category: 'pii',
        enabled: true,
        name: 'CVV/CVC Code',
        description: 'Detects credit card security codes'
      },
      
      // Network Infrastructure
      {
        id: 'builtin_ipv6',
        type: 'builtin',
        pattern: 'ipv6',
        replacement: null,
        category: 'network',
        enabled: true,
        name: 'IPv6 Address',
        description: 'Detects IPv6 addresses'
      },
      
      {
        id: 'builtin_basic_auth',
        type: 'builtin',
        pattern: 'basic_auth',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Basic Authentication URL',
        description: 'Detects URLs with embedded credentials'
      },
      
      // Enhanced Database Connections
      {
        id: 'builtin_database_connection',
        type: 'builtin',
        pattern: 'database_connection',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Database Connection String',
        description: 'Detects database connection strings with credentials'
      },
      
      {
        id: 'builtin_redis_url',
        type: 'builtin',
        pattern: 'redis_url',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Redis URL',
        description: 'Detects Redis connection URLs with authentication'
      },
      
      {
        id: 'builtin_rabbitmq_url',
        type: 'builtin',
        pattern: 'rabbitmq_url',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'RabbitMQ URL',
        description: 'Detects RabbitMQ connection URLs with credentials'
      },
      
      // GitLab Tokens - CRITICAL MISSING PATTERNS
      {
        id: 'builtin_gitlab_pat',
        type: 'builtin',
        pattern: 'gitlab_pat',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitLab Personal Access Token',
        description: 'Detects GitLab personal access tokens (glpat- prefix)'
      },
      
      {
        id: 'builtin_gitlab_runner_token',
        type: 'builtin',
        pattern: 'gitlab_runner_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GitLab Runner Token',
        description: 'Detects GitLab runner registration tokens (GR prefix)'
      },
      
      // Stripe API Keys - CRITICAL MISSING PATTERNS
      {
        id: 'builtin_stripe_secret_key',
        type: 'builtin',
        pattern: 'stripe_secret_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Stripe Secret Key',
        description: 'Detects Stripe secret keys (sk_live_, sk_test_ prefixes)'
      },
      
      {
        id: 'builtin_stripe_publishable_key',
        type: 'builtin',
        pattern: 'stripe_publishable_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Stripe Publishable Key',
        description: 'Detects Stripe publishable keys (pk_live_, pk_test_ prefixes)'
      },
      
      {
        id: 'builtin_stripe_webhook_secret',
        type: 'builtin',
        pattern: 'stripe_webhook_secret',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Stripe Webhook Secret',
        description: 'Detects Stripe webhook secrets (whsec_ prefix)'
      },
      
      // SendGrid API Keys - CRITICAL MISSING PATTERNS
      {
        id: 'builtin_sendgrid_api_key',
        type: 'builtin',
        pattern: 'sendgrid_api_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'SendGrid API Key',
        description: 'Detects SendGrid API keys (SG. prefix)'
      },
      
      // Twilio Credentials - CRITICAL MISSING PATTERNS
      {
        id: 'builtin_twilio_account_sid',
        type: 'builtin',
        pattern: 'twilio_account_sid',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Twilio Account SID',
        description: 'Detects Twilio Account SIDs (AC prefix)'
      },
      
      {
        id: 'builtin_twilio_auth_token',
        type: 'builtin',
        pattern: 'twilio_auth_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Twilio Auth Token',
        description: 'Detects Twilio Auth Tokens (SK prefix)'
      },
      
      // Generic Hex Keys - CRITICAL MISSING PATTERNS
      {
        id: 'builtin_hex_key',
        type: 'builtin',
        pattern: 'hex_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Hexadecimal Key',
        description: 'Detects long hexadecimal strings (32+ characters)'
      },
      
      // Google Cloud Platform
      {
        id: 'builtin_gcp_kms_path',
        type: 'builtin',
        pattern: 'gcp_kms_path',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GCP KMS Path',
        description: 'Detects Google Cloud KMS key resource paths'
      },
      
      {
        id: 'builtin_gcp_service_key',
        type: 'builtin',
        pattern: 'gcp_service_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'GCP Service Account Key',
        description: 'Detects Google Cloud service account key identifiers'
      },
      
      // Communication Platform Tokens
      {
        id: 'builtin_slack_token',
        type: 'builtin',
        pattern: 'slack_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Slack Token',
        description: 'Detects Slack API tokens (xoxb, xoxp, xoxa, xoxr, xoxs prefixes)'
      },
      
      {
        id: 'builtin_discord_token',
        type: 'builtin',
        pattern: 'discord_token',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Discord Token',
        description: 'Detects Discord bot and user tokens'
      },
      
      // Cryptographic Keys
      {
        id: 'builtin_private_key',
        type: 'builtin',
        pattern: 'private_key',
        replacement: null,
        category: 'secrets',
        enabled: true,
        name: 'Private Key',
        description: 'Detects PEM-formatted private keys (RSA, EC, DSA, OpenSSH)'
      },
      
      // Repository and Company Information
      {
        id: 'builtin_repository_url',
        type: 'builtin',
        pattern: 'repository_url',
        replacement: null,
        category: 'company',
        enabled: true,
        name: 'Repository URL',
        description: 'Detects Git repository URLs (GitHub, GitLab, Bitbucket)'
      },
      
      // Key-Value Pattern Rules - CRITICAL MISSING PATTERNS
      {
        id: 'kv_password',
        type: 'kv',
        pattern: 'password',
        replacement: 'REDACTED_PASSWORD',
        category: 'secrets',
        enabled: true,
        name: 'Password Key-Value',
        description: 'Detects password values in key-value pairs (password: value, "password": "value", PASSWORD=value)'
      },
      
      {
        id: 'kv_secret',
        type: 'kv',
        pattern: 'secret',
        replacement: 'REDACTED_SECRET',
        category: 'secrets',
        enabled: true,
        name: 'Secret Key-Value',
        description: 'Detects secret values in key-value pairs'
      },
      
      {
        id: 'kv_token',
        type: 'kv',
        pattern: 'token',
        replacement: 'REDACTED_TOKEN',
        category: 'secrets',
        enabled: true,
        name: 'Token Key-Value',
        description: 'Detects token values in key-value pairs'
      },
      
      {
        id: 'kv_api_key',
        type: 'kv',
        pattern: 'api_key',
        replacement: 'REDACTED_API_KEY',
        category: 'secrets',
        enabled: true,
        name: 'API Key Key-Value',
        description: 'Detects API key values in key-value pairs'
      },
      
      {
        id: 'kv_access_key',
        type: 'kv',
        pattern: 'access_key',
        replacement: 'REDACTED_ACCESS_KEY',
        category: 'secrets',
        enabled: true,
        name: 'Access Key Key-Value',
        description: 'Detects access key values in key-value pairs'
      },
      
      {
        id: 'kv_private_key',
        type: 'kv',
        pattern: 'private_key',
        replacement: 'REDACTED_PRIVATE_KEY',
        category: 'secrets',
        enabled: true,
        name: 'Private Key Key-Value',
        description: 'Detects private key values in key-value pairs'
      },
      
      {
        id: 'kv_client_secret',
        type: 'kv',
        pattern: 'client_secret',
        replacement: 'REDACTED_CLIENT_SECRET',
        category: 'secrets',
        enabled: true,
        name: 'Client Secret Key-Value',
        description: 'Detects client secret values in key-value pairs'
      },
      
      {
        id: 'kv_auth_token',
        type: 'kv',
        pattern: 'auth_token',
        replacement: 'REDACTED_AUTH_TOKEN',
        category: 'secrets',
        enabled: true,
        name: 'Auth Token Key-Value',
        description: 'Detects authentication token values in key-value pairs'
      },
      
      {
        id: 'kv_bearer_token',
        type: 'kv',
        pattern: 'bearer_token',
        replacement: 'REDACTED_BEARER_TOKEN',
        category: 'secrets',
        enabled: true,
        name: 'Bearer Token Key-Value',
        description: 'Detects bearer token values in key-value pairs'
      },
      
      {
        id: 'kv_refresh_token',
        type: 'kv',
        pattern: 'refresh_token',
        replacement: 'REDACTED_REFRESH_TOKEN',
        category: 'secrets',
        enabled: true,
        name: 'Refresh Token Key-Value',
        description: 'Detects refresh token values in key-value pairs'
      },
      
      // AWS-specific key-value patterns - CRITICAL MISSING PATTERNS
      {
        id: 'kv_secret_access_key',
        type: 'kv',
        pattern: 'secretAccessKey',
        replacement: 'REDACTED_SECRET_ACCESS_KEY',
        category: 'secrets',
        enabled: true,
        name: 'AWS Secret Access Key Key-Value',
        description: 'Detects AWS secretAccessKey values in key-value pairs'
      },
      
      {
        id: 'kv_access_key_id',
        type: 'kv',
        pattern: 'accessKeyId',
        replacement: 'REDACTED_ACCESS_KEY_ID',
        category: 'secrets',
        enabled: true,
        name: 'AWS Access Key ID Key-Value',
        description: 'Detects AWS accessKeyId values in key-value pairs'
      },
      
      {
        id: 'kv_session_token',
        type: 'kv',
        pattern: 'sessionToken',
        replacement: 'REDACTED_SESSION_TOKEN',
        category: 'secrets',
        enabled: true,
        name: 'AWS Session Token Key-Value',
        description: 'Detects AWS sessionToken values in key-value pairs'
      }
    ];
  }

  /**
   * Initialize default profile
   */
  initializeDefaultProfile() {
    const defaultProfile = {
      name: 'default',
      rules: this.getDefaultRules(),
      settings: this.getDefaultSettings(),
      created: new Date(),
      lastModified: new Date(),
      isDefault: true
    };
    
    this.setItem(this.keys.profiles, { default: defaultProfile });
  }

  /**
   * Get all profiles
   * @returns {Object.<string, Profile>}
   */
  getProfiles() {
    const profiles = this.getItem(this.keys.profiles);
    return profiles || {};
  }

  /**
   * Save a profile
   * @param {string} name 
   * @param {Rule[]} rules 
   * @param {Settings} settings 
   * @returns {boolean}
   */
  saveProfile(name, rules, settings) {
    const profiles = this.getProfiles();
    
    const profile = {
      name,
      rules,
      settings,
      created: profiles[name] ? profiles[name].created : new Date(),
      lastModified: new Date(),
      isDefault: name === 'default'
    };
    
    profiles[name] = profile;
    return this.setItem(this.keys.profiles, profiles);
  }

  /**
   * Load a profile
   * @param {string} name 
   * @returns {{rules: Rule[], settings: Settings}|null}
   */
  loadProfile(name) {
    const profiles = this.getProfiles();
    const profile = profiles[name];
    
    if (!profile) {
      console.error('Profile not found:', name);
      return null;
    }
    
    return {
      rules: profile.rules,
      settings: profile.settings
    };
  }

  /**
   * Delete a profile
   * @param {string} name 
   * @returns {boolean}
   */
  deleteProfile(name) {
    if (name === 'default') {
      console.error('Cannot delete default profile');
      return false;
    }
    
    const profiles = this.getProfiles();
    
    if (!profiles[name]) {
      console.error('Profile not found:', name);
      return false;
    }
    
    delete profiles[name];
    
    // If this was the current profile, switch to default
    const currentProfile = this.getCurrentProfile();
    if (currentProfile === name) {
      this.setCurrentProfile('default');
    }
    
    return this.setItem(this.keys.profiles, profiles);
  }

  /**
   * Get current profile name
   * @returns {string}
   */
  getCurrentProfile() {
    return this.getItem(this.keys.currentProfile) || 'default';
  }

  /**
   * Set current profile
   * @param {string} name 
   * @returns {boolean}
   */
  setCurrentProfile(name) {
    const profiles = this.getProfiles();
    
    if (!profiles[name]) {
      console.error('Profile not found:', name);
      return false;
    }
    
    return this.setItem(this.keys.currentProfile, name);
  }

  /**
   * Get sanitization history
   * @returns {HistoryEntry[]}
   */
  getHistory() {
    const history = this.getItem(this.keys.history);
    return history || [];
  }

  /**
   * Add entry to sanitization history
   * @param {HistoryEntry} entry 
   * @returns {boolean}
   */
  addHistoryEntry(entry) {
    const history = this.getHistory();
    const settings = this.getSettings();
    
    // Add timestamp and ID if not present
    if (!entry.timestamp) {
      entry.timestamp = new Date();
    }
    if (!entry.id) {
      entry.id = 'history_' + Date.now() + '_' + Math.random().toString(36).substring(2, 11);
    }
    
    history.unshift(entry); // Add to beginning
    
    // Limit history size
    if (history.length > settings.maxHistoryEntries) {
      history.splice(settings.maxHistoryEntries);
    }
    
    return this.setItem(this.keys.history, history);
  }

  /**
   * Clear sanitization history
   * @returns {boolean}
   */
  clearHistory() {
    return this.setItem(this.keys.history, []);
  }

  /**
   * Export all data for backup
   * @returns {Object}
   */
  exportData() {
    return {
      rules: this.getRules(),
      profiles: this.getProfiles(),
      settings: this.getSettings(),
      history: this.getHistory(),
      currentProfile: this.getCurrentProfile(),
      exportDate: new Date(),
      version: '1.0.0'
    };
  }

  /**
   * Get custom sensitive words configuration
   * @returns {CustomSensitiveWords}
   */
  getCustomSensitiveWords() {
    const settings = this.getSettings();
    return settings.customSensitiveWords || this.getDefaultSettings().customSensitiveWords;
  }

  /**
   * Update custom sensitive words configuration
   * @param {CustomSensitiveWords} config 
   * @returns {boolean}
   */
  updateCustomSensitiveWords(config) {
    const settings = this.getSettings();
    settings.customSensitiveWords = {
      ...settings.customSensitiveWords,
      ...config
    };
    return this.saveSettings(settings);
  }

  /**
   * Add a custom sensitive word
   * @param {string} word 
   * @param {string} category - 'company', 'competitor', 'project', 'custom'
   * @returns {boolean}
   */
  addCustomSensitiveWord(word, category = 'custom') {
    if (!word || typeof word !== 'string') {
      return false;
    }
    
    const config = this.getCustomSensitiveWords();
    const normalizedWord = word.trim().toLowerCase();
    
    switch (category) {
      case 'company':
        config.companyName = normalizedWord;
        break;
      case 'competitor':
        if (!config.competitorNames.includes(normalizedWord)) {
          config.competitorNames.push(normalizedWord);
        }
        break;
      case 'project':
        if (!config.projectNames.includes(normalizedWord)) {
          config.projectNames.push(normalizedWord);
        }
        break;
      case 'custom':
      default:
        if (!config.customWords.includes(normalizedWord)) {
          config.customWords.push(normalizedWord);
        }
        break;
    }
    
    return this.updateCustomSensitiveWords(config);
  }

  /**
   * Remove a custom sensitive word
   * @param {string} word 
   * @param {string} category 
   * @returns {boolean}
   */
  removeCustomSensitiveWord(word, category = 'custom') {
    if (!word || typeof word !== 'string') {
      return false;
    }
    
    const config = this.getCustomSensitiveWords();
    const normalizedWord = word.trim().toLowerCase();
    
    switch (category) {
      case 'company':
        config.companyName = '';
        break;
      case 'competitor':
        config.competitorNames = config.competitorNames.filter(w => w !== normalizedWord);
        break;
      case 'project':
        config.projectNames = config.projectNames.filter(w => w !== normalizedWord);
        break;
      case 'custom':
      default:
        config.customWords = config.customWords.filter(w => w !== normalizedWord);
        break;
    }
    
    return this.updateCustomSensitiveWords(config);
  }

  /**
   * Get all custom sensitive words as rules
   * @returns {Rule[]}
   */
  getCustomSensitiveWordRules() {
    const config = this.getCustomSensitiveWords();
    
    if (!config.enabled) {
      return [];
    }
    
    const rules = [];
    
    // Company name rule
    if (config.companyName) {
      rules.push({
        id: 'custom_company_name',
        type: 'literal',
        pattern: config.companyName,
        replacement: this.getReplacementForWord(config.companyName, 'company', config),
        category: 'company',
        enabled: true,
        name: 'Company Name',
        description: 'Custom company name detection',
        caseSensitive: false
      });
    }
    
    // Competitor names
    config.competitorNames.forEach((competitor, index) => {
      rules.push({
        id: `custom_competitor_${index}`,
        type: 'literal',
        pattern: competitor,
        replacement: this.getReplacementForWord(competitor, 'competitor', config),
        category: 'company',
        enabled: true,
        name: `Competitor: ${competitor}`,
        description: 'Custom competitor name detection',
        caseSensitive: false
      });
    });
    
    // Project names
    config.projectNames.forEach((project, index) => {
      rules.push({
        id: `custom_project_${index}`,
        type: 'literal',
        pattern: project,
        replacement: this.getReplacementForWord(project, 'project', config),
        category: 'company',
        enabled: true,
        name: `Project: ${project}`,
        description: 'Custom project name detection',
        caseSensitive: false
      });
    });
    
    // Custom words
    config.customWords.forEach((word, index) => {
      rules.push({
        id: `custom_word_${index}`,
        type: 'literal',
        pattern: word,
        replacement: this.getReplacementForWord(word, 'custom', config),
        category: 'custom',
        enabled: true,
        name: `Custom Word: ${word}`,
        description: 'User-defined sensitive word',
        caseSensitive: false
      });
    });
    
    return rules;
  }

  /**
   * Get replacement text for a custom word based on strategy
   * @param {string} word 
   * @param {string} category 
   * @param {CustomSensitiveWords} config 
   * @returns {string}
   */
  getReplacementForWord(word, category, config) {
    switch (config.replacementStrategy) {
      case 'competitor':
        // Replace with a competitor name
        const competitors = ['TechCorp', 'InnovateCo', 'GlobalTech', 'FutureSoft', 'NextGen'];
        const randomCompetitor = competitors[Math.floor(Math.random() * competitors.length)];
        return category === 'company' ? randomCompetitor : `[${category.toUpperCase()}_REDACTED]`;
        
      case 'generic':
        // Replace with generic terms
        switch (category) {
          case 'company':
            return 'CompanyName';
          case 'competitor':
            return 'CompetitorName';
          case 'project':
            return 'ProjectName';
          case 'custom':
            return '[REDACTED]';
          default:
            return '[REDACTED]';
        }
        
      case 'custom':
        // Use pattern-preserving replacement
        return this.preserveWordPattern(word);
        
      default:
        return '[REDACTED]';
    }
  }

  /**
   * Preserve the pattern of a word (length, case, special chars)
   * @param {string} word 
   * @returns {string}
   */
  preserveWordPattern(word) {
    let result = '';
    for (let i = 0; i < word.length; i++) {
      const char = word[i];
      if (/[A-Z]/.test(char)) {
        result += 'X';
      } else if (/[a-z]/.test(char)) {
        result += 'x';
      } else if (/[0-9]/.test(char)) {
        result += '0';
      } else {
        result += char; // Keep special characters
      }
    }
    return result;
  }

  /**
   * Import data from backup
   * @param {Object} data 
   * @returns {boolean}
   */
  importData(data) {
    try {
      if (data.rules) {
        this.setItem(this.keys.rules, data.rules);
      }
      if (data.profiles) {
        this.setItem(this.keys.profiles, data.profiles);
      }
      if (data.settings) {
        this.setItem(this.keys.settings, data.settings);
      }
      if (data.history) {
        this.setItem(this.keys.history, data.history);
      }
      if (data.currentProfile) {
        this.setItem(this.keys.currentProfile, data.currentProfile);
      }
      
      return true;
    } catch (error) {
      console.error('Failed to import data:', error);
      return false;
    }
  }
}

// Create global instance
window.storage = new StorageModule();