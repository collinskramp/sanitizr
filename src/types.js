/**
 * TypeScript-style interfaces defined as JSDoc comments for vanilla JavaScript
 * These interfaces define the core data structures used throughout the application
 */

/**
 * @typedef {Object} Rule
 * @property {string} id - Unique identifier for the rule
 * @property {'literal'|'regex'|'builtin'|'kv'} type - Type of pattern matching
 * @property {string} pattern - The detection pattern (literal text, regex, or builtin identifier)
 * @property {string} [flags] - Regex flags (for regex type only)
 * @property {string|null} replacement - Fixed replacement text or null for generated replacement
 * @property {'secrets'|'pii'|'company'|'custom'} category - Category for organization
 * @property {boolean} enabled - Whether the rule is active
 * @property {number} [priority] - Optional priority override (lower numbers = higher priority)
 * @property {string} [name] - Optional human-readable name for the rule
 * @property {string} [description] - Optional description of what the rule detects
 */

/**
 * @typedef {Object} Profile
 * @property {string} name - Profile name (unique identifier)
 * @property {Rule[]} rules - Array of rules in this profile
 * @property {Settings} settings - Profile-specific settings
 * @property {Date} created - Creation timestamp
 * @property {Date} lastModified - Last modification timestamp
 * @property {boolean} [isDefault] - Whether this is the default profile (cannot be deleted)
 */

/**
 * @typedef {Object} Detection
 * @property {string} ruleId - ID of the rule that made this detection
 * @property {string} ruleName - Human-readable name of the rule
 * @property {'secrets'|'pii'|'company'|'custom'} category - Category of the detected pattern
 * @property {string} pattern - The original pattern that was matched
 * @property {string} match - The actual text that was matched
 * @property {number} startIndex - Start position in the original text
 * @property {number} endIndex - End position in the original text
 * @property {string} replacement - The replacement text that will be used
 * @property {boolean} selected - Whether this detection is selected for sanitization
 * @property {string} [context] - Surrounding context for better understanding
 */

/**
 * @typedef {Object} Settings
 * @property {'light'|'dark'|'system'} theme - UI theme preference
 * @property {boolean} realTimeProcessing - Enable real-time sanitization as user types
 * @property {boolean} deterministicReplacement - Use deterministic replacement generation
 * @property {boolean} preserveFormatting - Preserve original text formatting where possible
 * @property {number} maxHistoryEntries - Maximum number of history entries to keep
 * @property {boolean} showWarnings - Show privacy and security warnings
 * @property {boolean} enableKeyValueDetection - Enable key-value pattern detection
 * @property {number} debounceDelay - Delay in milliseconds for real-time processing
 */

/**
 * @typedef {Object} SanitizeOptions
 * @property {Rule[]} rules - Rules to apply during sanitization
 * @property {boolean} [deterministicReplacement=true] - Use deterministic replacement
 * @property {boolean} [preserveFormatting=true] - Preserve original formatting
 * @property {string[]} [selectedDetections] - Only sanitize these detection IDs (for selective sanitization)
 */

/**
 * @typedef {Object} DetectOptions
 * @property {Rule[]} rules - Rules to use for detection
 * @property {boolean} [includeContext=false] - Include surrounding context in results
 * @property {number} [contextLength=20] - Number of characters of context to include
 */

/**
 * @typedef {Object} HistoryEntry
 * @property {string} id - Unique identifier for this history entry
 * @property {Date} timestamp - When the sanitization occurred
 * @property {string} inputPreview - Preview of the input text (first 100 chars)
 * @property {string} outputPreview - Preview of the sanitized output (first 100 chars)
 * @property {number} detectionsCount - Number of patterns detected
 * @property {string} profileName - Name of the profile used
 * @property {number} inputSize - Size of input in characters
 * @property {number} outputSize - Size of output in characters
 */

/**
 * @typedef {Object} StorageQuota
 * @property {number} used - Bytes currently used
 * @property {number} available - Total bytes available
 * @property {number} percentage - Usage percentage (0-100)
 */

/**
 * @typedef {Object} ExportOptions
 * @property {'text'|'json'|'csv'} format - Export format
 * @property {boolean} [includeMetadata=false] - Include sanitization metadata
 * @property {boolean} [includeDetections=false] - Include detection information
 * @property {string} [filename] - Custom filename (without extension)
 */

/**
 * @typedef {Object} ValidationResult
 * @property {boolean} isValid - Whether the validation passed
 * @property {string[]} errors - Array of error messages
 * @property {string[]} warnings - Array of warning messages
 */

/**
 * @typedef {Object} ProcessingStats
 * @property {number} processingTime - Time taken in milliseconds
 * @property {number} patternsDetected - Number of patterns found
 * @property {number} patternsReplaced - Number of patterns actually replaced
 * @property {number} inputSize - Size of input in characters
 * @property {number} outputSize - Size of output in characters
 * @property {string} inputType - Type of input ('text' or 'json')
 */

// Export types for use in other modules (for documentation purposes)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    // This file is primarily for JSDoc type definitions
    // No runtime exports needed for vanilla JavaScript
  };
}