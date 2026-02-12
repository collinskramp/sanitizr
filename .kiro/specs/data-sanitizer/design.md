# Design Document: Data Sanitizer

## Overview

The Data Sanitizer is a client-side web application built with vanilla JavaScript, HTML, and CSS that provides secure, local sanitization of sensitive data. The application follows a modular architecture with three core components: a Storage Module for persistence, a Sanitizer Engine for processing, and a UI Controller for user interaction.

The application operates entirely within the browser, using localStorage for persistence to ensure complete data privacy. The sanitization engine supports multiple rule types and can intelligently handle both plain text and structured JSON data while preserving formatting and structure.

## Architecture

The application follows a modular, event-driven architecture with clear separation of concerns:

```mermaid
graph TB
    Input[User Input Text] -->|text| UI[UI Controller<br/>app.js]
    UI -->|sanitize request| Sanitizer[Sanitizer Engine<br/>sanitizer.js]
    UI -->|load rules| Storage[Storage Module<br/>storage.js]
    Storage -->|rules array| Sanitizer
    Storage -->|persist| LS[localStorage]
    Sanitizer -->|detections| UI
    Sanitizer -->|sanitized text| UI
    UI -->|display| Output[Output Panel]
    
    subgraph "Rule Priority Order"
        KV[1. Key-Value Rules] --> Literal[2. Literal Rules]
        Literal --> Builtin[3. Built-in Patterns]
        Builtin --> Regex[4. Custom Regex]
    end
```

### Storage Constraints

The application operates under browser localStorage limitations:

- **Storage Quota**: Typically 5-10MB per origin, monitored via `navigator.storage.estimate()`
- **Maximum Input Size**: 1MB per sanitization operation to prevent quota exhaustion
- **Progressive Cleanup**: Automatic removal of oldest history entries when quota reaches 80%
- **Fallback Strategy**: In-memory storage with user notification if localStorage unavailable
- **Quota Monitoring**: Real-time storage usage display with warnings at 90% capacity

### Component Responsibilities

**UI Controller (app.js)**:
- Manages all user interface interactions and state
- Coordinates between Storage Module and Sanitizer Engine
- Handles real-time processing with debouncing
- Manages profile switching and rule configuration UI

**Storage Module (storage.js)**:
- Provides abstraction layer over localStorage
- Manages rules, profiles, and application settings
- Handles data serialization and deserialization
- Implements default rule initialization

**Sanitizer Engine (sanitizer.js)**:
- Core pattern detection and replacement logic
- JSON-aware processing with structure preservation
- Rule priority and application ordering
- Deterministic replacement generation

## Components and Interfaces

### Storage Module Interface

```javascript
// Core storage operations
initializeStorage(): void
getRules(): Rule[]
addRule(rule: Rule): void
updateRule(index: number, rule: Rule): void
deleteRule(index: number): void
resetToDefaults(): void

// Profile management
getProfiles(): Profile[]
saveProfile(name: string, rules: Rule[], settings: Settings): void
loadProfile(name: string): {rules: Rule[], settings: Settings}
deleteProfile(name: string): void

// Settings persistence
getSettings(): Settings
saveSettings(settings: Settings): void
```

### Sanitizer Engine Interface

```javascript
// Primary processing methods
sanitize(text: string, options: SanitizeOptions): string
detect(text: string, options: DetectOptions): Detection[]

// Utility methods
isJSON(text: string): boolean
sanitizeJSON(jsonText: string, rules: Rule[]): string
sanitizeText(text: string, rules: Rule[]): string
generateDummyValue(pattern: string, type: string): string
```

### UI Controller Interface

```javascript
// Initialization and setup
initialize(): void
loadRules(): void
setupEventListeners(): void

// Processing coordination
handleInputChange(text: string): void
performDetection(text: string): void
performSanitization(text: string): void

// UI state management
updateDetectionPanel(detections: Detection[]): void
updateOutputPanel(sanitizedText: string): void
toggleRealTimeMode(enabled: boolean): void
```

## Data Models

### Rule Object Structure

```javascript
interface Rule {
  id: string;              // Unique identifier
  type: 'literal' | 'regex' | 'builtin' | 'kv';
  pattern: string;         // The detection pattern
  flags?: string;          // Regex flags (for regex type)
  replacement: string | null; // Fixed replacement or null for generated
  category: 'secrets' | 'pii' | 'company' | 'custom';
  enabled: boolean;        // Whether rule is active
  priority?: number;       // Optional priority override
}
```

### Profile Object Structure

```javascript
interface Profile {
  name: string;
  rules: Rule[];
  settings: {
    deterministicReplacement: boolean;
    realTimeProcessing: boolean;
    preserveFormatting: boolean;
  };
  created: Date;
  lastModified: Date;
}
```

### Detection Result Structure

```javascript
interface Detection {
  ruleId: string;
  ruleName: string;
  category: string;
  pattern: string;
  match: string;
  startIndex: number;
  endIndex: number;
  replacement: string;
  selected: boolean;  // For selective sanitization
}
```

### Application Settings Structure

```javascript
interface Settings {
  theme: 'light' | 'dark' | 'system';
  realTimeProcessing: boolean;
  deterministicReplacement: boolean;
  preserveFormatting: boolean;
  maxHistoryEntries: number;
  showWarnings: boolean;
}
```

### Built-in Rule Definitions

The application includes comprehensive built-in rules for common sensitive patterns:

**Credential Patterns**:
- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- JWT Tokens: `eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*`
- GitHub Client IDs: `Iv1\.[a-f0-9]{16}`

**Personal Information**:
- Email addresses: RFC 5322 compliant pattern
- Phone numbers: International and US formats
- IP addresses: IPv4 and IPv6 patterns

**Key-Value Patterns**:
- YAML format: `KEY:\s*value`
- JSON format: `"key":\s*"value"`
- Environment variables: `KEY=value`

### Processing Pipeline Architecture

The sanitization process follows a structured pipeline with conflict resolution:

1. **Input Analysis**: Determine if input is JSON or plain text
2. **Rule Prioritization**: Order rules by type priority (kv → literal → builtin → regex)
3. **Pattern Detection**: Apply rules in priority order, collecting matches
4. **Conflict Resolution**: Handle overlapping matches using priority matrix
5. **Replacement Generation**: Create dummy values or apply fixed replacements
6. **Output Assembly**: Reconstruct sanitized text maintaining original structure

### Rule Conflict Resolution Matrix

When multiple rules match overlapping text regions, conflicts are resolved using this priority matrix:

| Scenario | Rule Type 1 | Rule Type 2 | Resolution Strategy |
|----------|-------------|-------------|-------------------|
| Complete Overlap | Any | Any | Higher priority type wins |
| Partial Overlap | KV | Literal/Regex | Split into non-overlapping segments |
| Nested Match | Builtin | Custom Regex | Builtin takes precedence |
| Same Priority | Same Type | Same Type | First rule in configuration order |

**Conflict Resolution Algorithm**:
```javascript
function resolveConflicts(detections) {
  // Sort by priority: kv > literal > builtin > regex
  const prioritized = detections.sort(byRulePriority);
  const resolved = [];
  
  for (const detection of prioritized) {
    const conflicts = resolved.filter(r => overlaps(r, detection));
    
    if (conflicts.length === 0) {
      resolved.push(detection);
    } else {
      // Handle partial overlaps by splitting ranges
      const nonOverlapping = splitOverlappingRanges(detection, conflicts);
      resolved.push(...nonOverlapping);
    }
  }
  
  return resolved;
}
```

### JSON Processing Algorithm

For JSON inputs, the engine implements a depth-first traversal with circular reference detection:

```javascript
function sanitizeJSON(obj, rules, depth = 0, visited = new WeakSet()) {
  // Prevent infinite recursion and stack overflow
  if (depth > MAX_DEPTH) throw new Error('Maximum depth exceeded');
  if (visited.has(obj)) return '[Circular Reference]';
  
  if (typeof obj === 'string') {
    return sanitizeText(obj, rules);
  }
  
  if (Array.isArray(obj)) {
    visited.add(obj);
    const result = obj.map(item => sanitizeJSON(item, rules, depth + 1, visited));
    visited.delete(obj);
    return result;
  }
  
  if (obj && typeof obj === 'object') {
    visited.add(obj);
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      // Keys are never sanitized, only values
      result[key] = sanitizeJSON(value, rules, depth + 1, visited);
    }
    visited.delete(obj);
    return result;
  }
  
  return obj; // Numbers, booleans, null remain unchanged
}
```

**Complexity Analysis**: O(n) where n is the number of nodes in the JSON structure
**Maximum Depth**: 100 levels to prevent stack overflow
**Memory Usage**: O(d) where d is the maximum depth for the visited set

### Deterministic Replacement Algorithm

When deterministic replacement is enabled, the system generates consistent dummy values:

```javascript
function generateDeterministicReplacement(originalValue, patternType) {
  // Use SHA-256 for cryptographically secure, consistent hashing
  const seed = sha256(originalValue + patternType);
  const rng = new SeededRNG(seed);
  
  switch (patternType) {
    case 'email':
      return `user${rng.nextInt(1000, 9999)}@example.com`;
    case 'phone':
      return `+1-555-${rng.nextInt(100, 999)}-${rng.nextInt(1000, 9999)}`;
    case 'aws_key':
      return `AKIA${rng.nextAlphaNumeric(16)}`;
    case 'jwt':
      return generateJWTStructure(rng);
    default:
      return preservePatternShape(originalValue, rng);
  }
}

function preservePatternShape(original, rng) {
  return original.replace(/[a-zA-Z]/g, () => rng.nextLetter())
                .replace(/[0-9]/g, () => rng.nextDigit())
                .replace(/[A-Z]/g, () => rng.nextUpperLetter());
  // Preserve special characters and structure
}
```

**Properties**:
- **Deterministic**: Same input always produces same output
- **Shape Preservation**: Maintains character classes and structural elements
- **Collision Resistance**: Different inputs produce different outputs with high probability

## Security Considerations

The Data Sanitizer implements multiple security layers to protect user data and prevent common web vulnerabilities:

### Input Sanitization and XSS Prevention
- **HTML Escaping**: All user input displayed in UI is HTML-escaped to prevent XSS attacks
- **Content Security Policy**: Recommended CSP headers: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`
- **DOM Manipulation**: Use `textContent` instead of `innerHTML` for user-generated content
- **Safe JSON Parsing**: Implement JSON parsing with size limits and timeout protection

### Regular Expression Security
- **ReDoS Protection**: All regex patterns limited to 1-second execution timeout
- **Pattern Validation**: User-defined regex patterns validated for catastrophic backtracking
- **Safe Compilation**: Regex compilation wrapped in try-catch with fallback to literal matching
- **Resource Limits**: Maximum 100 capture groups per regex pattern

### Browser Security Integration
- **Prototype Pollution Prevention**: Use `Object.create(null)` for rule storage objects
- **Memory Management**: Implement cleanup for large processing operations
- **Storage Isolation**: Namespace all localStorage keys to prevent conflicts
- **Secure Defaults**: All security-sensitive settings default to most restrictive values

### Data Privacy Guarantees
- **No Network Requests**: Static analysis and runtime monitoring to ensure zero network activity
- **Local Processing Only**: All sanitization occurs in browser main thread or web workers
- **Memory Clearing**: Sensitive data cleared from memory after processing
- **Storage Encryption**: Optional localStorage encryption for highly sensitive environments

## Performance Characteristics

The application is designed for efficient processing with predictable performance:

### Time Complexity Analysis
- **Text Sanitization**: O(n × m) where n = text length, m = number of active rules
- **JSON Processing**: O(n) where n = number of nodes in JSON structure
- **Rule Detection**: O(n × p) where n = text length, p = pattern complexity
- **Conflict Resolution**: O(d²) where d = number of detected patterns (typically small)

### Memory Usage
- **Base Application**: ~2MB for core JavaScript and CSS
- **Rule Storage**: ~1KB per rule (typical configuration: 50 rules = 50KB)
- **Processing Buffer**: 2× input size during sanitization (released immediately)
- **History Storage**: Configurable limit (default: 100 entries, ~1MB)

### Performance Guarantees
- **Small Inputs** (< 10KB): < 100ms processing time
- **Medium Inputs** (10KB - 100KB): < 500ms processing time  
- **Large Inputs** (100KB - 1MB): < 2 seconds processing time
- **Memory Limit**: Maximum 50MB total memory usage
- **Responsiveness**: UI remains responsive during processing via web workers for inputs > 100KB

### Optimization Strategies
- **Lazy Loading**: Rules loaded on-demand for better startup performance
- **Debounced Processing**: Real-time mode uses 300ms debounce to prevent excessive processing
- **Incremental Updates**: Only re-process changed portions of input when possible
- **Worker Threads**: Large sanitization operations offloaded to web workers

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

The following properties provide formal specifications with preconditions and postconditions:

### Property 1: Comprehensive Pattern Detection
**Given**: text ∈ String, |text| ≤ 1MB; rules ∈ RuleSet, ∀r ∈ rules: r.enabled = true  
**When**: detections = detect(text, rules)  
**Then**: ∀ match m in text where ∃r ∈ rules: matches(m, r.pattern) ⟹ ∃d ∈ detections: d.match = m ∧ d.ruleId = r.id ∧ d.position is correct  
**Validates: Requirements 1.1, 7.4, 7.5**

### Property 2: JSON Structure Preservation  
**Given**: jsonText ∈ String, isValidJSON(jsonText) = true; rules ∈ RuleSet  
**When**: result = sanitizeJSON(jsonText, rules)  
**Then**: isValidJSON(result) = true ∧ keys(parse(result)) = keys(parse(jsonText)) ∧ structure(parse(result)) = structure(parse(jsonText)) ∧ ∀ string values v in parse(jsonText): corresponding value in parse(result) is sanitized according to rules  
**Validates: Requirements 1.2, 6.1, 6.2, 6.3, 6.4**

### Property 3: Deterministic Replacement Consistency  
**Given**: text ∈ String; options.deterministic = true; pattern p detected in text  
**When**: result1 = sanitize(text, options) ∧ result2 = sanitize(text, options)  
**Then**: result1 = result2 ∧ ∀ replacement r in result1: r is deterministically generated from original pattern  
**Validates: Requirements 1.5**

### Property 4: Rule Priority Enforcement  
**Given**: text ∈ String; rules ∈ RuleSet with overlapping matches; priority order: kv > literal > builtin > regex  
**When**: detections = detect(text, rules) ∧ conflicts = findOverlaps(detections)  
**Then**: ∀ conflict c ∈ conflicts: resolvedRule(c) has highest priority among conflicting rules  
**Validates: Requirements 1.4**

### Property 5: Data Shape Preservation  
**Given**: pattern p ∈ String detected by rule r; replacement strategy = shape-preserving  
**When**: replacement = generateReplacement(p, r)  
**Then**: |replacement| = |p| ∧ characterClasses(replacement) = characterClasses(p) ∧ structuralElements(replacement) = structuralElements(p)  
**Validates: Requirements 1.3**

### Property 6: Storage Persistence Integrity  
**Given**: data d ∈ {Rule, Profile, Settings}; operation ∈ {create, update, delete}  
**When**: performOperation(operation, d) ∧ result = retrieveFromStorage(d.id)  
**Then**: result reflects operation immediately ∧ data integrity maintained ∧ no data corruption  
**Validates: Requirements 2.3, 3.3, 9.2**

### Property 7: Rule Storage Completeness  
**Given**: rule r with fields {type, pattern, replacement, category, enabled}  
**When**: storedRule = storeRule(r)  
**Then**: storedRule.id ≠ null ∧ storedRule.id is unique ∧ ∀ field f in r: storedRule.f = r.f  
**Validates: Requirements 2.2**

### Property 8: Profile Loading Consistency  
**Given**: profile p saved with rules R and settings S  
**When**: loadedProfile = loadProfile(p.name)  
**Then**: loadedProfile.rules = R ∧ loadedProfile.settings = S ∧ no data loss or corruption  
**Validates: Requirements 3.2**

### Property 9: Selective Sanitization Accuracy  
**Given**: detections D with subset S marked for sanitization; text T  
**When**: result = selectiveSanitize(T, D, S)  
**Then**: ∀ d ∈ S: d.match is replaced in result ∧ ∀ d ∈ (D - S): d.match unchanged in result  
**Validates: Requirements 4.4**

### Property 10: Network Isolation Guarantee  
**Given**: any sanitization operation O on input I  
**When**: networkRequests = monitorNetwork(O)  
**Then**: |networkRequests| = 0 ∧ all processing occurs locally  
**Validates: Requirements 5.1, 5.4**

### Property 11: JSON Fallback Handling  
**Given**: malformedJSON ∈ String, isValidJSON(malformedJSON) = false  
**When**: result = sanitize(malformedJSON, rules)  
**Then**: operation completes without error ∧ result = sanitizeAsPlainText(malformedJSON, rules)  
**Validates: Requirements 6.5**

### Property 12: Export Functionality Integrity  
**Given**: sanitizedText S generated by sanitization operation  
**When**: exportedContent = export(S, format)  
**Then**: content(exportedContent) = S ∧ isValidFormat(exportedContent, format) = true  
**Validates: Requirements 8.1, 8.3**

### Property 13: History Management Accuracy  
**Given**: sanitization operation O with timestamp T  
**When**: recordHistory(O, T) ∧ history = getHistory()  
**Then**: ∃ entry e ∈ history: e.operation = O ∧ e.timestamp = T ∧ clearHistory() preserves rules and profiles  
**Validates: Requirements 8.2, 8.4**

### Property 14: Theme Application Consistency  
**Given**: theme t ∈ {light, dark, system}; current UI state U  
**When**: applyTheme(t) ∧ newState = getUIState()  
**Then**: newState.theme = t ∧ no page reload required ∧ theme persisted across sessions  
**Validates: Requirements 9.3**

## Error Handling

The application implements comprehensive error handling across all modules:

### Storage Module Error Handling
- **localStorage Unavailable**: Graceful degradation to in-memory storage with user notification
- **Quota Exceeded**: Automatic cleanup of oldest history entries with user confirmation
- **Corrupted Data**: Reset to default configuration with backup of corrupted data
- **Invalid Rule Format**: Validation with specific error messages for correction

### Sanitizer Engine Error Handling
- **Invalid JSON**: Automatic fallback to plain text processing
- **Regex Compilation Errors**: Rule deactivation with error logging and user notification
- **Memory Constraints**: Processing chunking for large inputs with progress indication
- **Circular References**: Detection and safe handling in JSON processing

### UI Controller Error Handling
- **Processing Timeouts**: User notification with option to continue or cancel
- **Export Failures**: Retry mechanism with alternative export formats
- **Theme Loading Errors**: Fallback to default theme with error logging
- **Profile Loading Errors**: Fallback to default profile with corruption notification

## Testing Strategy

The Data Sanitizer employs a dual testing approach combining unit tests for specific scenarios and property-based tests for comprehensive validation:

### Unit Testing Focus
Unit tests validate specific examples, edge cases, and integration points:
- **Built-in Pattern Recognition**: Verify detection of specific credential formats (AWS keys, JWT tokens, GitHub IDs)
- **Default Rule Initialization**: Confirm presence and correctness of all default rules
- **Profile Management**: Test creation, deletion, and switching of named profiles
- **Theme Application**: Verify correct CSS class application for each theme
- **Error Boundary Conditions**: Test behavior with empty inputs, malformed JSON, and storage failures

### Property-Based Testing Configuration
Property tests validate universal behaviors across randomized inputs:
- **Testing Library**: Use fast-check for JavaScript property-based testing
- **Iteration Count**: Minimum 100 iterations per property test for statistical confidence
- **Test Tagging**: Each property test tagged with format: **Feature: data-sanitizer, Property {number}: {property_text}**
- **Input Generation**: Custom generators for JSON structures, rule configurations, and sensitive data patterns
- **Shrinking Strategy**: Automatic test case minimization for failure reproduction

### Example Property Test Generators

```javascript
// JSON structure generator with embedded sensitive data
const jsonWithSecretsGenerator = fc.oneof(
  fc.record({
    apiKey: fc.string().filter(s => s.startsWith('sk_')),
    config: fc.record({
      email: fc.emailAddress(),
      token: fc.string().filter(s => s.startsWith('eyJ'))
    }),
    users: fc.array(fc.record({
      name: fc.fullName(),
      phone: fc.phoneNumber()
    }))
  }),
  fc.array(fc.oneof(
    fc.string(),
    fc.record({ secret: fc.string().filter(s => /AKIA[A-Z0-9]{16}/.test(s)) })
  ))
);

// Rule configuration generator
const ruleGenerator = fc.record({
  type: fc.oneof(fc.constant('literal'), fc.constant('regex'), fc.constant('builtin'), fc.constant('kv')),
  pattern: fc.string().filter(s => s.length > 0 && s.length < 100),
  replacement: fc.oneof(fc.string(), fc.constant(null)),
  category: fc.oneof(fc.constant('secrets'), fc.constant('pii'), fc.constant('company')),
  enabled: fc.boolean()
});

// Text with embedded patterns generator
const textWithPatternsGenerator = fc.string().chain(base => 
  fc.array(fc.oneof(
    fc.constant('user@example.com'),
    fc.constant('AKIAIOSFODNN7EXAMPLE'),
    fc.constant('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'),
    fc.constant('+1-555-123-4567')
  )).map(patterns => 
    patterns.reduce((text, pattern, i) => 
      text + (i > 0 ? ' ' : '') + pattern, base)
  )
);
```

### Test Implementation Requirements
- Each correctness property must be implemented by exactly one property-based test
- Property tests should generate diverse inputs including edge cases through custom generators
- Unit tests should focus on specific examples that demonstrate correct behavior
- Integration tests should verify component interactions without duplicating property test coverage
- All tests must be runnable in browser environment without external dependencies

### Cross-Platform Validation Framework
The testing strategy includes JavaScript-based validation for consistency:
- **Node.js Test Runner**: Same JavaScript tests executed in Node.js environment for CI/CD
- **Sample Data Testing**: Comprehensive test suites with real-world JSON and YAML samples
- **Pattern Accuracy Validation**: Verify detection rates for all built-in patterns using known test vectors
- **Performance Benchmarking**: Automated performance regression testing with size-based test cases
- **Browser Compatibility**: Automated testing across Chrome, Firefox, Safari, and Edge