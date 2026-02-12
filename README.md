# AISanitizr 🛡️

Enterprise-grade data sanitization for AI workflows. Remove sensitive information before sharing with AI systems or external services.

## ✨ Features

- **🎨 Modern UI**: Beautiful, responsive interface inspired by big tech companies
- **🛡️ Bulletproof Engine**: Advanced v3 engine with comprehensive error handling
- **🎯 90%+ Coverage**: Detects all major sensitive data patterns
- **🏢 Custom Localization**: Company-specific sensitive word detection
- **⚡ High Performance**: Optimized with LRU caching and timeout protection
- **🔒 Client-Side Only**: All processing happens locally, no data leaves your browser
- **📊 Enterprise Ready**: Complete management interface for rules, history, and settings
- **🌓 Theme Support**: Light, dark, and system themes
- **📱 Responsive Design**: Works perfectly on desktop, tablet, and mobile
- **🤖 AI-Focused**: Designed specifically for sanitizing data before AI interactions

## 🚀 Quick Start

### NPM (Recommended)

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Open browser to http://localhost:3000
```

### Direct Access

- **Modern UI**: http://localhost:3000/modern (default)
- **Classic UI**: http://localhost:3000/classic
- **Settings**: http://localhost:3000/settings.html

## 🎨 UI Versions

### Modern UI (Default)
- Clean, modern design inspired by leading tech companies
- Smooth animations and micro-interactions
- Advanced typography and spacing system
- Glassmorphism effects with backdrop blur
- Responsive grid layouts

### Classic UI
- Original bulletproof interface
- Functional and reliable
- Full feature compatibility

## 📋 Supported Patterns

### 🔐 Secrets & Credentials
- API Keys (OpenAI, Anthropic, GitHub, Stripe, etc.)
- Database connection strings
- JWT tokens
- Private keys (RSA, EC, DSA)
- AWS credentials
- OAuth tokens

### 👤 Personal Information (PII)
- Email addresses
- Phone numbers (US/International)
- Social Security Numbers
- Credit card numbers
- CVV codes
- IP addresses (IPv4/IPv6)

### 🏢 Company Information
- Custom company names
- Project codenames
- Internal terminology
- Competitor references

## 🎮 Usage Examples

### Basic Sanitization

```javascript
// Load the app and paste your sensitive data
const input = `
Contact: john@company.com
API Key: sk-1234567890abcdefghijklmnopqrstuvwxyz
Database: postgresql://user:pass@localhost:5432/db
Phone: 555-123-4567
`;

// Click "Sanitize" button or use real-time processing
// Output: Sensitive data automatically replaced with safe alternatives
```

### Custom Company Words

```javascript
// Configure your organization
Company: "Microsoft"
Competitors: ["Google", "Apple", "Amazon"]
Projects: ["Azure", "Office365", "Teams"]
Custom Words: ["Redmond", "confidential"]

// Input: "Microsoft Azure team in Redmond working on confidential features"
// Output: "Google Cloud team in TechCity working on sensitive features"
```

## 🛠️ Development

### Project Structure

```
data-sanitizer-bulletproof/
├── src/
│   ├── sanitizer-engine-bulletproof.js  # Main engine
│   ├── storage.js                       # Data persistence
│   └── types.js                         # Type definitions
├── public/
│   ├── index-bulletproof.html           # Main app
│   ├── settings.html                    # Settings page
│   ├── manage-rules.html                # Rule management
│   ├── view-history.html                # History viewer
│   └── custom-words-settings.html       # Custom words config
├── test/
│   ├── test-production-readiness.html   # Production tests
│   ├── test-comprehensive-payload.html  # Payload testing
│   └── test-coverage-improvement.html   # Coverage analysis
├── server.js                            # Express server
└── package.json                         # NPM configuration
```

### Available Scripts

```bash
npm start          # Start production server
npm run dev        # Start development server with hot reload
npm test           # Run test suite
npm run serve      # Simple HTTP server
npm run build      # Build for production
npm run lint       # Code linting
```

### Testing

```bash
# Run comprehensive test suite
npm test

# Test specific components
npm run test:comprehensive  # Full payload testing
npm run test:coverage      # Coverage analysis

# Manual testing
open http://localhost:3000/test-production-readiness.html
```

## 🔧 Configuration

### Custom Sensitive Words

1. Click "🎯 Custom Words" in the main app
2. Configure your company information
3. Add competitors, projects, and custom terms
4. Choose replacement strategy
5. Test with live preview

### Rule Management

1. Click gear icon → "Manage Rules"
2. Add/edit/delete detection patterns
3. Test rules with sample data
4. Import/export configurations

### Settings

1. Click gear icon → "Settings"
2. Configure themes, performance, storage
3. Export/import all application data
4. Monitor storage usage

## 🏢 Enterprise Deployment

### Security Features

- **Client-side processing**: No data transmission
- **CSP headers**: Content Security Policy protection
- **Helmet.js**: Security middleware
- **CORS configuration**: Cross-origin protection
- **Input validation**: Comprehensive sanitization

### Performance Optimizations

- **LRU Caching**: Intelligent replacement caching
- **Timeout Protection**: ReDoS attack prevention
- **Memory Management**: Bounded cache sizes
- **Compression**: Gzip compression enabled
- **Static Asset Caching**: Optimized cache headers

### Monitoring

- Health check endpoint: `/api/health`
- Version info: `/api/version`
- Performance metrics in browser console
- Storage usage monitoring

## 📊 Coverage Analysis

The bulletproof engine achieves 90%+ coverage on comprehensive test datasets:

- **68% → 90%+**: Improved from v2 to v3
- **Critical patterns**: All major sensitive data types
- **Edge cases**: ReDoS protection, memory limits
- **Real-world data**: Tested with enterprise payloads

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new patterns
4. Ensure 90%+ coverage maintained
5. Submit pull request

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

- **Issues**: GitHub Issues
- **Documentation**: README.md
- **Testing**: Built-in test suite
- **Debug**: Settings → Debug button

---

**Built with ❤️ for enterprise data security**