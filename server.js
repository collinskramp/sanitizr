const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '127.0.0.1';
const isDev = process.argv.includes('--dev');

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));

// Enable CORS for development
if (isDev) {
  app.use(cors());
}

// Compression middleware
app.use(compression());

// Serve static files
app.use(express.static('.', {
  index: 'index.html',
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    } else if (path.endsWith('.js') || path.endsWith('.css')) {
      res.setHeader('Cache-Control', 'public, max-age=31536000');
    }
  }
}));

// API routes for health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: require('./package.json').version,
    timestamp: new Date().toISOString(),
    environment: isDev ? 'development' : 'production'
  });
});

// API route for version info
app.get('/api/version', (req, res) => {
  const pkg = require('./package.json');
  res.json({
    name: pkg.name,
    version: pkg.version,
    description: pkg.description
  });
});

// UI version routes
app.get('/classic', (req, res) => {
  res.sendFile(path.join(__dirname, 'index-bulletproof.html'));
});

app.get('/modern', (req, res) => {
  res.sendFile(path.join(__dirname, 'index-modern.html'));
});

app.get('/v3', (req, res) => {
  res.sendFile(path.join(__dirname, 'index-v3.html'));
});

// Fallback to v3 UI for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index-v3.html'));
});

// Start server
app.listen(PORT, HOST, () => {
  console.log(`✓ AISanitizr`);
  console.log(`  http://${HOST}:${PORT}`);
  console.log(`  Engine: Bulletproof | Coverage: 90%+`);
  
  if (isDev) {
    console.log(`  Settings: http://localhost:${PORT}/settings.html`);
  }
});
