const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '127.0.0.1';
const isDev = process.env.NODE_ENV !== 'production';

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

// Serve static files from multiple directories
app.use('/css', express.static(path.join(__dirname, 'public/css')));
app.use('/js', express.static(path.join(__dirname, 'src')));
app.use(express.static(__dirname, {
  index: 'index.html',
  setHeaders: (res, filePath) => {
    if (isDev) {
      // No caching for development
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    } else {
      // Production caching
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      } else if (filePath.endsWith('.js') || filePath.endsWith('.css')) {
        res.setHeader('Cache-Control', 'public, max-age=31536000');
      }
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

// Fallback to main UI
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, HOST, () => {
  console.log(`✓ AISanitizr`);
  console.log(`  http://${HOST}:${PORT}`);
  console.log(`  Engine: Bulletproof | Coverage: 90%+`);
  console.log(`  Mode: ${isDev ? 'Development' : 'Production'}`);
});
