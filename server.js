const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const CONFIG_PATH = path.join(__dirname, 'config.json');
const THEMES_PATH = path.join(__dirname, 'themes.json');

// HELPER: Always prioritize environment variable for admin password
const getAdminPassword = () => process.env.ADMIN_PASSWORD || 'cyberpunk2024';

// Load config function (moved to top)
async function loadConfig() {
  try {
    const data = await fs.readFile(CONFIG_PATH, 'utf8');
    const fileConfig = JSON.parse(data);
    
    // CRITICAL: Override adminPassword with environment variable
    app.locals.config = {
      ...fileConfig,
      adminPassword: getAdminPassword(),
    };
    return app.locals.config;
  } catch (error) {
    // File doesn't exist - create fresh config with env var password
    const defaultConfig = {
      adminPassword: getAdminPassword(),
      finalUrl: 'https://msod.skope.net.au',
      botDetectionEnabled: true,
      blockingCriteria: {
        minScore: 0.7,
        blockBotUA: true,
        blockScraperISP: true,
        blockIPAbuser: true,
        blockSuspiciousTraffic: false,
        blockDataCenterASN: true
      },
      allowedDomains: [],
      allowAllDomains: false,
      allowedCountries: [],
      blockedCountries: ["North Korea", "Iran", "Russia"],
      ipBlacklist: ["192.168.1.1"],
      theme: "default",
      lastUpdated: new Date().toISOString()
    };
    
    app.locals.config = defaultConfig;
    
    // Attempt to save (will fail on ephemeral filesystem, but that's ok)
    try {
      await saveConfig(defaultConfig);
    } catch (e) {
      console.warn('⚠️ Could not persist config.json (ephemeral filesystem)');
    }
    
    return defaultConfig;
  }
}

// Save config function
async function saveConfig(config) {
  config.lastUpdated = new Date().toISOString();
  app.locals.config = config;
  await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// Middleware to ensure config is loaded FIRST (moved before CORS)
app.use(async (req, res, next) => {
  if (!req.app.locals.config) {
    await loadConfig();
  }
  next();
});

// Security and parsing middleware
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(express.json({ limit: '10mb' }));

// ====== CORRECTED CORS MIDDLEWARE - handles /sdk.js properly ======
app.use((req, res, next) => {
  const origin = req.get('origin');
  const config = req.app.locals.config;
  const allowedDomains = config.allowedDomains || [];
  const allowAllDomains = config.allowAllDomains || false;

  // Helper to check if origin matches allowed domains
  const isOriginAllowed = (originToCheck) => {
    if (!originToCheck) return true; // Same-origin request
    if (allowAllDomains) return true;
    
    try {
      const originHostname = new URL(originToCheck).hostname;
      return allowedDomains.some(domain => 
        originHostname === domain || originHostname.endsWith('.' + domain)
      );
    } catch {
      return false;
    }
  };

  // CRITICAL: Handle /sdk.js with proper CORS headers
  if (req.path === '/sdk.js') {
    if (isOriginAllowed(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
      return next(); // Continue to static file handler
    } else {
      return res.status(403).json({ error: 'ERR-DOMAIN-BLOCKED' });
    }
  }

  // Handle preflight OPTIONS for API
  if (req.method === 'OPTIONS' && req.path.startsWith('/api')) {
    if (isOriginAllowed(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-SDK-Version');
      res.setHeader('Vary', 'Origin');
      return res.status(200).end();
    } else {
      return res.status(403).json({ error: 'ERR-DOMAIN-BLOCKED' });
    }
  }

  // For API endpoints
  if (req.path.startsWith('/api')) {
    if (isOriginAllowed(origin)) {
      cors({ origin: origin || true, credentials: true })(req, res, next);
    } else {
      res.status(403).json({ error: 'ERR-DOMAIN-BLOCKED' });
    }
    return;
  }

  // For other static files - allow without CORS headers
  if (req.path.includes('.')) {
    return next();
  }

  next();
});

// Serve static files AFTER CORS middleware (CRITICAL ORDER)
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'ERR-RATE-LIMIT' }
});
app.use('/api/', limiter);

// API Routes (unchanged from your code)
app.get('/api/config', async (req, res) => {
  try {
    const config = req.app.locals.config;
    // Strip sensitive data
    res.json({
      botDetectionEnabled: config.botDetectionEnabled,
      blockingCriteria: config.blockingCriteria,
      allowedCountries: config.allowedCountries,
      blockedCountries: config.blockedCountries,
      ipBlacklist: config.ipBlacklist,
      finalUrl: config.finalUrl,
      theme: config.theme,
      allowedDomains: config.allowedDomains,
      allowAllDomains: config.allowAllDomains,
      lastUpdated: config.lastUpdated
    });
  } catch (error) {
    res.status(500).json({ error: 'ERR-CONFIG-LOAD' });
  }
});

app.get('/api/themes', async (req, res) => {
  try {
    const data = await fs.readFile(THEMES_PATH, 'utf8');
    res.json(JSON.parse(data));
  } catch (error) {
    res.status(500).json({ error: 'ERR-THEMES-LOAD' });
  }
});

app.post('/api/bot-detect', async (req, res) => {
  try {
    const { ip, user_agent } = req.body;
    const response = await fetch('https://bad-defender-production.up.railway.app/api/detect_bot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, user_agent })
    });
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'ERR-BOT-DETECT' });
  }
});

app.get('/api/geoip/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    const response = await fetch(`https://ipapi.co/${ip}/json/`);
    const data = await response.json();
    res.json({
      country: data.country_name || 'Unknown',
      ip: data.ip || ip
    });
  } catch (error) {
    res.status(500).json({ error: 'ERR-GEOIP' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  const config = req.app.locals.config;

  if (password === config.adminPassword) {
    res.json({ success: true, token: 'admin-session-' + Date.now() });
  } else {
    res.status(401).json({ error: 'ERR-INVALID-PASS' });
  }
});

app.get('/api/admin/config', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'ERR-NO-AUTH' });
  }

  res.json(req.app.locals.config);
});

app.post('/api/admin/config', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'ERR-NO-AUTH' });
  }

  try {
    const newConfig = req.body;
    const oldConfig = req.app.locals.config;

    newConfig.adminPassword = newConfig.adminPassword || oldConfig.adminPassword;

    await saveConfig(newConfig);
    res.json({ success: true, lastUpdated: newConfig.lastUpdated });
  } catch (error) {
    res.status(500).json({ error: 'ERR-CONFIG-SAVE' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK', code: 'HEALTHY' });
});

// Start server
app.listen(PORT, '0.0.0.0', async () => {
  await loadConfig();
  console.log(`🚀 Control Station v3.1 running on port ${PORT}`);
  console.log(`📊 Admin: http://localhost:${PORT}/admin.html`);
  console.log(`🎯 SDK: http://localhost:${PORT}/sdk.js`);
  console.log(`🔒 Domain whitelist active: ${app.locals.config.allowAllDomains ? 'DISABLED' : 'ENABLED'}`);
});
