const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);
const CONFIG_PATH = path.join(__dirname, 'config.json');
const THEMES_PATH = path.join(__dirname, 'themes.json');

const getAdminPassword = () => process.env.ADMIN_PASSWORD || 'cyberpunk2024';

// Config functions
async function loadConfig() {
  try {
    const data = await fs.readFile(CONFIG_PATH, 'utf8');
    const fileConfig = JSON.parse(data);
    app.locals.config = { ...fileConfig, adminPassword: getAdminPassword() };
    return app.locals.config;
  } catch (error) {
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
    try { await saveConfig(defaultConfig); } catch (e) {}
    return defaultConfig;
  }
}

async function saveConfig(config) {
  config.lastUpdated = new Date().toISOString();
  app.locals.config = config;
  await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// Load config FIRST
app.use(async (req, res, next) => {
  if (!req.app.locals.config) {
    await loadConfig();
  }
  next();
});

// Security middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10mb' }));

// ===== HELPER FUNCTION: Whitelist Check =====
function isOriginAllowed(req) {
  const origin = req.get('origin');
  const config = req.app.locals.config;
  const allowedDomains = config.allowedDomains || [];
  const allowAllDomains = config.allowAllDomains || false;

  if (allowAllDomains) return true;
  if (!origin) return true; // Allow direct browser requests

  try {
    const originHostname = new URL(origin).hostname;
    return allowedDomains.some(domain => 
      originHostname === domain || originHostname.endsWith('.' + domain)
    );
  } catch {
    return false;
  }
}

// ===== CRITICAL: Centralized CORS + Whitelist Enforcement =====
// This replaces all previous CORS middleware blocks
app.use((req, res, next) => {
  const origin = req.get('origin');

  // Handle OPTIONS preflight FIRST (before path checks)
  if (req.method === 'OPTIONS') {
    // CRITICAL: Check whitelist even for preflight
    if (req.path.startsWith('/api') && !req.path.startsWith('/api/admin')) {
      if (isOriginAllowed(req)) {
        // Allowed: respond with CORS headers
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-SDK-Version');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');
        return res.status(200).end();
      } else {
        // Blocked: return 403 WITHOUT CORS headers
        // This forces browser to block the real request
        return res.status(403).json({ error: 'ERR-DOMAIN-BLOCKED' });
      }
    }
    
    // Admin preflight always passes
    if (req.path.startsWith('/api/admin')) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      return res.status(200).end();
    }
    
    return res.status(200).end();
  }

  // Handle actual API requests
  if (req.path.startsWith('/api') && !req.path.startsWith('/api/admin')) {
    if (isOriginAllowed(req)) {
      // Add CORS headers and proceed
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
      next();
    } else {
      // Block unauthorized domains
      res.status(403).json({ error: 'ERR-DOMAIN-BLOCKED' });
    }
    return;
  }

  // Continue for non-API routes
  next();
});

// ===== SDK.js endpoint (unchanged) =====
app.use('/sdk.js', (req, res, next) => {
  const origin = req.get('origin');
  const config = req.app.locals.config;
  const allowedDomains = config.allowedDomains || [];
  const allowAllDomains = config.allowAllDomains || false;

  const isOriginAllowed = (originToCheck) => {
    if (!originToCheck) return true;
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

  if (isOriginAllowed(origin)) {
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    next();
  } else {
    res.status(403).json({ error: 'ERR-DOMAIN-BLOCKED' });
  }
});

// Serve static files
app.use(express.static('public'));

// ===== HELPER FUNCTION: Rate Limit Skip Logic =====
function isWhitelistedDomain(req) {
  const config = req.app.locals.config;
  if (!config) return false;

  const origin = req.get('origin');
  const allowedDomains = config.allowedDomains || [];
  const allowAllDomains = config.allowAllDomains || false;

  if (allowAllDomains) return true;
  if (!origin) return false;

  try {
    const originHostname = new URL(origin).hostname;
    return allowedDomains.some(domain => {
      return originHostname === domain || originHostname.endsWith('.' + domain);
    });
  } catch (e) {
    return false;
  }
}

// ===== Rate limiting - skip for admin and whitelisted domains =====
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'ERR-RATE-LIMIT' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    const isAdmin = req.path.startsWith('/api/admin');
    const isWhitelisted = isWhitelistedDomain(req);
    
    if (isWhitelisted) {
      console.log(`Rate limit SKIPPED for whitelisted domain: ${req.get('origin')}`);
    }
    
    return isAdmin || isWhitelisted;
  }
}));

// API Routes (unchanged)
app.get('/api/config', async (req, res) => {
  try {
    const config = req.app.locals.config;
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
  } catch { res.status(500).json({ error: 'ERR-CONFIG-LOAD' }); }
});

app.get('/api/themes', async (req, res) => {
  try {
    const data = await fs.readFile(THEMES_PATH, 'utf8');
    res.json(JSON.parse(data));
  } catch { res.status(500).json({ error: 'ERR-THEMES-LOAD' }); }
});

app.post('/api/bot-detect', async (req, res) => {
  try {
    const { ip, user_agent } = req.body;
    const response = await fetch('https://bad-defender-production.up.railway.app/api/detect_bot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, user_agent })
    });
    res.json(await response.json());
  } catch { res.status(500).json({ error: 'ERR-BOT-DETECT' }); }
});

app.get('/api/geoip/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    const response = await fetch(`https://ipapi.co/${ip}/json/`);
    const data = await response.json();
    res.json({ country: data.country_name || 'Unknown', ip: data.ip || ip });
  } catch { res.status(500).json({ error: 'ERR-GEOIP' }); }
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
  } catch {
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
