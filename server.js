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

// ===== COMPREHENSIVE COUNTRY CODE MAPPING (ISO 3166-1 alpha-2) =====
const COUNTRY_CODE_MAP = {
  // A
  'AF': 'Afghanistan', 'AX': 'Åland Islands', 'AL': 'Albania', 'DZ': 'Algeria',
  'AS': 'American Samoa', 'AD': 'Andorra', 'AO': 'Angola', 'AI': 'Anguilla',
  'AQ': 'Antarctica', 'AG': 'Antigua and Barbuda', 'AR': 'Argentina', 'AM': 'Armenia',
  'AW': 'Aruba', 'AU': 'Australia', 'AT': 'Austria', 'AZ': 'Azerbaijan',
  
  // B
  'BS': 'Bahamas', 'BH': 'Bahrain', 'BD': 'Bangladesh', 'BB': 'Barbados',
  'BY': 'Belarus', 'BE': 'Belgium', 'BZ': 'Belize', 'BJ': 'Benin', 'BM': 'Bermuda',
  'BT': 'Bhutan', 'BO': 'Bolivia', 'BQ': 'Bonaire', 'BA': 'Bosnia', 'BW': 'Botswana',
  'BV': 'Bouvet Island', 'BR': 'Brazil', 'IO': 'British Indian Ocean Territory',
  'BN': 'Brunei', 'BG': 'Bulgaria', 'BF': 'Burkina', 'BI': 'Burundi',
  
  // C
  'KH': 'Cambodia', 'CM': 'Cameroon', 'CA': 'Canada', 'CV': 'Cape Verde',
  'KY': 'Cayman Islands', 'CF': 'Central African Republic', 'TD': 'Chad', 'CL': 'Chile',
  'CN': 'China', 'CX': 'Christmas Island', 'CC': 'Cocos Islands', 'CO': 'Colombia',
  'KM': 'Comoros', 'CG': 'Congo', 'CD': 'Congo', 'CK': 'Cook Islands', 'CR': 'Costa Rica',
  'CI': 'Côte d\'Ivoire', 'HR': 'Croatia', 'CU': 'Cuba', 'CW': 'Curaçao', 'CY': 'Cyprus',
  'CZ': 'Czech',
  
  // D
  'DK': 'Denmark', 'DJ': 'Djibouti', 'DM': 'Dominica', 'DO': 'Dominican Republic',
  
  // E
  'EC': 'Ecuador', 'EG': 'Egypt', 'SV': 'El Salvador', 'GQ': 'Equatorial Guinea',
  'ER': 'Eritrea', 'EE': 'Estonia', 'SZ': 'Eswatini', 'ET': 'Ethiopia',
  
  // F
  'FK': 'Falkland Islands', 'FO': 'Faroe Islands', 'FJ': 'Fiji', 'FI': 'Finland',
  'FR': 'France', 'GF': 'French Guiana', 'PF': 'French Polynesia', 'TF': 'French Southern Territories',
  
  // G
  'GA': 'Gabon', 'GM': 'Gambia', 'GE': 'Georgia', 'DE': 'Germany', 'GH': 'Ghana',
  'GI': 'Gibraltar', 'GR': 'Greece', 'GL': 'Greenland', 'GD': 'Grenada', 'GP': 'Guadeloupe',
  'GU': 'Guam', 'GT': 'Guatemala', 'GG': 'Guernsey', 'GN': 'Guinea', 'GW': 'Guinea-Bissau',
  'GY': 'Guyana',
  
  // H
  'HT': 'Haiti', 'HM': 'Heard Island', 'VA': 'Vatican City', 'HN': 'Honduras',
  'HK': 'Hong Kong', 'HU': 'Hungary',
  
  // I
  'IS': 'Iceland', 'IN': 'India', 'ID': 'Indonesia', 'IR': 'Iran', 'IQ': 'Iraq',
  'IE': 'Ireland', 'IM': 'Isle of Man', 'IL': 'Israel', 'IT': 'Italy',
  
  // J
  'JM': 'Jamaica', 'JP': 'Japan', 'JE': 'Jersey', 'JO': 'Jordan',
  
  // K
  'KZ': 'Kazakhstan', 'KE': 'Kenya', 'KI': 'Kiribati', 'KP': 'Korea', 'KR': 'Korea',
  'KW': 'Kuwait', 'KG': 'Kyrgyzstan',
  
  // L
  'LA': 'Laos', 'LV': 'Latvia', 'LB': 'Lebanon', 'LS': 'Lesotho', 'LR': 'Liberia',
  'LY': 'Libya', 'LI': 'Liechtenstein', 'LT': 'Lithuania', 'LU': 'Luxembourg',
  
  // M
  'MO': 'Macau', 'MK': 'Macedonia', 'MG': 'Madagascar', 'MW': 'Malawi',
  'MY': 'Malaysia', 'MV': 'Maldives', 'ML': 'Mali', 'MT': 'Malta',
  'MH': 'Marshall Islands', 'MQ': 'Martinique', 'MR': 'Mauritania', 'MU': 'Mauritius',
  'YT': 'Mayotte', 'MX': 'Mexico', 'FM': 'Micronesia', 'MD': 'Moldova', 'MC': 'Monaco',
  'MN': 'Mongolia', 'ME': 'Montenegro', 'MS': 'Montserrat', 'MA': 'Morocco',
  'MZ': 'Mozambique', 'MM': 'Myanmar',
  
  // N
  'NA': 'Namibia', 'NR': 'Nauru', 'NP': 'Nepal', 'NL': 'Netherlands', 'NC': 'New Caledonia',
  'NZ': 'New Zealand', 'NI': 'Nicaragua', 'NE': 'Niger', 'NG': 'Nigeria', 'NU': 'Niue',
  'NF': 'Norfolk Island', 'MP': 'Northern Mariana Islands', 'NO': 'Norway',
  
  // O
  'OM': 'Oman',
  
  // P
  'PK': 'Pakistan', 'PW': 'Palau', 'PS': 'Palestine', 'PA': 'Panama', 'PG': 'Papua',
  'PY': 'Paraguay', 'PE': 'Peru', 'PH': 'Philippines', 'PN': 'Pitcairn', 'PL': 'Poland',
  'PT': 'Portugal', 'PR': 'Puerto Rico',
  
  // Q
  'QA': 'Qatar',
  
  // R
  'RE': 'Réunion', 'RO': 'Romania', 'RU': 'Russia', 'RW': 'Rwanda',
  
  // S
  'BL': 'Saint Barthélemy', 'SH': 'Saint Helena', 'KN': 'Saint Kitts', 'LC': 'Saint Lucia',
  'MF': 'Saint Martin', 'PM': 'Saint Pierre', 'VC': 'Saint Vincent', 'WS': 'Samoa',
  'SM': 'San Marino', 'ST': 'São Tomé', 'SA': 'Saudi Arabia', 'SN': 'Senegal',
  'RS': 'Serbia', 'SC': 'Seychelles', 'SL': 'Sierra', 'SG': 'Singapore',
  'SX': 'Sint Maarten', 'SK': 'Slovakia', 'SI': 'Slovenia', 'SB': 'Solomon Islands',
  'SO': 'Somalia', 'ZA': 'South Africa', 'GS': 'South Georgia', 'SS': 'South Sudan',
  'ES': 'Spain', 'LK': 'Sri Lanka', 'SD': 'Sudan', 'SR': 'Suriname', 'SJ': 'Svalbard',
  'SE': 'Sweden', 'CH': 'Switzerland', 'SY': 'Syria',
  
  // T
  'TW': 'Taiwan', 'TJ': 'Tajikistan', 'TZ': 'Tanzania', 'TH': 'Thailand', 'TL': 'Timor-Leste',
  'TG': 'Togo', 'TK': 'Tokelau', 'TO': 'Tonga', 'TT': 'Trinidad', 'TN': 'Tunisia',
  'TR': 'Turkey', 'TM': 'Turkmenistan', 'TC': 'Turks and Caicos', 'TV': 'Tuvalu',
  
  // U
  'UG': 'Uganda', 'UA': 'Ukraine', 'AE': 'UAE', 'GB': 'United Kingdom', 'US': 'United States',
  'UM': 'United States Minor Outlying Islands', 'UY': 'Uruguay', 'UZ': 'Uzbekistan',
  
  // V
  'VU': 'Vanuatu', 'VE': 'Venezuela', 'VN': 'Vietnam', 'VG': 'Virgin Islands', 'VI': 'Virgin Islands',
  
  // W
  'WF': 'Wallis and Futuna', 'EH': 'Western Sahara',
  
  // Y
  'YE': 'Yemen',
  
  // Z
  'ZM': 'Zambia', 'ZW': 'Zimbabwe'
};

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
app.use((req, res, next) => {
  const origin = req.get('origin');

  // Handle OPTIONS preflight FIRST (before path checks)
  if (req.method === 'OPTIONS') {
    // CRITICAL: Check whitelist even for preflight
    if (req.path.startsWith('/api') && !req.path.startsWith('/api/admin')) {
      if (isOriginAllowed(req)) {
        // Allowed: respond with CORS headers (only set origin if it exists)
        if (origin) {
          res.setHeader('Access-Control-Allow-Origin', origin);
          res.setHeader('Vary', 'Origin');
        }
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-SDK-Version');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        return res.status(200).end();
      } else {
        // Blocked: return 403 WITHOUT CORS headers
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
      // Add CORS headers only if origin exists
      if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
      }
      res.setHeader('Access-Control-Allow-Credentials', 'true');
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

// ===== SDK.js endpoint =====
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

// API Routes
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
  } catch (err) {
    console.error('❌ Config load error:', err);
    res.status(500).json({ error: 'ERR-CONFIG-LOAD' });
  }
});

app.get('/api/themes', async (req, res) => {
  try {
    const data = await fs.readFile(THEMES_PATH, 'utf8');
    res.json(JSON.parse(data));
  } catch (err) {
    console.error('❌ Themes load error:', err);
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
    res.json(await response.json());
  } catch (err) {
    console.error('❌ Bot detection error:', err);
    res.status(500).json({ error: 'ERR-BOT-DETECT' });
  }
});

// ===== ENHANCED GEOIP ENDPOINT WITH COMPLETE COUNTRY NORMALIZATION =====
app.get('/api/geoip/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    
    // Resolve real client IP with better proxy handling
    const clientIP = (ip === '127.0.0.1' || ip === '::1' || !ip)
      ? req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip 
      : ip;
    
    console.log(`📍 GeoIP lookup requested for: ${clientIP}`);
    
    const response = await fetch(`https://ipapi.co/${clientIP}/json/`);
    
    if (!response.ok) {
      throw new Error(`ipapi.co returned ${response.status}`);
    }
    
    const data = await response.json();
    
    // Multi-layer country normalization
    let country = data.country_name || data.country || 'Unknown';
    
    // Convert 2-letter ISO codes to full names
    if (country.length === 2 && COUNTRY_CODE_MAP[country.toUpperCase()]) {
      country = COUNTRY_CODE_MAP[country.toUpperCase()];
      console.log(`🔤 Converted country code "${data.country}" → "${country}"`);
    }
    
    // Handle special case for UK/GB
    if (country === 'GB' || country === 'UK') {
      country = 'United Kingdom';
    }
    
    // Final sanitization
    country = country.trim();
    
    console.log(`📍 GeoIP result: ${clientIP} → "${country}" (raw: "${data.country_name || data.country}")`);
    
    res.json({ country, ip: clientIP });
  } catch (error) {
    console.error(`❌ GeoIP lookup failed: ${error.message}`);
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
  } catch (err) {
    console.error('❌ Config save error:', err);
    res.status(500).json({ error: 'ERR-CONFIG-SAVE' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK', code: 'HEALTHY' });
});

// Start server
app.listen(PORT, '0.0.0.0', async () => {
  await loadConfig();
  console.log(`🚀 Control Station v3.2 running on port ${PORT}`);
  console.log(`📊 Admin: http://localhost:${PORT}/admin.html`);
  console.log(`🎁 SDK: http://localhost:${PORT}/sdk.js`);
  console.log(`🔒 Domain whitelist active: ${app.locals.config.allowAllDomains ? 'DISABLED' : 'ENABLED'}`);
  console.log(`🌍 Country code mapping: ${Object.keys(COUNTRY_CODE_MAP).length} countries loaded`);
});
