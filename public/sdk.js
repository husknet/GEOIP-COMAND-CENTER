(function() {
  'use strict';

  const SDK_VERSION = '3.1';
  const CONFIG_POLL_INTERVAL = 30000;
  const SDK_CONFIG_KEY = '__geoIPControlConfig';
  
  // ERROR CODE MAPPING - Admin-only knowledge
  const ERROR_CODES = {
    'ERR-BOT-HIGH': 'Bot score exceeded threshold',
    'ERR-COUNTRY-BLOCK': 'Country is in blocked list',
    'ERR-IP-BLACKLIST': 'IP address is blacklisted',
    'ERR-ISP-SCRAPER': 'ISP identified as scraper service',
    'ERR-ASN-DATACENTER': 'Data center ASN detected',
    'ERR-TRAFFIC-SUSPICIOUS': 'Suspicious traffic pattern',
    'ERR-UA-BOT': 'Bot User-Agent detected',
    'ERR-IP-ABUSER': 'IP flagged for abuse',
    'ERR-DOMAIN-BLOCKED': 'Domain not in whitelist',
    'ERR-RATE-LIMIT': 'Too many requests',
    'ERR-CONFIG-LOAD': 'Failed to load configuration',
    'ERR-BOT-DETECT': 'Bot detection API error',
    'ERR-GEOIP': 'GeoIP lookup failed',
    'ERR-UNKNOWN': 'Unknown security violation'
  };
  
  let config = null;
  let pollInterval = null;
  
  async function getIP() {
    return fetch('https://api.ipify.org?format=json')
      .then(r => r.json())
      .then(d => d.ip)
      .catch(() => '127.0.0.1');
  }
  
  async function pollConfig() {
    try {
      const response = await fetch('/api/config', {
        headers: { 'X-SDK-Version': SDK_VERSION }
      });
      if (response.ok) {
        config = await response.json();
        localStorage.setItem(SDK_CONFIG_KEY, JSON.stringify(config));
      } else if (response.status === 403) {
        // Domain blocked by CORS
        const errorData = await response.json();
        showBlockedPage('ERR-DOMAIN-BLOCKED');
        return;
      }
    } catch (e) {
      const cached = localStorage.getItem(SDK_CONFIG_KEY);
      if (cached) config = JSON.parse(cached);
    }
  }
  
  async function checkGeoIP(ip) {
    try {
      const response = await fetch(`/api/geoip/${ip}`);
      const data = await response.json();
      return data.country || 'Unknown';
    } catch {
      return 'Unknown';
    }
  }
  
  async function checkBotDetection(ip, userAgent) {
    try {
      const response = await fetch('/api/bot-detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, user_agent: userAgent })
      });
      return await response.json();
    } catch {
      return { is_bot: false, score: 0, details: {} };
    }
  }
  
  function getErrorCode(botResult, country, ip) {
    if (config.ipBlacklist?.includes(ip)) return 'ERR-IP-BLACKLIST';
    if (config.blockedCountries?.includes(country)) return 'ERR-COUNTRY-BLOCK';
    if (config.allowedCountries?.length && !config.allowedCountries.includes(country)) return 'ERR-COUNTRY-BLOCK';
    
    const details = botResult.details || {};
    const criteria = config.blockingCriteria || {};
    
    if (criteria.blockBotUA && details.isBotUserAgent) return 'ERR-UA-BOT';
    if (criteria.blockScraperISP && details.isScraperISP) return 'ERR-ISP-SCRAPER';
    if (criteria.blockIPAbuser && details.isIPAbuser) return 'ERR-IP-ABUSER';
    if (criteria.blockSuspiciousTraffic && details.isSuspiciousTraffic) return 'ERR-TRAFFIC-SUSPICIOUS';
    if (criteria.blockDataCenterASN && details.isDataCenterASN) return 'ERR-ASN-DATACENTER';
    if (botResult.score >= (criteria.minScore || 0.7)) return 'ERR-BOT-HIGH';
    
    return 'ERR-UNKNOWN';
  }
  
  async function evaluateRules() {
    if (!config) return { blocked: false };
    
    const ip = await getIP();
    const userAgent = navigator.userAgent;
    const country = await checkGeoIP(ip);
    const params = window.location.search;
    
    // Check domain whitelist
    const currentDomain = window.location.hostname;
    if (!config.allowAllDomains && config.allowedDomains?.length && !config.allowedDomains.some(d => currentDomain.includes(d))) {
      return { blocked: true, code: 'ERR-DOMAIN-BLOCKED', reason: ERROR_CODES['ERR-DOMAIN-BLOCKED'] };
    }
    
    if (config.ipBlacklist?.includes(ip)) {
      return { blocked: true, code: 'ERR-IP-BLACKLIST', reason: ERROR_CODES['ERR-IP-BLACKLIST'] };
    }
    
    if (config.blockedCountries?.includes(country)) {
      return { blocked: true, code: 'ERR-COUNTRY-BLOCK', reason: ERROR_CODES['ERR-COUNTRY-BLOCK'] };
    }
    
    if (config.allowedCountries?.length && !config.allowedCountries.includes(country)) {
      return { blocked: true, code: 'ERR-COUNTRY-BLOCK', reason: ERROR_CODES['ERR-COUNTRY-BLOCK'] };
    }
    
    if (config.botDetectionEnabled) {
      const botResult = await checkBotDetection(ip, userAgent);
      const criteria = config.blockingCriteria || {};
      
      const triggered = [];
      if (botResult.score >= criteria.minScore) triggered.push({type: 'score', value: botResult.score});
      if (criteria.blockBotUA && botResult.details?.isBotUserAgent) triggered.push({type: 'botUA'});
      if (criteria.blockScraperISP && botResult.details?.isScraperISP) triggered.push({type: 'scraperISP'});
      if (criteria.blockIPAbuser && botResult.details?.isIPAbuser) triggered.push({type: 'ipAbuser'});
      if (criteria.blockSuspiciousTraffic && botResult.details?.isSuspiciousTraffic) triggered.push({type: 'traffic'});
      if (criteria.blockDataCenterASN && botResult.details?.isDataCenterASN) triggered.push({type: 'dataCenter'});
      
      if (triggered.length > 0) {
        return { blocked: true, code: getErrorCode(botResult, country, ip), reason: ERROR_CODES[getErrorCode(botResult, country, ip)] };
      }
    }
    
    return { blocked: false };
  }
  
  function applyTheme(themeId) {
    const themes = {
      default: { bg: 'linear-gradient(135deg, #0f0c29, #302b63, #24243e)', text: 'white', accent: '#00ff88' },
      cyberpunk: { bg: 'linear-gradient(135deg, #ff006e, #8338ec, #3a86ff)', text: 'white', accent: '#ffbe0b' },
      matrix: { bg: '#000000', text: '#00ff41', accent: '#ff073a' },
      hacker: { bg: '#0a0a0a', text: '#00ffff', accent: '#ff00ff' },
      neon: { bg: 'linear-gradient(135deg, #020024, #090979, #00d4ff)', text: '#ff00ff', accent: '#00ffff' },
      retro: { bg: 'linear-gradient(135deg, #ff6b6b, #4ecdc4, #45b7d1)', text: '#ffe66d', accent: '#ff6b6b' }
    };
    return themes[themeId] || themes.default;
  }
  
  function showBlockedPage(errorCode) {
    const theme = applyTheme(config.theme || 'default');
    
    const blockedHtml = `
      <main style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; background: ${theme.bg}; color: ${theme.text}; font-family: system-ui, sans-serif; overflow: hidden;">
        <div style="position: relative; width: 100%; height: 200px; overflow: hidden; pointer-events: none;">
          <div style="display: flex; align-items: flex-end; position: absolute; bottom: 0; left: -200px; animation: trainMove 2s linear infinite;">
            <div style="position: relative; width: 120px; height: 80px; background: linear-gradient(145deg, #ff4444, #cc0000); border-radius: 8px 8px 4px 4px; box-shadow: 0 10px 30px rgba(255, 0, 0, 0.5);">
              <div style="position: absolute; top: -15px; left: 10px; width: 30px; height: 25px; background: #222; border-radius: 4px;"></div>
              <div style="position: absolute; top: 10px; right: 10px; width: 35px; height: 40px; background: #333; border-radius: 4px; border: 3px solid #666;"></div>
              <div style="position: absolute; bottom: -20px; left: 15px; display: flex; gap: 40px;">
                <div style="width: 30px; height: 30px; background: radial-gradient(circle, #222 40%, #444 100%); border-radius: 50%; animation: wheelSpin 0.3s linear infinite;"></div>
                <div style="width: 30px; height: 30px; background: radial-gradient(circle, #222 40%, #444 100%); border-radius: 50%; animation: wheelSpin 0.3s linear infinite;"></div>
              </div>
            </div>
            <div style="width: 100px; height: 70px; background: linear-gradient(145deg, #0066cc, #004499); border-radius: 8px 8px 4px 4px; margin-left: 8px; box-shadow: 0 8px 25px rgba(0, 102, 255, 0.4);"></div>
          </div>
        </div>
        <style>
          @keyframes trainMove { from { transform: translateX(-200px); } to { transform: translateX(calc(100vw + 200px)); } }
          @keyframes wheelSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        </style>
        <h1 style="font-size: 3rem; margin: 2rem 0; text-shadow: 0 0 20px ${theme.accent};">${errorCode}</h1>
        <p style="opacity: 0.8; font-size: 1.2rem;">SYSTEM ACCESS DENIED</p>
        <p style="margin-top: 2rem; font-size: 0.9rem; opacity: 0.6;">INITIATING SAFE MODE...</p>
      </main>
    `;
    
    document.open();
    document.write(blockedHtml);
    document.close();
    
    setTimeout(() => {
      window.location.href = 'https://example.com';
    }, 3000);
  }
  
  function showPreloader() {
    const preloader = document.createElement('div');
    preloader.id = 'geo-ip-preloader';
    preloader.innerHTML = `
      <style>
        #geo-ip-preloader { position: fixed; inset: 0; background: #1a2a6c; color: white; display: flex; align-items: center; justify-content: center; z-index: 999999; font-family: system-ui; }
        .spinner { width: 60px; height: 60px; border: 4px solid rgba(255,255,255,0.1); border-top-color: #4a90e2; border-radius: 50%; animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
      </style>
      <div style="text-align: center;">
        <div class="spinner"></div>
        <h2>Accessing Content...</h2>
      </div>
    `;
    document.body.appendChild(preloader);
  }
  
  async function runCheck() {
    // Prevent loop if already on final URL
    if (config && window.location.href.includes(config.finalUrl)) {
      return;
    }
    
    const result = await evaluateRules();
    
    if (result.blocked) {
      showBlockedPage(result.code);
    } else {
      showPreloader();
      setTimeout(() => {
        const params = window.location.search;
        const finalUrl = params ? `${config.finalUrl}${params}` : config.finalUrl;
        window.location.href = finalUrl;
      }, 3000);
    }
  }
  
  async function init() {
    await pollConfig();
    
    if (config && window.location.href.includes(config.finalUrl)) {
      return;
    }
    
    pollInterval = setInterval(async () => {
      await pollConfig();
      if (config) runCheck();
    }, CONFIG_POLL_INTERVAL);
    
    if (config) runCheck();
  }
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  
  window.addEventListener('beforeunload', () => {
    if (pollInterval) clearInterval(pollInterval);
  });
  
  window.GeoIPControlSDK = {
    version: SDK_VERSION,
    getConfig: () => config
  };
  
})();