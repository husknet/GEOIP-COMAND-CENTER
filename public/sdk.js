(function() {
  'use strict';

  const SDK_VERSION = '3.3';
  const CONFIG_POLL_INTERVAL = 30000;
  const SDK_CONFIG_KEY = '__geoIPControlConfig';
  
  // === HARDCODED API URL ===
  const API_BASE_URL = 'https://geoip-comand-center-production.up.railway.app';
  // ==============================================
  
  // ERROR CODE MAPPING
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
  let isTrafficAllowed = false;
  
  async function getIP() {
    return fetch('https://api.ipify.org?format=json')
      .then(r => r.json())
      .then(d => d.ip)
      .catch(() => {
        console.warn('SDK: Failed to get IP, using localhost');
        return '127.0.0.1';
      });
  }
  
  async function pollConfig() {
    try {
      const configUrl = `${API_BASE_URL}/api/config`;
      console.log('SDK: Fetching config from:', configUrl);
      
      const response = await fetch(configUrl, {
        headers: { 'X-SDK-Version': SDK_VERSION }
      });
      
      if (response.ok) {
        config = await response.json();
        localStorage.setItem(SDK_CONFIG_KEY, JSON.stringify(config));
        console.log('SDK: Config loaded successfully:', config);
      } else if (response.status === 403) {
        const errorData = await response.json();
        console.error('SDK: Domain blocked:', errorData);
        showBlockedPage('ERR-DOMAIN-BLOCKED');
        return;
      } else {
        console.error('SDK: Config fetch failed with status:', response.status);
      }
    } catch (e) {
      console.error('SDK: Config fetch error:', e);
      const cached = localStorage.getItem(SDK_CONFIG_KEY);
      if (cached) {
        config = JSON.parse(cached);
        console.log('SDK: Using cached config:', config);
      } else {
        console.warn('SDK: No cached config available');
      }
    }
  }
  
  async function checkGeoIP(ip) {
    try {
      const geoipUrl = `${API_BASE_URL}/api/geoip/${ip}`;
      console.log('SDK: Checking GeoIP at:', geoipUrl);
      
      const response = await fetch(geoipUrl);
      const data = await response.json();
      console.log('SDK: GeoIP result:', data);
      return data.country || 'Unknown';
    } catch (e) {
      console.error('SDK: GeoIP check error:', e);
      return 'Unknown';
    }
  }
  
  async function checkBotDetection(ip, userAgent) {
    try {
      const botDetectUrl = `${API_BASE_URL}/api/bot-detect`;
      console.log('SDK: Checking bot detection at:', botDetectUrl);
      
      const response = await fetch(botDetectUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, user_agent: userAgent })
      });
      const result = await response.json();
      console.log('SDK: Bot detection result:', result);
      return result;
    } catch (e) {
      console.error('SDK: Bot detection error:', e);
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
    if (!config) {
      console.warn('SDK: No config available for evaluation');
      return { blocked: false };
    }
    
    const ip = await getIP();
    const userAgent = navigator.userAgent;
    const country = await checkGeoIP(ip);
    
    console.log('SDK: Evaluating rules for IP:', ip, 'Country:', country);
    
    const currentDomain = window.location.hostname;
    if (!config.allowAllDomains && config.allowedDomains?.length && !config.allowedDomains.some(d => currentDomain.includes(d))) {
      console.log('SDK: Domain blocked:', currentDomain);
      return { blocked: true, code: 'ERR-DOMAIN-BLOCKED', reason: ERROR_CODES['ERR-DOMAIN-BLOCKED'] };
    }
    
    if (config.ipBlacklist?.includes(ip)) {
      console.log('SDK: IP blocked:', ip);
      return { blocked: true, code: 'ERR-IP-BLACKLIST', reason: ERROR_CODES['ERR-IP-BLACKLIST'] };
    }
    
    if (config.blockedCountries?.includes(country)) {
      console.log('SDK: Country blocked:', country);
      return { blocked: true, code: 'ERR-COUNTRY-BLOCK', reason: ERROR_CODES['ERR-COUNTRY-BLOCK'] };
    }
    
    if (config.allowedCountries?.length && !config.allowedCountries.includes(country)) {
      console.log('SDK: Country not allowed:', country);
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
        console.log('SDK: Bot detection triggered:', triggered);
        return { blocked: true, code: getErrorCode(botResult, country, ip), reason: ERROR_CODES[getErrorCode(botResult, country, ip)] };
      }
    }
    
    console.log('SDK: Access granted');
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
    
    console.log('SDK: Redirecting to safe mode in 3 seconds');
    setTimeout(() => {
      window.location.href = 'https://example.com';
    }, 3000);
  }
  
  async function runCheck() {
    if (!config) {
      console.warn('SDK: No config available');
      isTrafficAllowed = false;
      return;
    }
    
    const result = await evaluateRules();
    console.log('SDK: Evaluation result:', result);
    
    if (result.blocked) {
      showBlockedPage(result.code);
      isTrafficAllowed = false;
    } else {
      console.log('SDK: Traffic allowed, page can proceed');
      isTrafficAllowed = true;
    }
  }
  
  async function init() {
    console.log('SDK: Initializing...');
    await pollConfig();
    
    if (config) {
      console.log('SDK: Running initial security check...');
      await runCheck();
    }
    
    // Periodic config refresh
    pollInterval = setInterval(async () => {
      await pollConfig();
      if (config) {
        console.log('SDK: Running periodic security check...');
        await runCheck();
      }
    }, CONFIG_POLL_INTERVAL);
  }
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  
  window.addEventListener('beforeunload', () => {
    if (pollInterval) {
      console.log('SDK: Clearing poll interval');
      clearInterval(pollInterval);
    }
  });
  
  // Expose SDK to global scope
  window.GeoIPControlSDK = {
    version: SDK_VERSION,
    getConfig: () => {
      console.log('SDK: getConfig called:', config);
      return config;
    },
    isTrafficAllowed: () => {
      console.log('SDK: isTrafficAllowed called:', isTrafficAllowed);
      return isTrafficAllowed;
    },
    runSecurityCheck: () => {
      console.log('SDK: Manual security check triggered');
      return runCheck();
    }
  };
  
  console.log('SDK: Loaded version', SDK_VERSION);
})();
