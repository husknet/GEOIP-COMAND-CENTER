# 🔒 Geo-IP Control Station v3.1

**DOMAIN WHITELIST + ERROR CODE PROTOCOL + MULTI-THEME SYSTEM**

---

## 🆕 New Features in v3.1

### 1. Domain Whitelist Control
Only specified domains can load your SDK. Unauthorized domains receive `ERR-DOMAIN-BLOCKED` error.

**Configuration:**
- **Allow All Domains**: Toggle to disable whitelist (default: OFF)
- **Domain List**: One domain per line (e.g., `example.com`, `app.yoursite.com`)

### 2. "Allow All Countries" Button
Quickly enable global access without selecting countries individually. Automatically:
- Selects **all countries** in allowed list
- Clears **blocked countries** selection
- One-click deployment

### 3. Error Code Reference
| Code | Meaning | Admin Action |
|------|---------|--------------|
| `ERR-DOMAIN-BLOCKED` | Domain not in whitelist | Review domain list |
| `ERR-BOT-HIGH` | Bot score exceeded threshold | Check bot detection logs |
| `ERR-COUNTRY-BLOCK` | Country in blocked list | Review country lists |
| `ERR-IP-BLACKLIST` | IP is blacklisted | Verify IP blacklist |
| `ERR-ISP-SCRAPER` | Scraper ISP detected | Check ISP patterns |
| `ERR-ASN-DATACENTER` | Data center ASN | Review ASN flags |
| `ERR-TRAFFIC-SUSPICIOUS` | Traffic pattern flagged | Analyze traffic |
| `ERR-UA-BOT` | Bot User-Agent found | Check UA filters |
| `ERR-IP-ABUSER` | IP flagged for abuse | Review abuse DB |

---

## Quick Start

### Deploy to Railway
```bash
railway login
railway init
railway variables set ADMIN_PASSWORD="your-secure-password"
railway up