# VerusIT: Fresh Ink, Not Old Links

**VerusIT** is a Chrome Extension that helps you identify outdated content in Google search results before you click. It injects "Freshness Badges" directly into search results, showing you how old content is at a glance.

## The Problem

Google ranks by popularity, not recency. A tutorial from 2019 might be #1 for your search, but uses deprecated patterns you won't discover until you're 30 minutes in.

VerusIT fixes that.

## Features

### Freshness Detection (Traffic Light System)
- **Fresh** - Content less than 6 months old
- **Aging** - 6 months to 2 years old
- **Stale** - Over 2 years old

### Tech Debt Detection
- **Danger** - Critical: mysql_connect, eval(), deprecated React lifecycle
- **Risk** - Outdated: var, componentWillMount, AngularJS
- **Info** - Dated but functional: jQuery, CommonJS

### Source Intelligence
- **Official Docs** - MDN, React.dev, Python docs, etc.
- **Platform Detection** - GitHub, Stack Overflow, NPM, PyPI

## Privacy

- All processing is local
- No data transmitted to external servers
- No analytics or tracking

## Installation

1. Download or clone this repository
2. Open Chrome - chrome://extensions/
3. Enable "Developer mode" (top right)
4. Click "Load unpacked"
5. Select the VerusIT folder

## Test Searches

| Search | What You'll See |
|--------|-----------------|
| react tutorial | Old results flagged for deprecated lifecycle methods |
| python mysql connect | Flags for insecure PHP 5 patterns |
| MDN array methods | Official Docs badge |
| useState react | Modern badge on Hook-based results |

## File Structure
```
VerusIT/
├── manifest.json          # MV3 config
├── content/
│   ├── hover.js           # Badge injection & date detection
│   └── hover.css          # Badge styling
├── icons/
│   ├── 16.png
│   ├── 32.png
│   ├── 48.png
│   └── 128.png
├── README.md
└── PRIVACY.md
```

## Permissions

- https://www.google.com/* - Required to inject badges into Google search results

## Changelog

### v1.0.0
- Freshness badges (green/yellow/red)
- Tech debt detection (40+ patterns)
- Official docs highlighting
- Platform detection
- IDE-inspired dark theme

---

**4Godsake Enterprises**

*"Fresh ink, not old links."*