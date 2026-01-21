// content/hover.js
// VerusIT - Intelligent Relevance Engine
// Combined Date Detection + Tech Stack Analysis

// =============================================================================
// 1. CONFIGURATION & PATTERNS
// =============================================================================

const SELECTORS = {
  result: 'div.g',
  snippet: 'div[style*="-webkit-line-clamp"]',
  title: 'h3'
};

const AGE_THRESHOLDS = {
  FRESH: 180,      // 0-6 months = GREEN
  AGING: 730,      // 6 months - 2 years = YELLOW
  // > 2 years = RED
};

const TECH_PATTERNS = {
  LEGACY: [
    { term: "var ", label: "ES5 (Pre-2015)", type: "risk" },
    { term: "mysql_connect", label: "PHP 5 (Insecure)", type: "danger" },
    { term: "mysql_query", label: "PHP 5 (Insecure)", type: "danger" },
    { term: "Python 2", label: "EOL", type: "risk" },
    { term: "python2", label: "EOL", type: "risk" },
    { term: "React.createClass", label: "React Legacy", type: "risk" },
    { term: "componentWillMount", label: "React Deprecated", type: "danger" },
    { term: "componentWillReceiveProps", label: "React Deprecated", type: "danger" },
    { term: "componentWillUpdate", label: "React Deprecated", type: "danger" },
    { term: "AngularJS", label: "Angular 1.x", type: "risk" },
    { term: "angular.module", label: "Angular 1.x", type: "risk" },
    { term: "get_magic_quotes", label: "PHP Deprecated", type: "risk" },
    { term: "cv2.cv.", label: "OpenCV 2", type: "risk" },
    { term: "javax.servlet", label: "Java EE (Old)", type: "info" },
    { term: "jQuery", label: "jQuery", type: "info" },
    { term: "$.ajax", label: "jQuery", type: "info" },
    { term: "require(", label: "CommonJS", type: "info" },
    { term: "module.exports", label: "CommonJS", type: "info" },
    { term: "XMLHttpRequest", label: "Pre-Fetch API", type: "info" },
    { term: "document.write", label: "Legacy DOM", type: "risk" },
    { term: "innerHTML =", label: "XSS Risk", type: "risk" },
    { term: "eval(", label: "Security Risk", type: "danger" },
    { term: "with (", label: "Deprecated JS", type: "risk" },
    { term: "__proto__", label: "Deprecated", type: "risk" },
    { term: "arguments.callee", label: "Deprecated", type: "risk" },
    { term: "escape(", label: "Deprecated", type: "info" },
    { term: "unescape(", label: "Deprecated", type: "info" }
  ],

  MODERN: [
    { term: "useState", label: "React Hooks" },
    { term: "useEffect", label: "React Hooks" },
    { term: "useContext", label: "React Hooks" },
    { term: "useReducer", label: "React Hooks" },
    { term: "async/await", label: "Modern JS" },
    { term: "async ", label: "Modern JS" },
    { term: "await ", label: "Modern JS" },
    { term: "const ", label: "ES6+" },
    { term: "let ", label: "ES6+" },
    { term: "import ", label: "ES Modules" },
    { term: "export ", label: "ES Modules" },
    { term: "fetch(", label: "Fetch API" },
    { term: "Promise", label: "Modern JS" },
    { term: "arrow function", label: "ES6+" },
    { term: "=>", label: "ES6+" },
    { term: "TypeScript", label: "TypeScript" },
    { term: "Deno", label: "Modern Runtime" },
    { term: "Bun", label: "Modern Runtime" }
  ],

  AUTHORITY_DOMAINS: [
    "developer.mozilla.org",
    "react.dev",
    "reactjs.org",
    "vuejs.org",
    "angular.io",
    "svelte.dev",
    "nextjs.org",
    "pypi.org",
    "npmjs.com",
    "docs.python.org",
    "go.dev",
    "rust-lang.org",
    "learn.microsoft.com",
    "docs.microsoft.com",
    "docs.aws.amazon.com",
    "cloud.google.com",
    "developers.google.com",
    "developer.apple.com",
    "docs.oracle.com",
    "kotlinlang.org",
    "typescriptlang.org",
    "php.net"
  ],

  PLATFORMS: {
    github: { pattern: /github\.com\/[\w-]+\/[\w-]+/, label: "GitHub" },
    stackoverflow: { pattern: /stackoverflow\.com\/questions/, label: "Stack Overflow" },
    npm: { pattern: /npmjs\.com\/package/, label: "NPM" },
    pypi: { pattern: /pypi\.org\/project/, label: "PyPI" },
    medium: { pattern: /medium\.com/, label: "Medium" },
    devto: { pattern: /dev\.to/, label: "Dev.to" }
  }
};

// =============================================================================
// 2. MAIN PROCESSING
// =============================================================================

function processResult(element) {
  if (element.dataset.verusProcessed) return;
  element.dataset.verusProcessed = "true";

  let dateInfo = findDateInSnippet(element);
  let targetUrl = null;

  const linkElement = element.querySelector('a');
  if (linkElement) {
    targetUrl = linkElement.href;
  }

  if (!dateInfo && targetUrl) {
    dateInfo = extractDateFromURL(targetUrl);
  }

  const snippetText = getSnippetText(element);
  const techDebt = scanForTechDebt(snippetText);
  const modernTech = scanForModernTech(snippetText);
  const isAuthority = targetUrl ? getDomainAuthority(targetUrl) : false;
  const platform = targetUrl ? detectPlatform(targetUrl) : null;

  const container = createBadgeContainer();

  // Tech debt badge (highest priority warning)
  if (techDebt.length > 0) {
    const worst = techDebt[0];
    const badge = createBadge(worst.label, `verus-${worst.type}`);
    badge.title = `Tech Debt: ${techDebt.map(t => t.label).join(', ')}`;
    container.appendChild(badge);
  }

  // Authority badge
  if (isAuthority) {
    const badge = createBadge("\uD83D\uDEE1\uFE0F Official Docs", "verus-authority");
    container.appendChild(badge);
  }

  // Platform badge
  if (platform && !isAuthority) {
    const badge = createBadge(platform.label, "verus-platform");
    container.appendChild(badge);
  }

  // Modern tech badge
  if (modernTech.length > 0 && techDebt.length === 0) {
    const badge = createBadge("\u2713 Modern", "verus-modern");
    badge.title = `Modern: ${modernTech.map(t => t.label).join(', ')}`;
    container.appendChild(badge);
  }

  // Date badge
  if (dateInfo) {
    const ageDays = Math.floor((Date.now() - dateInfo.date.getTime()) / (1000 * 60 * 60 * 24));
    const ageClass = getAgeClass(ageDays);
    const ageText = formatAge(ageDays);
    const badge = createBadge(`\uD83D\uDCC5 ${ageText}`, ageClass);
    badge.title = dateInfo.date.toLocaleDateString();
    container.appendChild(badge);
  }
  // Deep Scan disabled in free version - no button for unknown dates

  // Insert container
  const titleElement = element.querySelector('h3');
  if (titleElement) {
    const parent = titleElement.parentElement;
    if (parent) {
      parent.style.position = 'relative';
      container.style.position = 'absolute';
      container.style.top = '-8px';
      container.style.right = '0';
      parent.appendChild(container);
    }
  }
}

// =============================================================================
// 3. DATE EXTRACTION
// =============================================================================

function findDateInSnippet(element) {
  const snippet = element.querySelector(SELECTORS.snippet);
  if (!snippet) return null;

  const text = snippet.textContent || "";

  // Pattern 1: "Mon D, YYYY" or "Mon DD, YYYY"
  const pattern1 = text.match(/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2}),?\s+(\d{4})\b/i);
  if (pattern1) {
    const date = new Date(`${pattern1[1]} ${pattern1[2]}, ${pattern1[3]}`);
    if (!isNaN(date.getTime())) return { date, source: 'snippet' };
  }

  // Pattern 2: "D Mon YYYY" or "DD Mon YYYY"
  const pattern2 = text.match(/\b(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})\b/i);
  if (pattern2) {
    const date = new Date(`${pattern2[2]} ${pattern2[1]}, ${pattern2[3]}`);
    if (!isNaN(date.getTime())) return { date, source: 'snippet' };
  }

  // Pattern 3: "YYYY-MM-DD"
  const pattern3 = text.match(/\b(\d{4})-(\d{2})-(\d{2})\b/);
  if (pattern3) {
    const date = new Date(`${pattern3[1]}-${pattern3[2]}-${pattern3[3]}`);
    if (!isNaN(date.getTime())) return { date, source: 'snippet' };
  }

  // Pattern 4: "MM/DD/YYYY" or "M/D/YYYY"
  const pattern4 = text.match(/\b(\d{1,2})\/(\d{1,2})\/(\d{4})\b/);
  if (pattern4) {
    const date = new Date(`${pattern4[1]}/${pattern4[2]}/${pattern4[3]}`);
    if (!isNaN(date.getTime())) return { date, source: 'snippet' };
  }

  // Pattern 5: Relative dates
  const relativeMatch = text.match(/(\d+)\s+(day|week|month|year)s?\s+ago/i);
  if (relativeMatch) {
    const num = parseInt(relativeMatch[1]);
    const unit = relativeMatch[2].toLowerCase();
    const date = new Date();
    if (unit === 'day') date.setDate(date.getDate() - num);
    else if (unit === 'week') date.setDate(date.getDate() - num * 7);
    else if (unit === 'month') date.setMonth(date.getMonth() - num);
    else if (unit === 'year') date.setFullYear(date.getFullYear() - num);
    return { date, source: 'relative' };
  }

  return null;
}

function extractDateFromURL(url) {
  // Pattern: /YYYY/MM/DD/ or /YYYY/MM/
  const urlDateMatch = url.match(/\/(\d{4})\/(\d{2})(?:\/(\d{2}))?/);
  if (urlDateMatch) {
    const year = parseInt(urlDateMatch[1]);
    const month = parseInt(urlDateMatch[2]) - 1;
    const day = urlDateMatch[3] ? parseInt(urlDateMatch[3]) : 1;
    if (year >= 2000 && year <= new Date().getFullYear() + 1) {
      const date = new Date(year, month, day);
      if (!isNaN(date.getTime())) return { date, source: 'url' };
    }
  }
  return null;
}

// =============================================================================
// 4. TECH ANALYSIS
// =============================================================================

function getSnippetText(element) {
  const snippet = element.querySelector(SELECTORS.snippet);
  const title = element.querySelector(SELECTORS.title);
  let text = '';
  if (snippet) text += snippet.textContent || '';
  if (title) text += ' ' + (title.textContent || '');
  return text;
}

function scanForTechDebt(text) {
  const found = [];
  for (const pattern of TECH_PATTERNS.LEGACY) {
    if (text.includes(pattern.term)) {
      found.push(pattern);
    }
  }
  // Sort by severity: danger > risk > info
  const order = { danger: 0, risk: 1, info: 2 };
  found.sort((a, b) => order[a.type] - order[b.type]);
  return found;
}

function scanForModernTech(text) {
  const found = [];
  for (const pattern of TECH_PATTERNS.MODERN) {
    if (text.includes(pattern.term)) {
      found.push(pattern);
    }
  }
  return found;
}

function getDomainAuthority(url) {
  try {
    const hostname = new URL(url).hostname.replace('www.', '');
    return TECH_PATTERNS.AUTHORITY_DOMAINS.some(d =>
      hostname === d || hostname.endsWith('.' + d)
    );
  } catch (e) {
    return false;
  }
}

function detectPlatform(url) {
  if (!url) return null;
  for (const [key, config] of Object.entries(TECH_PATTERNS.PLATFORMS)) {
    if (config.pattern.test(url)) {
      return { type: key, label: config.label };
    }
  }
  return null;
}

// =============================================================================
// 5. UI COMPONENTS
// =============================================================================

function createBadgeContainer() {
  const container = document.createElement('div');
  container.className = 'verus-container';
  return container;
}

function createBadge(text, className) {
  const badge = document.createElement('span');
  badge.className = `verus-badge ${className}`;
  badge.textContent = text;
  return badge;
}

function getAgeClass(days) {
  if (days <= AGE_THRESHOLDS.FRESH) return 'verus-fresh';
  if (days <= AGE_THRESHOLDS.AGING) return 'verus-aging';
  return 'verus-stale';
}

function formatAge(days) {
  if (days < 7) return `${days}d`;
  if (days < 30) return `${Math.floor(days / 7)}w`;
  if (days < 365) return `${Math.floor(days / 30)}mo`;
  const years = Math.floor(days / 365);
  const months = Math.floor((days % 365) / 30);
  if (months > 0) return `${years}y ${months}mo`;
  return `${years}y`;
}

function createDeepScanButton(url, container) {
  // Deep Scan disabled in free version (requires <all_urls> permission)
  // Returns null - no button shown for results without visible dates
  return null;
}

// =============================================================================
// 6. OBSERVERS (Infinite Scroll Support)
// =============================================================================

const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeType === 1) {
        if (node.matches && node.matches(SELECTORS.result)) {
          processResult(node);
        } else if (node.querySelectorAll) {
          const results = node.querySelectorAll(SELECTORS.result);
          results.forEach(processResult);
        }
      }
    });
  });
});

observer.observe(document.body, { childList: true, subtree: true });

// Initial run
const initialResults = document.querySelectorAll(SELECTORS.result);
initialResults.forEach(processResult);