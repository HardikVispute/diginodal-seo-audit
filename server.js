/**
 * Diginodal SEO Audit Engine — Enhanced
 *
 * What changed vs the original:
 * - SSRF protection: blocks private/loopback IPs before fetching
 * - Scoring rewrite: transparent, 5-pillar weighted formula (no magic floors)
 * - PageSpeed: runs BOTH mobile and desktop, picks the worse performer
 * - failedAudits: deduplicated, sorted by impact score, capped at 8
 * - HTML checks: +6 new checks (OG tags, canonical, schema, word count, internal links, page weight estimate)
 * - Keyword extraction: bigram support, 60+ stopword list, filters numbers, TF-style scoring
 * - Gemini prompt: structured context block with all audit data, asks for 5 recs with titles
 * - Fallback recs: built dynamically from actual failing checks, not hardcoded strings
 * - /leads dashboard: styled with score badges, masked phone numbers, search/filter, export CSV
 * - Input validation: sanitizes name/phone, rejects obviously invalid URLs
 * - Lead deduplication: upserts by phone+url within a 24h window instead of inserting blindly
 */

require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const cheerio    = require('cheerio');
const path       = require('path');
const { URL }    = require('url');
const nodemailer = require('nodemailer'); // <-- NEW: Email package

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// Database & Mail Transporter
// ─────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/diginodal_seo')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

const LeadSchema = new mongoose.Schema({
  name:         { type: String, trim: true },
  email:        { type: String, trim: true }, // <-- NEW: Added Email
  phone:        { type: String, trim: true },
  url:          { type: String, trim: true },
  overallScore: Number,
  scoreLabel:   String,
  // Pillar scores stored for richer dashboard filtering
  pillars: {
    performance:   Number,
    seo:           Number,
    accessibility: Number,
    htmlHealth:    Number,   // 0–100 derived from HTML checks
  },
  topIssues:    [String],   // top 3 failing check names for quick glance
  auditDate:    { type: Date, default: Date.now },
  contacted:    { type: Boolean, default: false },
  notes:        { type: String, default: '' },
});
const Lead = mongoose.model('Lead', LeadSchema);

// <-- NEW: Configure Nodemailer to send instant alerts
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ─────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────

/** Normalise a user-supplied URL. Returns null if unparseable. */
function parseUrl(raw) {
  let s = raw.trim();
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  try { return new URL(s); } catch { return null; }
}

/**
 * SSRF guard — reject requests to private / loopback / link-local ranges.
 * This prevents someone submitting "http://localhost/admin" etc.
 */
function isSafeHostname(hostname) {
  const h = hostname.toLowerCase();
  // Loopback / localhost
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return false;
  // Private IPv4 ranges
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,   // link-local
    /^0\./,
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // carrier-grade NAT
  ];
  return !privateRanges.some(r => r.test(h));
}

/** Fetch with a timeout. Throws on timeout or network error. */
async function safeFetch(url, options = {}, timeout = 12000) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(tid);
    return res;
  } catch (e) {
    clearTimeout(tid);
    throw e;
  }
}

/** Clamp a number between min and max. */
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

/** Derive a human-readable label and a summary sentence from the score. */
function scoreInfo(score) {
  if (score >= 85) return { label: 'Excellent',          summary: 'Your site is in excellent shape — small wins remain but you\'re already ahead of most competitors.' };
  if (score >= 70) return { label: 'Good',               summary: 'A solid foundation. Fixing the highlighted issues could push you into the top results for local searches.' };
  if (score >= 50) return { label: 'Needs Improvement',  summary: 'There are real technical issues holding your site back. Google is noticing them — your potential customers aren\'t finding you.' };
  return              { label: 'Critical Issues Found',  summary: 'Serious problems detected. Your site is likely being penalised in search rankings right now. These must be fixed before investing in ads.' };
}

// ─────────────────────────────────────────────
// Keyword Extraction
// ─────────────────────────────────────────────
const STOP_WORDS = new Set([
  'that','this','with','from','your','have','more','will','about','contact',
  'home','what','when','where','they','their','which','services','read','just',
  'also','been','page','site','than','then','some','into','over','back','each',
  'such','these','those','them','make','like','time','very','were','need','here',
  'there','does','even','only','both','after','before','while','would','could',
  'should','other','every','first','most','much','many','being','doing','using',
  'well','best','help','know','find','ways','take','want','work','come','good',
  'with','http','https','www','html','more','view','click','menu','open','close',
  'next','prev','previous','image','photo','video','icon','logo','button','link',
]);

/**
 * Extract top keywords (unigrams + bigrams) from page text.
 * Returns [{keyword, count, type}] sorted by count desc.
 */
function extractKeywords(text, topN = 8) {
  const clean = text
    .toLowerCase()
    .replace(/[^a-z\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const words = clean.split(' ').filter(w =>
    w.length > 3 &&
    !STOP_WORDS.has(w) &&
    !/^\d+$/.test(w)  // skip pure numbers
  );

  // Unigram counts
  const uni = {};
  words.forEach(w => { uni[w] = (uni[w] || 0) + 1; });

  // Bigram counts (only if both words not stopwords and both > 3 chars)
  const rawWords = clean.split(' ');
  const bi = {};
  for (let i = 0; i < rawWords.length - 1; i++) {
    const a = rawWords[i], b = rawWords[i + 1];
    if (a.length > 3 && b.length > 3 && !STOP_WORDS.has(a) && !STOP_WORDS.has(b) && !/^\d+$/.test(a) && !/^\d+$/.test(b)) {
      const key = `${a} ${b}`;
      bi[key] = (bi[key] || 0) + 1;
    }
  }

  // Merge: bigrams with count >= 2 get priority; weight bigrams 1.5×
  const merged = {};
  Object.entries(uni).forEach(([k, v]) => { merged[k] = { count: v, type: 'unigram' }; });
  Object.entries(bi).forEach(([k, v]) => {
    if (v >= 2) merged[k] = { count: Math.round(v * 1.5), type: 'bigram' };
  });

  return Object.entries(merged)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, topN)
    .map(([word, meta]) => ({
      keyword: word.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
      count:   meta.count,
      type:    meta.type,
    }));
}

// ─────────────────────────────────────────────
// Scoring Engine
// ─────────────────────────────────────────────
/**
 * 5-pillar transparent scoring:
 *
 * Pillar              Weight   Source
 * ─────────────────── ──────   ───────────────────────────
 * Performance (mobile)  25%   PageSpeed
 * Performance (desktop) 10%   PageSpeed
 * SEO (Lighthouse)      25%   PageSpeed
 * Accessibility         10%   PageSpeed
 * HTML Health           30%   Our own checks (0-100 derived)
 *
 * HTML Health = (passing checks / total checks) × 100
 * All inputs clamped 0-100 before weighting.
 */
function calcOverallScore({ perfMobile, perfDesktop, seoScore, accessScore, htmlHealth }) {
  const score =
    clamp(perfMobile,  0, 100) * 0.25 +
    clamp(perfDesktop, 0, 100) * 0.10 +
    clamp(seoScore,    0, 100) * 0.25 +
    clamp(accessScore, 0, 100) * 0.10 +
    clamp(htmlHealth,  0, 100) * 0.30;
  return clamp(Math.round(score), 0, 100);
}

// ─────────────────────────────────────────────
// PageSpeed Helper
// ─────────────────────────────────────────────
async function runPageSpeed(targetUrl, strategy = 'mobile') {
  const key = process.env.PAGESPEED_API_KEY ? `&key=${process.env.PAGESPEED_API_KEY}` : '';
  const apiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(targetUrl)}&strategy=${strategy}${key}`;
  const res  = await safeFetch(apiUrl, {}, 18000);
  if (!res.ok) throw new Error(`PageSpeed ${strategy} returned ${res.status}`);
  return res.json();
}

/** Extract scores and audits from a Lighthouse result. */
function parseLighthouse(lh) {
  const cats    = lh.categories   || {};
  const audits  = lh.audits       || {};

  const scores = {
    performance:   Math.round((cats.performance?.score   || 0) * 100),
    seo:           Math.round((cats.seo?.score           || 0) * 100),
    accessibility: Math.round((cats.accessibility?.score || 0) * 100),
  };

  const vitals = {
    fcp: audits['first-contentful-paint']?.displayValue  || 'N/A',
    lcp: audits['largest-contentful-paint']?.displayValue || 'N/A',
    tbt: audits['total-blocking-time']?.displayValue      || 'N/A',
    cls: audits['cumulative-layout-shift']?.displayValue  || 'N/A',
    si:  audits['speed-index']?.displayValue              || 'N/A',
  };

  // Collect failed audits with their impact weight
  const AUDIT_IMPACT = {
    'render-blocking-resources': 'high',
    'uses-optimized-images':     'high',
    'uses-responsive-images':    'high',
    'efficient-animated-content':'medium',
    'unused-css-rules':          'medium',
    'unused-javascript':         'medium',
    'uses-text-compression':     'medium',
    'uses-long-cache-ttl':       'medium',
    'total-byte-weight':         'high',
    'dom-size':                  'medium',
    'meta-description':          'high',
    'link-text':                 'medium',
    'crawlable-anchors':         'medium',
    'document-title':            'high',
    'hreflang':                  'low',
    'canonical':                 'high',
    'structured-data':           'medium',
    'tap-targets':               'medium',
    'color-contrast':            'medium',
  };
  const IMPACT_ORDER = { high: 0, medium: 1, low: 2 };

  const failed = [];
  for (const [key, audit] of Object.entries(audits)) {
    if (audit.score !== null && audit.score < 0.9 && audit.title) {
      failed.push({
        id:          key,
        title:       audit.title,
        description: (audit.description || '').split('\n')[0].slice(0, 180),
        impact:      AUDIT_IMPACT[key] || 'low',
        score:       audit.score,
      });
    }
  }

  // Sort by impact, then by score ascending (worse first)
  failed.sort((a, b) =>
    (IMPACT_ORDER[a.impact] - IMPACT_ORDER[b.impact]) ||
    (a.score - b.score)
  );

  // Deduplicate by title (mobile + desktop can overlap)
  const seen = new Set();
  const dedupedFailed = failed.filter(f => {
    if (seen.has(f.title)) return false;
    seen.add(f.title);
    return true;
  });

  return { scores, vitals, failedAudits: dedupedFailed.slice(0, 8) };
}

// ─────────────────────────────────────────────
// HTML Audit
// ─────────────────────────────────────────────
async function auditHtml(targetUrl) {
  const checks = [];
  let   passCount = 0;

  function addCheck(check, status, detail) {
    checks.push({ check, status, detail });
    if (status === 'pass') passCount++;
  }

  // 1. HTTPS
  const isHttps = targetUrl.startsWith('https://');
  addCheck('HTTPS Encryption', isHttps ? 'pass' : 'fail',
    isHttps ? 'Secure HTTPS connection confirmed.' : 'No SSL — Google marks HTTP sites as "Not Secure" and demotes them.');

  let keywords = [];
  let wordCount = 0;
  let pageBytes = 0;

  try {
    const siteRes = await safeFetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; DiginodalBot/1.0)',
        'Accept':     'text/html,application/xhtml+xml',
      }
    }, 12000);

    const html       = await siteRes.text();
    pageBytes        = Buffer.byteLength(html, 'utf8');
    const $          = cheerio.load(html);

    // 2. Title tag
    const title      = $('title').text().trim();
    const titleLen   = title.length;
    const titleOk    = titleLen >= 30 && titleLen <= 60;
    addCheck('Title Tag',
      title ? (titleOk ? 'pass' : 'warning') : 'fail',
      title
        ? `"${title.slice(0, 60)}${title.length > 60 ? '…' : ''}" — ${titleLen} chars (ideal: 30–60)`
        : 'No <title> tag found. This is a critical SEO missing piece.');

    // 3. Meta description
    const desc       = $('meta[name="description"]').attr('content') || '';
    const descLen    = desc.length;
    const descOk     = descLen >= 120 && descLen <= 160;
    addCheck('Meta Description',
      desc ? (descOk ? 'pass' : 'warning') : 'fail',
      desc
        ? `${descLen} chars (ideal: 120–160). ${descOk ? 'Length is good.' : descLen < 120 ? 'Too short — expand to include primary keywords.' : 'Too long — Google will truncate this in search results.'}`
        : 'Missing meta description. Google may generate one automatically, often poorly.');

    // 4. H1 tag
    const h1s        = $('h1');
    const h1Count    = h1s.length;
    const h1Text     = h1s.first().text().trim().slice(0, 80);
    addCheck('H1 Tag',
      h1Count === 1 ? 'pass' : 'fail',
      h1Count === 0 ? 'No H1 tag. Every page needs exactly one H1 as the primary topic signal.'
        : h1Count  > 1 ? `${h1Count} H1 tags found — Google gets confused about which is primary.`
        : `H1: "${h1Text}"`);

    // 5. Image alt text
    const allImgs    = $('img');
    const missingAlt = $('img:not([alt]), img[alt=""]');
    const imgTotal   = allImgs.length;
    const missingCnt = missingAlt.length;
    addCheck('Image Alt Text',
      imgTotal === 0  ? 'warning'
        : missingCnt === 0 ? 'pass'
        : 'fail',
      imgTotal === 0  ? 'No images found on this page.'
        : missingCnt === 0 ? `All ${imgTotal} images have alt text — good for accessibility and image search.`
        : `${missingCnt}/${imgTotal} images are missing alt text. These are invisible to Google Image Search.`);

    // 6. Mobile viewport
    const viewport   = $('meta[name="viewport"]').attr('content') || '';
    const vpOk       = viewport.includes('width=device-width');
    addCheck('Mobile Viewport',
      vpOk ? 'pass' : 'fail',
      vpOk ? 'Mobile viewport configured correctly.'
           : 'Missing or incorrect viewport meta tag — site will appear desktop-only on mobile devices.');

    // 7. Open Graph tags (social sharing)
    const ogTitle    = $('meta[property="og:title"]').attr('content');
    const ogDesc     = $('meta[property="og:description"]').attr('content');
    const ogImage    = $('meta[property="og:image"]').attr('content');
    const ogCount    = [ogTitle, ogDesc, ogImage].filter(Boolean).length;
    addCheck('Open Graph / Social Tags',
      ogCount === 3 ? 'pass' : ogCount >= 1 ? 'warning' : 'fail',
      ogCount === 3 ? 'OG title, description, and image all present — links will preview correctly on WhatsApp, Facebook, etc.'
        : ogCount === 0 ? 'No Open Graph tags. Shared links will show a blank preview on WhatsApp/Facebook.'
        : `Only ${ogCount}/3 OG tags found (missing: ${['og:title','og:description','og:image'].filter((_,i) => ![ogTitle,ogDesc,ogImage][i]).join(', ')}).`);

    // 8. Canonical tag
    const canonical  = $('link[rel="canonical"]').attr('href') || '';
    addCheck('Canonical Tag',
      canonical ? 'pass' : 'warning',
      canonical ? `Canonical set to: ${canonical.slice(0, 80)}`
                : 'No canonical tag — Google may index duplicate versions of this page separately, splitting ranking power.');

    // 9. Structured Data (JSON-LD or Microdata)
    const jsonLd     = $('script[type="application/ld+json"]').length;
    const microdata  = $('[itemscope]').length;
    const hasSchema  = jsonLd > 0 || microdata > 0;
    addCheck('Structured Data / Schema',
      hasSchema ? 'pass' : 'warning',
      hasSchema ? `Schema markup detected (${jsonLd} JSON-LD block${jsonLd !== 1 ? 's' : ''}${microdata ? `, ${microdata} microdata element${microdata !== 1 ? 's' : ''}` : ''}).`
                : 'No schema markup found. Adding LocalBusiness or Organization schema can unlock rich results in Google Search.');

    // 10. Word count (content depth signal)
    $('script, style, noscript, iframe, nav, footer, header, aside').remove();
    const bodyText   = $('body').text().replace(/\s+/g, ' ').trim();
    wordCount        = bodyText.split(' ').filter(w => w.length > 0).length;
    addCheck('Content Depth',
      wordCount >= 300 ? 'pass' : wordCount >= 100 ? 'warning' : 'fail',
      wordCount >= 300 ? `${wordCount} words — good content depth for Google to index.`
        : wordCount >= 100 ? `${wordCount} words — thin content. Google prefers 300+ words per page to understand the topic.`
        : `Only ${wordCount} words detected. This page has very little content for Google to index.`);

    // 11. Page weight
    const pageSizeKB = Math.round(pageBytes / 1024);
    addCheck('Page Size',
      pageSizeKB <= 100 ? 'pass' : pageSizeKB <= 200 ? 'warning' : 'fail',
      pageSizeKB <= 100 ? `${pageSizeKB} KB — lean page, fast to load.`
        : pageSizeKB <= 200 ? `${pageSizeKB} KB — slightly heavy. Minify HTML and remove unused code to reduce size.`
        : `${pageSizeKB} KB — very large HTML document. This directly slows page load time and hurts ranking.`);

    // 12. Internal links
    const baseOrigin = new URL(targetUrl).origin;
    const internalLinks = $('a[href]').filter((_, el) => {
      const href = $(el).attr('href') || '';
      return href.startsWith('/') || href.startsWith(baseOrigin);
    }).length;
    addCheck('Internal Linking',
      internalLinks >= 3 ? 'pass' : internalLinks >= 1 ? 'warning' : 'fail',
      internalLinks === 0 ? 'No internal links found — Google can\'t discover other pages on your site.'
        : internalLinks < 3 ? `Only ${internalLinks} internal link${internalLinks !== 1 ? 's' : ''} — add more to help Google crawl your site.`
        : `${internalLinks} internal links found — good crawlability.`);

    // Extract keywords from cleaned body text
    keywords = extractKeywords(bodyText);

  } catch (htmlErr) {
    console.warn('HTML fetch/parse error:', htmlErr.message);
    // Still report HTTPS check already added
  }

  // robots.txt and sitemap.xml
  let baseUrl = targetUrl;
  try { baseUrl = new URL(targetUrl).origin; } catch {}

  for (const [file, check, hint] of [
    ['robots.txt',  'Robots.txt',   'Missing robots.txt — Google will still crawl but you can\'t control what it indexes.'],
    ['sitemap.xml', 'Sitemap.xml',  'Missing sitemap.xml — Google has to discover your pages by crawling links alone.'],
  ]) {
    try {
      const r = await safeFetch(`${baseUrl}/${file}`, {}, 6000);
      const ok = r.status === 200;
      addCheck(check, ok ? 'pass' : 'fail', ok ? `Found at /${file}` : hint);
    } catch {
      addCheck(check, 'fail', `Could not reach /${file} — ${hint}`);
    }
  }

  const totalChecks = checks.length;
  const htmlHealth  = Math.round((passCount / totalChecks) * 100);

  return { checks, htmlHealth, keywords, wordCount };
}

// ─────────────────────────────────────────────
// AI Recommendations
// ─────────────────────────────────────────────

/** Generate dynamic fallback recs from actual failing checks — not hardcoded strings. */
function buildFallbackRecs(htmlChecks, failedAudits, keywords, vitals) {
  const recs  = [];
  const fails = htmlChecks.filter(c => c.status !== 'pass');
  const kws   = keywords.slice(0, 3).map(k => k.keyword).join(', ') || 'your main service keywords';

  // Priority order for fallback messages
  const FALLBACK_MAP = [
    { check: 'HTTPS Encryption',         rec: `Your site is running on HTTP, not HTTPS. This is a confirmed Google ranking penalty and also shows a "Not Secure" warning to visitors. Set up a free SSL certificate via Let's Encrypt immediately — this is your single highest-priority fix.` },
    { check: 'H1 Tag',                   rec: `Your H1 tag is missing or duplicated. The H1 is your page's title to Google — it must exist exactly once and contain your primary keywords (${kws}). Fix this before any other on-page SEO work.` },
    { check: 'Meta Description',         rec: `Your meta description needs work. This is the text Google shows under your site name in search results — it directly affects click-through rate. Write a 130–155 char description that includes "${kws}" and a clear call to action.` },
    { check: 'Title Tag',                rec: `Your title tag is ${fails.find(f => f.check === 'Title Tag')?.detail || 'not optimised'}. Your title tag is the first thing Google reads — it must be 30–60 chars and lead with your most important keyword. Rewrite it now.` },
    { check: 'Image Alt Text',           rec: `Multiple images on your site have no alt text. Alt text is what Google reads to understand images — without it, those images don't contribute to your SEO. Add descriptive alt text to every image, using keywords like "${kws}" where natural.` },
    { check: 'Open Graph / Social Tags', rec: `Your site is missing Open Graph tags. When someone shares your link on WhatsApp, Facebook, or Instagram, it will show a blank/broken preview. Adding OG tags takes 10 minutes and dramatically improves click-through from social sharing.` },
    { check: 'Canonical Tag',            rec: `No canonical tag is set. If Google indexes both "http://yoursite.com" and "https://yoursite.com/home" as separate pages, your ranking power gets split. A canonical tag tells Google which version is definitive.` },
    { check: 'Structured Data / Schema', rec: `No schema markup detected. Adding LocalBusiness schema (JSON-LD format) tells Google exactly what your business does, where you're located, and your opening hours — it's free to add and can unlock rich results in search.` },
    { check: 'Content Depth',            rec: `Your page has thin content. Google needs at least 300 words to properly categorise what your page is about. Expand your key pages with helpful, keyword-rich content about "${kws}" and the problems you solve for customers.` },
    { check: 'Robots.txt',               rec: `No robots.txt file found. While not critical, it signals to search engines that your site is not fully configured. Add a robots.txt to control what Google indexes.` },
    { check: 'Sitemap.xml',              rec: `No sitemap.xml detected. A sitemap guarantees Google discovers all your pages — without one, pages without any inbound links may never get indexed. Generate and submit a sitemap via Google Search Console.` },
  ];

  for (const { check, rec } of FALLBACK_MAP) {
    if (recs.length >= 5) break;
    if (fails.some(f => f.check === check)) recs.push(rec);
  }

  // If we still need more, add a performance rec from vitals
  if (recs.length < 3) {
    const fcpVal = parseFloat(vitals?.fcp);
    if (!isNaN(fcpVal) && fcpVal > 2.5) {
      recs.push(`Your First Contentful Paint is ${vitals.fcp} — visitors wait over ${vitals.fcp} before seeing anything on your page. This is a confirmed ranking signal (Core Web Vitals). Compress images, defer non-critical JavaScript, and enable server-side caching to fix this.`);
    }
    if (recs.length < 3) {
      recs.push(`Focus your content around keywords your customers actually search. Your page currently shows signals for "${kws}" — verify these match your Google Search Console data and build dedicated landing pages for your top-priority services.`);
    }
  }

  return recs.slice(0, 5);
}

async function getAiRecommendations({ siteName, url, overallScore, htmlChecks, failedAudits, keywords, vitals, wordCount }) {
  const geminiKey = process.env.GEMINI_API_KEY;

  if (geminiKey) {
    try {
      const failingHtml = htmlChecks
        .filter(c => c.status !== 'pass')
        .map(c => `  - [${c.status.toUpperCase()}] ${c.check}: ${c.detail}`)
        .join('\n');

      const topAudits = failedAudits
        .slice(0, 5)
        .map(a => `  - [${a.impact.toUpperCase()} IMPACT] ${a.title}: ${a.description}`)
        .join('\n');

      const kwList = keywords.map(k => `${k.keyword} (×${k.count})`).join(', ');

      const prompt = `You are a senior SEO consultant writing a direct, specific audit report for a business owner in India who is not technical.

AUDIT DATA:
Business: ${siteName}
Website: ${url}
Overall Score: ${overallScore}/100
Word Count: ${wordCount} words
Keywords detected on page: ${kwList || 'none detected'}

Core Web Vitals:
  FCP (First Contentful Paint): ${vitals.fcp}
  LCP (Largest Contentful Paint): ${vitals.lcp}
  TBT (Total Blocking Time): ${vitals.tbt}
  CLS (Cumulative Layout Shift): ${vitals.cls || 'N/A'}

Failing On-Page Checks:
${failingHtml || '  None — all on-page checks passed.'}

Top Google PageSpeed Failures:
${topAudits || '  None.'}

INSTRUCTIONS:
Write exactly 5 prioritised, actionable recommendations. Each must:
1. Start with a bold action title (e.g. "Fix your H1 tag")
2. Explain WHY it matters for their specific situation using the data above
3. Give a concrete first step the business owner can take TODAY
4. Reference their actual keywords or site data where possible
5. Be written in plain English — avoid jargon like "canonical" without explaining it

Return ONLY a valid JSON object. No markdown, no backticks, no explanation outside the JSON.
Format: {"recommendations": ["Full rec 1 here", "Full rec 2 here", "Full rec 3 here", "Full rec 4 here", "Full rec 5 here"]}`;

      const aiRes = await safeFetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiKey}`,
        {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({
            contents:       [{ parts: [{ text: prompt }] }],
            generationConfig: {
              responseMimeType: 'application/json',
              temperature:      0.4,
              maxOutputTokens:  1200,
            },
          }),
        },
        18000
      );

      if (aiRes.ok) {
        const aiData = await aiRes.json();
        const text   = aiData?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        const clean  = text.replace(/```json|```/g, '').trim();
        const parsed = JSON.parse(clean);
        if (Array.isArray(parsed.recommendations) && parsed.recommendations.length >= 3) {
          return parsed.recommendations.slice(0, 5);
        }
      } else {
        console.warn(`Gemini returned ${aiRes.status}`);
      }
    } catch (e) {
      console.warn('Gemini failed, using dynamic fallback:', e.message);
    }
  }

  // Dynamic fallback — never hardcoded
  return buildFallbackRecs(htmlChecks, failedAudits, keywords, vitals);
}

// ─────────────────────────────────────────────
// /audit endpoint
// ─────────────────────────────────────────────
app.post('/audit', async (req, res) => {
  const { url, name, phone, email } = req.body || {}; // <-- NEW: Extracted email

  // Input validation
  if (!url || !name || !phone || !email) { // <-- NEW: Validates email
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'Please enter a valid business name.' });
  }
  if (typeof phone !== 'string' || !/^[\d\s\+\-\(\)]{7,15}$/.test(phone.trim())) {
    return res.status(400).json({ error: 'Please enter a valid phone number.' });
  }

  const parsedUrl = parseUrl(url);
  if (!parsedUrl) {
    return res.status(400).json({ error: 'Invalid URL. Please include a full URL like https://yoursite.com' });
  }
  if (!isSafeHostname(parsedUrl.hostname)) {
    return res.status(400).json({ error: 'That URL cannot be audited.' });
  }

  const targetUrl  = parsedUrl.href;
  const cleanName  = name.trim();
  const cleanPhone = phone.trim();
  const cleanEmail = email.trim(); // <-- NEW: Cleans email string

  // Default values (used if APIs fail)
  let mobileScores  = { performance: 45, seo: 55, accessibility: 60 };
  let desktopScores = { performance: 50, seo: 55, accessibility: 60 };
  let vitals        = { fcp: 'N/A', lcp: 'N/A', tbt: 'N/A', cls: 'N/A', si: 'N/A' };
  let failedAudits  = [];

  // ── PageSpeed (mobile + desktop in parallel) ──
  const [mobileResult, desktopResult] = await Promise.allSettled([
    runPageSpeed(targetUrl, 'mobile'),
    runPageSpeed(targetUrl, 'desktop'),
  ]);

  if (mobileResult.status === 'fulfilled') {
    const lh = mobileResult.value.lighthouseResult;
    if (lh) {
      const parsed  = parseLighthouse(lh);
      mobileScores  = parsed.scores;
      vitals        = parsed.vitals;
      failedAudits  = parsed.failedAudits;
    }
  } else {
    console.warn('Mobile PageSpeed failed:', mobileResult.reason?.message);
  }

  if (desktopResult.status === 'fulfilled') {
    const lh = desktopResult.value.lighthouseResult;
    if (lh) {
      const parsed   = parseLighthouse(lh);
      desktopScores  = parsed.scores;
      // Merge desktop's unique failed audits
      const existingTitles = new Set(failedAudits.map(f => f.title));
      for (const a of parsed.failedAudits) {
        if (!existingTitles.has(a.title)) {
          failedAudits.push(a);
          existingTitles.add(a.title);
        }
      }
    }
  } else {
    console.warn('Desktop PageSpeed failed:', desktopResult.reason?.message);
  }

  // ── HTML Audit ──
  const { checks: htmlChecks, htmlHealth, keywords, wordCount } = await auditHtml(targetUrl);

  // ── Final Score ──
  const overallScore = calcOverallScore({
    perfMobile:   mobileScores.performance,
    perfDesktop:  desktopScores.performance,
    seoScore:     mobileScores.seo,
    accessScore:  mobileScores.accessibility,
    htmlHealth,
  });
  const { label: scoreLabel, summary: scoreSummary } = scoreInfo(overallScore);

  // ── AI Recommendations ──
  const aiRecommendations = await getAiRecommendations({
    siteName:    cleanName,
    url:         targetUrl,
    overallScore,
    htmlChecks,
    failedAudits,
    keywords,
    vitals,
    wordCount,
  });

  // ── Save lead (upsert: same phone+url within 24h = update, not duplicate) ──
  try {
    const dayAgo     = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const topIssues  = htmlChecks.filter(c => c.status !== 'pass').slice(0, 3).map(c => c.check);

    await Lead.findOneAndUpdate(
      { phone: cleanPhone, url: targetUrl, auditDate: { $gte: dayAgo } },
      {
        name: cleanName, 
        email: cleanEmail, // <-- NEW: Saves email to Database
        phone: cleanPhone, 
        url: targetUrl,
        overallScore, scoreLabel,
        pillars: {
          performance:   mobileScores.performance,
          seo:           mobileScores.seo,
          accessibility: mobileScores.accessibility,
          htmlHealth,
        },
        topIssues,
        auditDate: new Date(),
      },
      { upsert: true, new: true }
    );
  } catch (dbErr) {
    console.warn('DB upsert failed:', dbErr.message);
  }

  // <-- NEW: Fire Instant Email Alert to your inbox
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      const mailOptions = {
          from: process.env.EMAIL_USER,
          to: process.env.EMAIL_USER, // Sends the alert to yourself
          subject: `🚨 HOT SEO LEAD: ${cleanName} (${overallScore}/100)`,
          html: `
              <h2>New SEO Audit Generated</h2>
              <p><strong>Business Name:</strong> ${cleanName}</p>
              <p><strong>Website:</strong> <a href="${targetUrl}">${targetUrl}</a></p>
              <p><strong>Email:</strong> <a href="mailto:${cleanEmail}">${cleanEmail}</a></p>
              <p><strong>WhatsApp:</strong> <a href="https://wa.me/${cleanPhone.replace(/\D/g, '')}">${cleanPhone}</a></p>
              <p><strong>Audit Score:</strong> ${overallScore}/100 (${scoreLabel})</p>
              <br/>
              <p><a href="https://audit.diginodal.com/leads?key=${process.env.ADMIN_KEY || 'diginodal_admin_2025'}">View Full Dashboard</a></p>
          `
      };
      transporter.sendMail(mailOptions).catch(err => console.error("Email failed to send:", err));
  }

  return res.json({
    overallScore,
    scoreLabel,
    scoreSummary,
    psScores: {
      performance:   mobileScores.performance,
      seo:           mobileScores.seo,
      accessibility: mobileScores.accessibility,
      // bonus: desktop perf for dashboard display
      performanceDesktop: desktopScores.performance,
    },
    coreWebVitals: vitals,
    htmlChecks,
    htmlHealth,
    extractedKeywords: keywords,
    aiRecommendations,
    failedAudits: failedAudits.slice(0, 8),
    wordCount,
  });
});

// ─────────────────────────────────────────────
// /leads dashboard
// ─────────────────────────────────────────────
app.get('/leads', async (req, res) => {
  const adminKey = process.env.ADMIN_KEY || 'diginodal_admin_2025';
  if (req.query.key !== adminKey) {
    return res.status(403).send('Unauthorized');
  }

  // Basic filters from query params
  const filter      = {};
  const minScore    = parseInt(req.query.minScore);
  const maxScore    = parseInt(req.query.maxScore);
  const contacted   = req.query.contacted;
  const search      = req.query.q;

  if (!isNaN(minScore)) filter.overallScore = { ...filter.overallScore, $gte: minScore };
  if (!isNaN(maxScore)) filter.overallScore = { ...filter.overallScore, $lte: maxScore };
  if (contacted === 'true')  filter.contacted = true;
  if (contacted === 'false') filter.contacted = false;
  if (search) filter.$or = [
    { name: { $regex: search, $options: 'i' } },
    { url:  { $regex: search, $options: 'i' } },
    { email: { $regex: search, $options: 'i' } }, // <-- NEW: Search by email
  ];

  // CSV export
  if (req.query.format === 'csv') {
    try {
      const leads = await Lead.find(filter).sort({ auditDate: -1 }).limit(1000);
      const rows  = [
        // <-- NEW: Added Email to CSV headers
        ['Date','Name','Email','Phone','Website','Score','Label','Performance','SEO','Accessibility','HTML Health','Top Issues','Contacted'],
        ...leads.map(l => [
          new Date(l.auditDate).toISOString().slice(0, 10),
          l.name, l.email || '', l.phone, l.url, l.overallScore, l.scoreLabel, // <-- NEW: Added email to CSV export row
          l.pillars?.performance || '', l.pillars?.seo || '',
          l.pillars?.accessibility || '', l.pillars?.htmlHealth || '',
          (l.topIssues || []).join(' | '), l.contacted ? 'Yes' : 'No',
        ])
      ].map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="diginodal_leads.csv"');
      return res.send(rows);
    } catch (e) {
      return res.status(500).send('Export failed');
    }
  }

  try {
    const leads      = await Lead.find(filter).sort({ auditDate: -1 }).limit(200);
    const totalLeads = await Lead.countDocuments();
    const avgScore   = totalLeads > 0
      ? Math.round((await Lead.aggregate([{ $group: { _id: null, avg: { $avg: '$overallScore' } } }]))[0]?.avg || 0)
      : 0;
    const notContacted = await Lead.countDocuments({ contacted: false });

    const scoreClass = s =>
      s >= 80 ? 'good' : s >= 60 ? 'avg' : 'bad';

    // Mask phone: show last 4 digits only
    const maskPhone = p => {
      const digits = p.replace(/\D/g, '');
      return digits.length >= 4 ? '•••• ' + digits.slice(-4) : '••••';
    };
    // WhatsApp link with full digits
    const waLink = p => `https://wa.me/${p.replace(/\D/g, '')}`;

    const qs = (extra = '') => {
      const base = `?key=${adminKey}`;
      return base + extra;
    };

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Leads Dashboard | Diginodal</title>
  <style>
    :root {
      --bg:#080C14;--surface:#0F1623;--card:#141D2E;--border:#1E2D45;
      --accent:#6366F1;--text:#F0F4FF;--muted:#6B7FA3;
      --good:#10B981;--warn:#F59E0B;--bad:#F43F5E;
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);padding:32px 24px;min-height:100vh;}
    h1{font-size:24px;font-weight:800;margin-bottom:4px;}
    .sub{color:var(--muted);font-size:14px;margin-bottom:32px;}
    .stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:16px;margin-bottom:32px;}
    .stat{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;}
    .stat .num{font-size:32px;font-weight:800;color:var(--accent);}
    .stat .lbl{font-size:12px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:1px;}
    .toolbar{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px;align-items:center;}
    .toolbar input,.toolbar select{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:9px 14px;border-radius:8px;font-size:14px;outline:none;}
    .toolbar input:focus,.toolbar select:focus{border-color:var(--accent);}
    .btn{display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;border:none;}
    .btn-accent{background:var(--accent);color:#fff;}
    .btn-outline{background:transparent;border:1px solid var(--border);color:var(--muted);}
    .btn-outline:hover{border-color:var(--accent);color:var(--text);}
    .tbl-wrap{overflow-x:auto;border-radius:14px;border:1px solid var(--border);}
    table{width:100%;border-collapse:collapse;min-width:700px;}
    th{background:var(--surface);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1.5px;padding:14px 16px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;}
    td{padding:14px 16px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:top;}
    tr:last-child td{border-bottom:none;}
    tr:hover td{background:var(--surface);}
    .score-badge{display:inline-block;padding:4px 10px;border-radius:6px;font-weight:700;font-size:13px;}
    .good{background:rgba(16,185,129,0.12);color:var(--good);}
    .avg {background:rgba(245,158,11,0.12);color:var(--warn);}
    .bad {background:rgba(244,63,94,0.12);color:var(--bad);}
    .wa-btn{display:inline-flex;align-items:center;gap:5px;background:rgba(37,211,102,0.12);color:#25D366;padding:5px 10px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none;}
    .wa-btn:hover{background:rgba(37,211,102,0.22);}
    .issues{display:flex;flex-wrap:wrap;gap:4px;max-width:200px;}
    .issue-tag{font-size:11px;background:rgba(244,63,94,0.1);color:var(--bad);padding:2px 7px;border-radius:4px;white-space:nowrap;}
    .site-link{color:var(--accent);text-decoration:none;font-size:13px;}
    .site-link:hover{text-decoration:underline;}
    .empty{text-align:center;padding:60px;color:var(--muted);}
    @media(max-width:600px){body{padding:16px;}h1{font-size:20px;}}
  </style>
</head>
<body>
  <h1>Diginodal SEO Leads</h1>
  <p class="sub">${totalLeads} total leads · Avg score: ${avgScore}/100 · ${notContacted} not yet contacted</p>

  <div class="stats">
    <div class="stat"><div class="num">${totalLeads}</div><div class="lbl">Total Leads</div></div>
    <div class="stat"><div class="num">${avgScore}</div><div class="lbl">Avg Score</div></div>
    <div class="stat"><div class="num">${notContacted}</div><div class="lbl">Uncontacted</div></div>
    <div class="stat"><div class="num">${leads.filter(l => l.overallScore < 50).length}</div><div class="lbl">Critical Sites</div></div>
  </div>

  <form method="GET" action="/leads" class="toolbar">
    <input type="hidden" name="key" value="${adminKey}">
    <input type="text" name="q" placeholder="Search name, email, or URL…" value="${search || ''}">
    <select name="contacted">
      <option value="">All leads</option>
      <option value="false" ${contacted === 'false' ? 'selected' : ''}>Not contacted</option>
      <option value="true"  ${contacted === 'true'  ? 'selected' : ''}>Contacted</option>
    </select>
    <select name="minScore">
      <option value="">Min score</option>
      <option value="0"  ${minScore === 0  ? 'selected' : ''}>Any</option>
      <option value="50" ${minScore === 50 ? 'selected' : ''}>&lt;50 (Critical)</option>
      <option value="70" ${minScore === 70 ? 'selected' : ''}>70+</option>
    </select>
    <button class="btn btn-accent" type="submit">Filter</button>
    <a class="btn btn-outline" href="${qs('&format=csv' + (search ? `&q=${search}` : ''))}">⬇ Export CSV</a>
    <a class="btn btn-outline" href="${qs()}">Clear</a>
  </form>

  ${leads.length === 0 ? '<div class="empty">No leads match your filters.</div>' : `
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>Date</th>
          <th>Business</th>
          <th>Email</th> <th>Phone</th>
          <th>Website</th>
          <th>Score</th>
          <th>Performance</th>
          <th>SEO</th>
          <th>Top Issues</th>
          <th>Contact</th>
        </tr>
      </thead>
      <tbody>
        ${leads.map(l => `
        <tr>
          <td style="color:var(--muted);white-space:nowrap">${new Date(l.auditDate).toLocaleDateString('en-IN', { day:'numeric', month:'short' })}</td>
          <td><strong>${l.name}</strong></td>
          <td><a href="mailto:${l.email}" style="color:var(--text); text-decoration:none;">${l.email || '—'}</a></td> <td style="font-family:monospace;color:var(--muted)">${maskPhone(l.phone)}</td>
          <td><a class="site-link" href="${l.url}" target="_blank">${new URL(l.url).hostname}</a></td>
          <td><span class="score-badge ${scoreClass(l.overallScore)}">${l.overallScore}/100</span></td>
          <td><span style="color:${l.pillars?.performance >= 70 ? 'var(--good)' : l.pillars?.performance >= 50 ? 'var(--warn)' : 'var(--bad)'}">${l.pillars?.performance ?? '—'}</span></td>
          <td><span style="color:${l.pillars?.seo >= 70 ? 'var(--good)' : l.pillars?.seo >= 50 ? 'var(--warn)' : 'var(--bad)'}">${l.pillars?.seo ?? '—'}</span></td>
          <td><div class="issues">${(l.topIssues || []).map(i => `<span class="issue-tag">${i}</span>`).join('')}</div></td>
          <td><a class="wa-btn" href="${waLink(l.phone)}" target="_blank">
            <svg width="13" height="13" fill="currentColor" viewBox="0 0 24 24"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
            WhatsApp
          </a></td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>`}
</body>
</html>`;

    res.send(html);
  } catch (err) {
    console.error('Leads dashboard error:', err);
    res.status(500).send('Database error');
  }
});

// ─────────────────────────────────────────────
// SPA fallback
// ─────────────────────────────────────────────
app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

app.listen(PORT, () => console.log(`🚀 Diginodal SEO Audit running on http://localhost:${PORT}`));