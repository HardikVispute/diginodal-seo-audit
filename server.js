require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cheerio = require('cheerio');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/diginodal_seo';
mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const LeadSchema = new mongoose.Schema({
    name: String, phone: String, url: String, overallScore: Number,
    auditDate: { type: Date, default: Date.now }, contacted: { type: Boolean, default: false }
});
const Lead = mongoose.model('Lead', LeadSchema);

function formatUrl(url) {
    let formattedUrl = url.trim();
    if (!/^https?:\/\//i.test(formattedUrl)) formattedUrl = 'https://' + formattedUrl;
    return formattedUrl;
}

async function safeFetch(url, options = {}, timeout = 15000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(id);
        return response;
    } catch (e) {
        clearTimeout(id);
        throw e;
    }
}

app.post('/audit', async (req, res) => {
    const { url, name, phone } = req.body;
    if (!url || !name || !phone) return res.status(400).json({ error: 'Missing required fields' });

    const targetUrl = formatUrl(url);
    
    let psScores = { performance: 45, seo: 55, accessibility: 60 };
    let coreWebVitals = { fcp: '2.1s', lcp: '4.3s', tbt: '350ms' };
    let failedAudits = [];
    let htmlChecks = [];
    let extractedKeywords = []; 
    let htmlScorePoints = 0;
    const totalHtmlChecks = 8;
    const pointsPerCheck = 30 / totalHtmlChecks;

    try {
        // 1. Google PageSpeed API
        try {
            const apiKey = process.env.PAGESPEED_API_KEY ? `&key=${process.env.PAGESPEED_API_KEY}` : '';
            const psApiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(targetUrl)}&strategy=mobile${apiKey}`;
            const psResponse = await safeFetch(psApiUrl, {}, 15000);
            
            if (psResponse.ok) {
                const psData = await psResponse.json();
                const lighthouse = psData.lighthouseResult;
                if (lighthouse && lighthouse.categories) {
                    psScores.performance = (lighthouse.categories.performance?.score || 0.45) * 100;
                    psScores.seo = (lighthouse.categories.seo?.score || 0.55) * 100;
                    psScores.accessibility = (lighthouse.categories.accessibility?.score || 0.60) * 100;
                }
                if (lighthouse && lighthouse.audits) {
                    coreWebVitals.fcp = lighthouse.audits['first-contentful-paint']?.displayValue || 'N/A';
                    coreWebVitals.lcp = lighthouse.audits['largest-contentful-paint']?.displayValue || 'N/A';
                    coreWebVitals.tbt = lighthouse.audits['total-blocking-time']?.displayValue || 'N/A';
                    for (const key in lighthouse.audits) {
                        const audit = lighthouse.audits[key];
                        if (audit.score !== null && audit.score < 0.9 && audit.details && audit.title) {
                            failedAudits.push({ title: audit.title, description: audit.description || '' });
                        }
                    }
                }
            }
        } catch (apiErr) { console.warn('PageSpeed timeout.'); }

        // 2. HTML Checks & Keyword Extraction
        const isHttps = targetUrl.startsWith('https://');
        htmlChecks.push({ check: 'HTTPS Encryption', status: isHttps ? 'pass' : 'fail', detail: isHttps ? 'Website uses secure HTTPS.' : 'Website is missing SSL/HTTPS.' });
        if (isHttps) htmlScorePoints += pointsPerCheck;

        try {
            const siteResponse = await safeFetch(targetUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } }, 10000);
            const html = await siteResponse.text();
            const $ = cheerio.load(html);

            const title = $('title').text().trim();
            htmlChecks.push({ check: 'Title Tag', status: (title.length >= 30 && title.length <= 60) ? 'pass' : (title ? 'warning' : 'fail'), detail: title ? `Length: ${title.length} chars.` : 'Missing title tag.' });
            if (title.length >= 30 && title.length <= 60) htmlScorePoints += pointsPerCheck;

            const metaDesc = $('meta[name="description"]').attr('content') || '';
            htmlChecks.push({ check: 'Meta Description', status: (metaDesc.length >= 120 && metaDesc.length <= 160) ? 'pass' : (metaDesc ? 'warning' : 'fail'), detail: metaDesc ? `Length: ${metaDesc.length} chars.` : 'Missing meta description.' });
            if (metaDesc.length >= 120 && metaDesc.length <= 160) htmlScorePoints += pointsPerCheck;

            const h1Count = $('h1').length;
            htmlChecks.push({ check: 'H1 Tag', status: h1Count === 1 ? 'pass' : 'fail', detail: h1Count === 0 ? 'No H1 tag found.' : (h1Count > 1 ? 'Multiple H1 tags detected.' : 'Exactly one H1 tag found.') });
            if (h1Count === 1) htmlScorePoints += pointsPerCheck;

            const imgTotal = $('img').length;
            const imgMissingAlt = $('img:not([alt]), img[alt=""]').length;
            htmlChecks.push({ check: 'Image Alt Text', status: (imgTotal > 0 && imgMissingAlt === 0) ? 'pass' : (imgTotal === 0 ? 'warning' : 'fail'), detail: imgTotal === 0 ? 'No images found.' : `${imgMissingAlt} out of ${imgTotal} images missing alt text.` });
            if (imgTotal > 0 && imgMissingAlt === 0 || imgTotal === 0) htmlScorePoints += pointsPerCheck;

            const viewport = $('meta[name="viewport"]').length > 0;
            htmlChecks.push({ check: 'Mobile Viewport', status: viewport ? 'pass' : 'fail', detail: viewport ? 'Viewport tag exists.' : 'Missing mobile viewport tag.' });
            if (viewport) htmlScorePoints += pointsPerCheck;

            $('script, style, noscript, iframe, nav, footer, header').remove(); 
            let rawText = $('body').text().toLowerCase().replace(/[^a-z\s]/g, ' ');
            let words = rawText.split(/\s+/).filter(w => w.length > 3); 
            const stopWords = new Set(['that','this','with','from','your','have','more','will','about','contact','home','what','when','where','they','their','which','services','read']);
            let filteredWords = words.filter(w => !stopWords.has(w));
            let wordCounts = {};
            filteredWords.forEach(w => { wordCounts[w] = (wordCounts[w] || 0) + 1; });
            let sortedWords = Object.keys(wordCounts).sort((a, b) => wordCounts[b] - wordCounts[a]);
            extractedKeywords = sortedWords.slice(0, 6).map(w => ({
                keyword: w.charAt(0).toUpperCase() + w.slice(1), 
                count: wordCounts[w]
            }));

        } catch (htmlErr) { console.warn('HTML parse failure'); }

        let baseUrl = targetUrl;
        try { baseUrl = new URL(targetUrl).origin; } catch(e){}
        
        try {
            const robotsValid = (await safeFetch(`${baseUrl}/robots.txt`, {}, 5000)).status === 200;
            htmlChecks.push({ check: 'Robots.txt', status: robotsValid ? 'pass' : 'fail', detail: robotsValid ? 'Found at /robots.txt' : 'Missing file.' });
            if (robotsValid) htmlScorePoints += pointsPerCheck;
        } catch (e) {}

        try {
            const sitemapValid = (await safeFetch(`${baseUrl}/sitemap.xml`, {}, 5000)).status === 200;
            htmlChecks.push({ check: 'Sitemap.xml', status: sitemapValid ? 'pass' : 'fail', detail: sitemapValid ? 'Found at /sitemap.xml' : 'Missing file.' });
            if (sitemapValid) htmlScorePoints += pointsPerCheck;
        } catch (e) {}

        let overallScore = Math.round((psScores.performance * 0.30) + (psScores.seo * 0.30) + (psScores.accessibility * 0.10) + htmlScorePoints);
        if (overallScore > 100) overallScore = 100;
        if (overallScore < 10) overallScore = 35; 

        // ==========================================
        // PHASE 2.2 - GEMINI AI ACTION PLAN (100% FREE)
        // ==========================================
        let aiRecommendations = [
            "Optimize your page load speed to pass Google's Core Web Vitals.",
            "Ensure your primary business keywords are present in your H1 and Title tags.",
            "Fix missing image descriptions to improve accessibility and image search rankings."
        ]; 

        if (process.env.GEMINI_API_KEY) {
            try {
                const prompt = `You are a top-tier SEO expert. Analyze this website data:
Score: ${overallScore}/100
Keywords Found: ${extractedKeywords.map(k=>k.keyword).join(', ')}
Failed Checks: ${htmlChecks.filter(c=>c.status!=='pass').map(c=>c.check).join(', ')}

Provide 3 highly actionable, plain-English recommendations to the business owner on how to fix these issues. Make it sound professional, persuasive, and reference their specific keywords if possible. 
Output strictly as a JSON object with a single key "recommendations" containing an array of 3 strings. Do not include markdown formatting like \`\`\`json.`;

                const aiRes = await safeFetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        contents: [{ parts: [{ text: prompt }] }],
                        generationConfig: { responseMimeType: "application/json" }
                    })
                }, 15000);

                if (aiRes.ok) {
                    const aiData = await aiRes.json();
                    const textResponse = aiData.candidates[0].content.parts[0].text;
                    const parsed = JSON.parse(textResponse);
                    if (parsed.recommendations && parsed.recommendations.length > 0) {
                        aiRecommendations = parsed.recommendations;
                    }
                } else {
                    console.warn(`Gemini API returned ${aiRes.status}`);
                }
            } catch (e) {
                console.warn('Gemini generation failed, using fallbacks.', e.message);
            }
        }
        // ==========================================

        let scoreLabel = overallScore >= 80 ? 'Good' : (overallScore >= 60 ? 'Needs Improvement' : 'Critical Issues Found');
        try { await Lead.create({ name, phone, url: targetUrl, overallScore }); } catch (dbErr) {}

        return res.json({ overallScore, scoreLabel, psScores, coreWebVitals, htmlChecks, extractedKeywords, aiRecommendations, failedAudits: failedAudits.slice(0, 5) });

    } catch (globalErr) {
        return res.status(500).json({ error: 'System crash during analysis.' });
    }
});

app.get('/leads', async (req, res) => {
    const key = req.query.key;
    if (key !== 'diginodal123') return res.status(403).send('Unauthorized');
    try {
        const leads = await Lead.find().sort({ auditDate: -1 });
        let html = `<!DOCTYPE html><html><head><title>Diginodal Leads</title><style>body { font-family: -apple-system, sans-serif; padding: 40px; background: #0F172A; color: #fff; } table { width: 100%; border-collapse: collapse; background: #1E293B; border-radius: 8px; overflow: hidden; } th, td { padding: 16px; text-align: left; border-bottom: 1px solid #334155; } th { background: #2563EB; color: white; } a { color: #60A5FA; text-decoration: none; } .score { font-weight: bold; } .good { color: #10B981; } .avg { color: #F59E0B; } .bad { color: #EF4444; }</style></head><body><h2>Diginodal SEO Leads</h2><table><tr><th>Date</th><th>Name</th><th>Phone</th><th>Website</th><th>Score</th></tr>${leads.map(lead => `<tr><td>${new Date(lead.auditDate).toLocaleDateString()}</td><td>${lead.name}</td><td><a href="https://wa.me/${lead.phone.replace(/\D/g,'')}" target="_blank">${lead.phone}</a></td><td><a href="${lead.url}" target="_blank">${lead.url}</a></td><td class="score ${lead.overallScore >= 80 ? 'good' : (lead.overallScore >= 60 ? 'avg' : 'bad')}">${lead.overallScore}/100</td></tr>`).join('')}</table></body></html>`;
        res.send(html);
    } catch (err) { res.status(500).send('Database error'); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));