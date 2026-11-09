#!/usr/bin/env node
/**
 * Joomla K2 Finder — passive, low-rate public-HTML technology detector.
 * Node.js 22+, no third-party packages.
 * No vulnerability scans, authentication, directory enumeration, or form submissions.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

const USER_AGENT = 'JoomlaK2Finder/1.1 (public-pages-research; contact site owner for an audit)';
const ROBOT_AGENT = 'JoomlaK2Finder';
const DEFAULTS = { delay: 1500, timeout: 10000, maxPages: 3, maxSites: 100, manifest: false, ruOnly: false, retryErrors: false, fresh: false };
export const FIELDS = [
  'domain','site_url','site_title','company_name','business_type','joomla_detected','k2_detected',
  'k2_confidence','joomla_version','version_confidence','version_source',
  'technical_priority','lead_priority','priority','contact_url','pages_checked',
  'robots_status','scan_status','evidence','error','checked_at'
];
export const LEAD_FIELDS = FIELDS;
const NON_BUSINESS = new Set(['media','ngo','government','personal','other']);

export function isRussianDomain(domain) {
  return /\.(?:ru|xn--p1ai)$/i.test(String(domain || ''));
}

export function businessType(value) {
  const v = String(value ?? '').trim().toLowerCase();
  return ['business','media','ngo','government','personal','other'].includes(v) ? v : 'unknown';
}

// A prospect score describes *technical fit*, not commercial viability or a security finding.
export function prospectPriority(row) {
  const type = businessType(row.business_type);
  if (row.scan_status !== 'ok' || row.k2_detected !== 'yes' || NON_BUSINESS.has(type)) return 'low';
  if (type === 'unknown') return 'review';
  if (row.version_confidence === 'conflict') return 'review';
  return row.technical_priority === 'high' && !!row.contact_url ? 'high' : 'medium';
}

export function eligibleLead(row) {
  return isRussianDomain(row.domain) && row.scan_status === 'ok' &&
    row.k2_detected === 'yes' && !NON_BUSINESS.has(businessType(row.business_type));
}

export function normalizeCachedRow(input) {
  const row = { ...input };
  const ok = row.scan_status === 'ok';
  for (const field of ['joomla_detected','k2_detected']) {
    const val = String(row[field] ?? '').toLowerCase();
    row[field] = !ok ? 'unknown' : (val === 'true' || val === 'yes' ? 'yes' : val === 'false' || val === 'no' ? 'no' : 'unknown');
  }
  row.business_type = businessType(row.business_type);
  row.company_name = row.company_name || '';
  row.k2_confidence ||= row.k2_detected === 'yes' ? 'medium' : 'unknown';
  row.technical_priority ||= (row.priority === 'review' ? 'review' : row.k2_detected === 'yes' ?
    (row.version_confidence === 'conflict' ? 'review' : (row.version_confidence === 'high' && /^[123]\./.test(row.joomla_version) ? 'high' : 'medium')) : 'low');
  row.lead_priority = prospectPriority(row);
  row.priority = row.technical_priority; // backward-compatible alias
  return row;
}

export function csvParse(raw) {
  const rows = [];
  let row = [], field = '', quoted = false;
  raw = String(raw).replace(/^\uFEFF/, '');
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (quoted) {
      if (c === '"' && raw[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && raw[i + 1] === '\n') i++;
      row.push(field);
      if (row.some(x => x.trim())) rows.push(row);
      row = []; field = '';
    } else field += c;
  }
  row.push(field);
  if (row.some(x => x.trim())) rows.push(row);
  return rows;
}

function csvCell(value) {
  let s = String(value ?? '').replace(/\r?\n/g, ' ');
  if (/^[\s]*[=+@\-]/.test(s)) s = "'" + s; // prevent spreadsheet formula execution
  return /[",\r\n]/.test(s) ? '"' + s.replaceAll('"', '""') + '"' : s;
}
export function csvStringify(rows, fields = FIELDS) {
  return '\uFEFF' + [fields.join(','), ...rows.map(r => fields.map(k => csvCell(r[k])).join(','))].join('\r\n') + '\r\n';
}

export function parseDomainRecords(source) {
  const domains = loadDomains(source);
  const meta = new Map();
  const trimmed = String(source).trim().replace(/^\uFEFF/, '');
  if (trimmed && (trimmed.includes(',') || /^(domain|url|site|домен|сайт),/i.test(trimmed))) {
    const data = csvParse(trimmed);
    const keys = data[0].map(x => x.trim().toLowerCase());
    const key = keys.findIndex(x => ['domain','url','site','website','домен','сайт'].includes(x));
    if (key >= 0) for (const values of data.slice(1)) {
      const domain = normalizeDomain(values[key]);
      if (!domain) continue;
      const item = Object.fromEntries(keys.map((x,i)=>[x, values[i] || '']));
      meta.set(domain, { company_name: item.company_name || item.company || '',
        business_type: businessType(item.business_type || item.company_type) });
    }
  }
  return domains.map(domain => ({ domain, ...meta.get(domain) }));
}

export function loadDomains(source) {
  const trimmed = source.trim().replace(/^\uFEFF/, '');
  if (!trimmed) return [];
  let entries;
  if (trimmed.includes(',') || /^(domain|url|site|домен|сайт),/i.test(trimmed)) {
    const data = csvParse(trimmed);
    const header = data[0].map(x => x.trim().toLowerCase());
    const idx = header.findIndex(x => ['domain','url','site','website','домен','сайт'].includes(x));
    entries = idx >= 0 ? data.slice(1).map(r => r[idx]) : data.map(r => r[0]);
  } else {
    entries = trimmed.split(/\r?\n/).map(x => x.trim().split(/\s|;/)[0]);
  }
  return [...new Set(entries.map(normalizeDomain).filter(Boolean))];
}

export function normalizeDomain(value) {
  try {
    const str = String(value ?? '').trim();
    if (!str || str.startsWith('#')) return null;
    const url = new URL(/^[a-z][\w+.-]*:\/\//i.test(str) ? str : `https://${str}`);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port) return null;
    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    if (isIP(host) || host === 'localhost' || host.endsWith('.localhost') ||
      host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.test') ||
      host.endsWith('.invalid') || !host.includes('.') || host.length > 253 ||
      !/^[a-z0-9.-]+$/.test(host)) return null;
    return host;
  } catch { return null; }
}

function sameSite(a, b) {
  const hostA = new URL(a).hostname.replace(/^www\./i, '');
  const hostB = new URL(b).hostname.replace(/^www\./i, '');
  return hostA === hostB;
}

/** Only public DNS results; never explicitly probe IP addresses or local hosts. */
export function publicIp(ip) {
  const family = isIP(ip);
  if (family === 4) {
    const [a, b] = ip.split('.').map(Number);
    if ([0, 10, 127].includes(a) || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && [0, 168].includes(b)) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 192 && b === 88) return false; // 192.88.99/24 deprecated relay
    return true;
  }
  if (family === 6) {
    const x = ip.toLowerCase();
    if (x === '::' || x === '::1' || x.startsWith('fc') || x.startsWith('fd') ||
      x.startsWith('fe8') || x.startsWith('fe9') || x.startsWith('fea') || x.startsWith('feb') ||
      x.startsWith('ff') || x.startsWith('2001:db8:')) return false;
    if (x.includes('.')) {
      const lastIp = x.match(/(?:\d{1,3}\.){3}\d{1,3}$/)?.[0];
      if (lastIp && !publicIp(lastIp)) return false;
    }
    if (x.startsWith('::ffff:')) {
      const hex = x.slice(7);
      if (/^[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(hex)) {
        const [p, q] = hex.split(':').map(h => parseInt(h, 16));
        return publicIp([(p >> 8) & 255, p & 255, (q >> 8) & 255, q & 255].join('.'));
      }
    }
    return true;
  }
  return false;
}

function robotsGroups(content) {
  const groups = [];
  let agents = [], rules = [], startedRules = false;
  function flush() {
    if (agents.length) groups.push({ agents, rules });
    agents = []; rules = []; startedRules = false;
  }
  for (const line of content.split(/\r?\n/)) {
    const clean = line.replace(/#.*$/, '').trim();
    if (!clean) { if (startedRules) flush(); continue; }
    const m = clean.match(/^([a-z-]+)\s*:\s*(.*)$/i);
    if (!m) continue;
    const directive = m[1].toLowerCase(), value = m[2].trim();
    if (directive === 'user-agent') {
      if (startedRules) flush();
      agents.push(value.toLowerCase());
    } else if (['allow','disallow'].includes(directive) && agents.length) {
      rules.push({ allow: directive === 'allow', pattern: value });
      startedRules = true;
    }
  }
  flush();
  return groups;
}

export function robotsAllowed(content, path, agent = ROBOT_AGENT) {
  const groups = robotsGroups(content);
  let matches = [], best = -1;
  for (const group of groups) {
    const specificity = Math.max(-1, ...group.agents.map(a => a === '*' ? 0 :
      (agent.toLowerCase().includes(a) ? a.length : -1)));
    if (specificity > best) { best = specificity; matches = [group]; }
    else if (specificity === best && specificity >= 0) matches.push(group);
  }
  if (best < 0) return true;
  let winner = null;
  for (const group of matches) for (const rule of group.rules) {
    if (!rule.pattern) continue;
    const pattern = rule.pattern;
    const anchored = pattern.endsWith('$');
    const source = (anchored ? pattern.slice(0, -1) : pattern)
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replaceAll('\\*', '.*');
    const regex = new RegExp('^' + source + (anchored ? '$' : ''));
    if (!regex.test(path)) continue;
    const specificity = pattern.replace(/[\*$]/g, '').length;
    if (!winner || specificity > winner.spec || (specificity === winner.spec && rule.allow))
      winner = { spec: specificity, allow: rule.allow };
  }
  return !winner || winner.allow;
}

function decodeHtml(s) {
  return s.replace(/&(?:amp|quot|lt|gt|nbsp|#39|#x27);/gi, entity => ({
    '&amp;': '&', '&quot;': '"', '&lt;': '<', '&gt;': '>', '&nbsp;': ' ', '&#39;': "'", '&#x27;': "'"
  })[entity.toLowerCase()] ?? entity).replace(/\s+/g, ' ').trim();
}

function attribute(tag, name) {
  const re = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
  const match = tag.match(re);
  return match ? decodeHtml(match[1] ?? match[2] ?? match[3]) : '';
}

export function parsePage(html, pageUrl) {
  const evidence = [];
  const title = decodeHtml(html.match(/<title\b[^>]*>([\s\S]{0,500}?)<\/title>/i)?.[1] ?? '').slice(0, 200);
  const push = (kind, detail) => {
    if (!evidence.some(x => x.kind === kind && x.detail === detail))
      evidence.push({ kind, detail, url: pageUrl });
  };
  const signatures = [
    [/option=com_k2\b/i, 'K2:option=com_k2', 'k2'],
    [/\/components\/com_k2\//i, 'K2:components/com_k2', 'k2'],
    [/\/media\/k2\//i, 'K2:media/k2', 'k2'],
    [/\/component\/k2\//i, 'K2:component/k2', 'k2'],
    [/\/media\/jui\//i, 'Joomla3:media/jui', 'j3'],
    [/\/templates\/protostar\//i, 'Joomla3:protostar', 'j3'],
    [/\/templates\/beez3\//i, 'Joomla3:beez3', 'j3'],
    [/\/templates\/beez_20\//i, 'Joomla2.5:beez_20', 'j2'],
    [/\/templates\/atomic\//i, 'Joomla2.5:atomic', 'j2'],
    [/\/templates\/cassiopeia\//i, 'Joomla4+:cassiopeia', 'j4plus'],
    [/\/media\/system\/js\/mootools-core\.js/i, 'LegacyJoomla:mootools', 'legacy'],
  ];
  const kinds = new Set();
  for (const [re, label, kind] of signatures) if (re.test(html)) { push(kind, label); kinds.add(kind); }
  let versionFromMeta = '';
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    if (attribute(tag, 'name').toLowerCase() !== 'generator') continue;
    const content = attribute(tag, 'content');
    if (!/joomla/i.test(content)) continue;
    kinds.add('joomla');
    push('joomla', `generator:${content.slice(0, 90)}`);
    versionFromMeta = content.match(/\bjoomla!?\s*[-:]?\s*v?(\d+(?:\.\d+){1,3})\b/i)?.[1] ?? '';
  }
  if (kinds.has('k2')) kinds.add('joomla');
  const links = [];
  let contactUrl = '';
  for (const tag of html.match(/<a\b[^>]*>/gi) || []) {
    const href = attribute(tag, 'href');
    if (!href || /^(mailto:|tel:|javascript:|data:|#)/i.test(href)) continue;
    let abs;
    try { abs = new URL(href, pageUrl); } catch { continue; }
    if (!['http:', 'https:'].includes(abs.protocol) || !sameSite(abs.href, pageUrl)) continue;
    if (abs.username || abs.password || abs.port) continue;
    abs.hash = '';
    if (!contactUrl && /(?:kontakty|contacts?|kontakt|контакт)/i.test(abs.pathname)) contactUrl = abs.href;
    if (/\/(?:administrator|wp-admin|user|login|logout|checkout)(?:\/|$)/i.test(abs.pathname)) continue;
    if (/\.(?:pdf|zip|jpg|png|webp|svg|docx?|xlsx?|css|js|mp4|exe)(?:$|\?)/i.test(abs.href)) continue;
    if (/option=com_k2|\/component\/k2\/|\/catalog(?:ue)?\/|\/uslug|\/services?\/|\/products?\/|\/news\/|\/blog\/|\/company\/|\/about\/|\/item\//i.test(abs.href))
      links.push(abs.href);
  }
  return { title, evidence, kinds, versionFromMeta, links: [...new Set(links)], contactUrl };
}

export function parseJoomlaManifest(xml) {
  // This path names the *core* file manifest, not the K2 component manifest.
  if (!/<extension\b/i.test(xml) || !/<name>\s*(?:files_joomla|joomla!?|joomla\s+cms)\s*<\/name>/i.test(xml)) return '';
  return xml.match(/<version>\s*(\d+(?:\.\d+){1,3})\s*<\/version>/i)?.[1] ?? '';
}

export function classify(pages, manifestVersion = '') {
  const signals = [...new Set(pages.flatMap(p => p.evidence.map(x => `${x.detail} @ ${x.url}`)))];
  const kinds = new Set(pages.flatMap(p => [...p.kinds]));
  const k2 = kinds.has('k2');
  const metaVersions = [...new Set(pages.map(x => x.versionFromMeta).filter(Boolean))];
  let version = '', confidence = 'unknown', source = 'none';
  if (manifestVersion) { version = manifestVersion; confidence = 'high'; source = 'public_core_manifest'; }
  if (metaVersions.length) {
    if (version && !metaVersions.some(x => version === x || version.startsWith(x + '.'))) {
      version = `${version} / ${metaVersions.join('/')}`;
      confidence = 'conflict'; source = 'manifest_vs_generator';
    } else if (!version && metaVersions.length === 1) {
      version = metaVersions[0]; confidence = 'high'; source = 'html_generator';
    } else if (!version) {
      version = metaVersions.join('/'); confidence = 'conflict'; source = 'multiple_generators';
    }
  }
  if (!version) {
    const possible = [];
    if (kinds.has('j2')) possible.push('2.5');
    if (kinds.has('j3')) possible.push('3.x');
    if (kinds.has('j4plus')) possible.push('4+');
    if (possible.length === 1) { version = possible[0]; confidence = 'medium'; source = 'frontend_assets'; }
    else if (possible.length > 1) { version = possible.join(' / '); confidence = 'conflict'; source = 'mixed_frontend_assets'; }
    else if (k2) { version = '3.x or earlier (hypothesis)'; confidence = 'low'; source = 'k2_compatibility'; }
  }
  const joomla = kinds.has('joomla') || kinds.has('j2') || kinds.has('j3') || kinds.has('j4plus') || kinds.has('legacy') || k2 || !!manifestVersion;
  if (manifestVersion) signals.push(`Joomla core manifest:${manifestVersion}`);
  let priority = 'low';
  if (k2 && confidence === 'conflict') priority = 'review';
  else if (k2 && confidence === 'high' && /^[123]\./.test(version)) priority = 'high';
  else if (k2) priority = 'medium';
  return { joomla_detected: joomla ? 'yes' : 'no', k2_detected: k2 ? 'yes' : 'no',
    k2_confidence: k2 ? (signals.some(x => /K2:(option=com_k2|components\/com_k2|component\/k2)/.test(x)) ? 'high' : 'medium') : 'unknown',
    joomla_version: version || 'unknown', version_confidence: confidence, version_source: source,
    technical_priority: priority, priority, evidence: signals.join(' | ').slice(0, 4000) };
}

function createTransport(options, deps = {}) {
  let lastCall = 0;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const dnsLookup = deps.dnsLookup ?? lookup;
  async function pacedFetch(url, accept = 'text/html') {
    const parsed = new URL(url);
    const host = normalizeDomain(parsed.hostname);
    if (!host || parsed.port || parsed.username || parsed.password || !['https:', 'http:'].includes(parsed.protocol))
      throw new Error('unsafe_url');
    const addresses = await dnsLookup(host, { all: true });
    if (!addresses?.length || addresses.some(x => !publicIp(x.address))) throw new Error('non_public_dns');
    const waitMs = Math.max(0, lastCall + options.delay - Date.now());
    if (waitMs) await new Promise(resolve => setTimeout(resolve, waitMs));
    lastCall = Date.now();
    return fetchImpl(url, { method: 'GET', redirect: 'manual', headers: {
      'User-Agent': USER_AGENT, 'Accept': accept
    }, signal: AbortSignal.timeout(options.timeout) });
  }
  async function request(url, accept = 'text/html') {
    let current = url;
    for (let n = 0; n < 4; n++) {
      const response = await pacedFetch(current, accept);
      if ([301,302,303,307,308].includes(response.status)) {
        const to = response.headers.get('location');
        await response.body?.cancel();
        if (!to) throw new Error('redirect_missing_location');
        const target = new URL(to, current);
        if (!sameSite(target.href, url) || !['http:', 'https:'].includes(target.protocol) ||
            target.port || target.username || target.password) throw new Error('redirect_outside_site');
        current = target.href;
        continue;
      }
      return { response, finalUrl: current };
    }
    throw new Error('redirect_limit');
  }
  const robotsCache = new Map();
  async function getRobots(origin) {
    if (robotsCache.has(origin)) return robotsCache.get(origin);
    const { response } = await request(new URL('/robots.txt', origin).href, 'text/plain');
    let state;
    if ([401,403,429].includes(response.status) || response.status >= 500)
      state = { status: `robots_http_${response.status}`, blocked: true, content: '' };
    else if ([404,410].includes(response.status)) state = { status: 'robots_absent', blocked: false, content: '' };
    else if (response.status >= 400) state = { status: `robots_http_${response.status}`, blocked: true, content: '' };
    else state = { status: 'robots_read', blocked: false, content: await readLimited(response, 300_000) };
    await response.body?.cancel().catch(() => {});
    robotsCache.set(origin, state);
    return state;
  }
  async function checkedRequest(url, accept, maxBytes) {
    // Verify permission for the first origin and again after any www redirect.
    let current = url;
    for (let redirects = 0; redirects < 4; redirects++) {
      const { origin, pathname, search } = new URL(current);
      const robots = await getRobots(origin);
      if (robots.blocked || !robotsAllowed(robots.content, pathname + search))
        throw new Error(`robots_disallowed (${robots.status} ${pathname})`);
      const response = await pacedFetch(current, accept);
      if ([301,302,303,307,308].includes(response.status)) {
        const location = response.headers.get('location');
        await response.body?.cancel();
        if (!location) throw new Error('redirect_missing_location');
        const next = new URL(location, current);
        if (!sameSite(next.href, url) || !['https:', 'http:'].includes(next.protocol) ||
            next.port || next.username || next.password) throw new Error('redirect_outside_site');
        current = next.href;
        continue;
      }
      const body = await readLimited(response, maxBytes);
      return { status: response.status, body, finalUrl: current, contentType: response.headers.get('content-type') ?? '', robotsStatus: robots.status };
    }
    throw new Error('redirect_limit');
  }
  return { checkedRequest };
}

async function readLimited(response, maxBytes) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error('response_too_large');
      chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

function baseResult(domain) {
  return {
    domain, site_url: '', site_title: '', company_name: '', business_type: 'unknown',
    joomla_detected: 'unknown', k2_detected: 'unknown', k2_confidence: 'unknown',
    joomla_version: 'unknown', version_confidence: 'unknown', version_source: 'none',
    technical_priority: 'low', lead_priority: 'low', priority: 'low', contact_url: '', pages_checked: 0, robots_status: '',
    scan_status: 'error', evidence: '', error: '', checked_at: new Date().toISOString()
  };
}

export async function scanDomain(domain, settings = {}, deps = {}) {
  const opts = { ...DEFAULTS, ...settings };
  const record = baseResult(domain);
  const transport = createTransport(opts, deps);
  let home;
  for (const protocol of ['https:', 'http:']) {
    try {
      home = await transport.checkedRequest(`${protocol}//${domain}/`, 'text/html', 1_500_000);
      break;
    } catch (err) {
      const reason = String(err.message ?? err);
      // Never fall back after explicit robots denial or an unsafe redirect.
      if (protocol === 'http:' || /robots_disallowed|non_public_dns|redirect_outside_site|unsafe_url/.test(reason)) {
        record.error = reason; return record;
      }
    }
  }
  if (!home) { record.error = 'site_unreachable'; return record; }
  record.site_url = home.finalUrl;
  record.robots_status = home.robotsStatus;
  if (home.status !== 200) { record.error = `home_http_${home.status}`; return record; }
  if (home.contentType && !/text\/html|application\/xhtml\+xml/i.test(home.contentType)) {
    record.error = 'home_not_html'; return record;
  }
  const pages = [parsePage(home.body, home.finalUrl)];
  record.pages_checked = 1;
  record.site_title = pages[0].title;
  record.contact_url = pages[0].contactUrl;
  // Prefer K2/catalog links over news so a tiny scan is more informative.
  const linkRank = x => /option=com_k2|\/component\/k2\//i.test(x) ? 3 :
    /\/catalog(?:ue)?\/|\/uslug|\/services?\/|\/products?\/|\/item\//i.test(x) ? 2 : 1;
  const candidates = pages[0].links.filter(x => x !== home.finalUrl)
    .sort((a,b) => linkRank(b) - linkRank(a))
    .slice(0, Math.max(0, opts.maxPages - 1));
  for (const url of candidates) {
    try {
      const page = await transport.checkedRequest(url, 'text/html', 1_500_000);
      if (page.status !== 200 || (page.contentType && !/text\/html|application\/xhtml\+xml/i.test(page.contentType))) continue;
      pages.push(parsePage(page.body, page.finalUrl));
      record.pages_checked++;
      if (!record.contact_url) record.contact_url = pages.at(-1).contactUrl;
    } catch { /* respect robots, skip unavailable individual pages */ }
  }
  let manifestVersion = '';
  if (opts.manifest) {
    try {
      const page = await transport.checkedRequest(new URL('/administrator/manifests/files/joomla.xml', home.finalUrl).href,
        'application/xml,text/xml', 200_000);
      if (page.status === 200 && (!page.contentType || /xml|text\/plain|octet-stream/i.test(page.contentType)))
        manifestVersion = parseJoomlaManifest(page.body);
    } catch { /* no bypass/retries on denied manifest */ }
  }
  Object.assign(record, classify(pages, manifestVersion));
  record.scan_status = 'ok';
  record.lead_priority = prospectPriority(record);
  return record;
}

export function mergeResults(records, cached = [], fresh = false) {
  const old = fresh ? new Map() : new Map(cached.filter(x => normalizeDomain(x.domain)).map(x => [normalizeDomain(x.domain), normalizeCachedRow(x)]));
  return records.map(item => {
    const current = old.get(item.domain) ?? null;
    if (!current) return { item, cached: null };
    // Explicit fresh classification in the input CSV wins; old labels are retained otherwise.
    if (item.company_name) current.company_name = item.company_name;
    if (item.business_type && item.business_type !== 'unknown') current.business_type = item.business_type;
    current.lead_priority = prospectPriority(current);
    return { item, cached: current };
  });
}

export async function runBatch(opts, deps = {}) {
  const read = deps.readFile ?? readFile, write = deps.writeFile ?? writeFile;
  const scan = deps.scan ?? scanDomain;
  const input = await read(opts.input, 'utf8');
  const records = parseDomainRecords(input).filter(x => !opts.ruOnly || isRussianDomain(x.domain));
  if (!records.length) throw new Error('No matching public domains found in input');
  let cached = [];
  if (!opts.fresh) try {
    const rows = csvParse(await read(opts.output, 'utf8'));
    const names = rows[0].map(x=>x.trim());
    cached = rows.slice(1).map(cells=>Object.fromEntries(names.map((x,i)=>[x,cells[i] ?? ''])));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const queue = mergeResults(records, cached, opts.fresh);
  const results = new Map(queue.filter(x => x.cached).map(x => [x.item.domain, x.cached]));
  let scanned = 0, skipped = 0;
  async function save() {
    const rows = queue.map(x=>results.get(x.item.domain)).filter(Boolean);
    const leads = rows.filter(eligibleLead).sort((a,b)=>
      ({high:0,medium:1,review:2,low:3}[a.lead_priority] ?? 4) -
      ({high:0,medium:1,review:2,low:3}[b.lead_priority] ?? 4));
    await write(opts.output + '.tmp', csvStringify(rows), 'utf8');
    await (deps.rename ?? (await import('node:fs/promises')).rename)(opts.output + '.tmp', opts.output);
    await write(opts.leads + '.tmp', csvStringify(leads, LEAD_FIELDS), 'utf8');
    await (deps.rename ?? (await import('node:fs/promises')).rename)(opts.leads + '.tmp', opts.leads);
    return leads;
  }
  let leads = await save();
  for (const { item, cached: previous } of queue) {
    if (previous && (previous.scan_status === 'ok' || !opts.retryErrors)) { skipped++; continue; }
    if (scanned >= opts.maxSites) break;
    const result = await scan(item.domain, opts);
    const merged = normalizeCachedRow({ ...result, ...item,
      business_type: item.business_type && item.business_type !== 'unknown' ? item.business_type : previous?.business_type ?? 'unknown',
      company_name: item.company_name || previous?.company_name || '' });
    results.set(item.domain, merged);
    scanned++;
    leads = await save();
    console.log(`[${scanned}] ${item.domain}: ${merged.scan_status}, K2=${merged.k2_detected}, ` +
      `Joomla=${merged.joomla_version}, tech=${merged.technical_priority}, lead=${merged.lead_priority}` +
      (merged.error ? `, ${merged.error}` : ''));
  }
  console.log(`Scanned: ${scanned}, skipped cached: ${skipped}, leads: ${leads.length}. Files: ${opts.output}, ${opts.leads}`);
  return { scanned, skipped, leads, results: queue.map(x => results.get(x.item.domain)).filter(Boolean) };
}

function help() {
  return `Joomla K2 Finder 1.1 — low-rate public Joomla/K2 discovery (Node.js 22+)

Usage:
  node finder.mjs --input domains.txt --output results.csv --leads leads.csv --ru-only
  node finder.mjs --input companies.csv --manifest --retry-errors

Options:
  --input PATH       TXT or CSV with domain/url/site/домен column
  --output PATH      Full report CSV (default results.csv)
  --leads PATH       Russian K2 prospects CSV (default leads.csv)
  --ru-only          Scan only .ru and .рф domains
  --retry-errors     Retry cached failed or blocked checks (never bypass robots.txt)
  --fresh            Ignore existing CSV and start a new report
  --delay MS         Delay between HTTP requests (default 1500, min 1000)
  --timeout MS       Request timeout (default 10000)
  --max-pages N      Public pages per domain (default 3, 1..5)
  --max-sites N      New scans per run (default 100)
  --manifest         Try public core Joomla manifest if robots.txt permits
  --help             Print help

Cached completed rows are skipped by default. Errors are unknown, not negative evidence.
`;
}

function cliArgs(args) {
  if (args.includes('--help') || args.includes('-h')) return { help: true };
  const vals = { ...DEFAULTS, input: '', output: 'results.csv', leads: 'leads.csv' };
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (key === '--manifest') { vals.manifest = true; continue; }
    if (key === '--ru-only') { vals.ruOnly = true; continue; }
    if (key === '--retry-errors') { vals.retryErrors = true; continue; }
    if (key === '--fresh') { vals.fresh = true; continue; }
    const names = { '--input': 'input', '--output': 'output', '--leads': 'leads', '--delay': 'delay', '--timeout': 'timeout',
      '--max-pages': 'maxPages', '--max-sites': 'maxSites' };
    const name = names[key];
    if (!name || !args[i + 1]) throw new Error(`Unknown or incomplete argument: ${key}`);
    vals[name] = args[++i];
  }
  if (!vals.input) throw new Error('--input is required');
  if (vals.input === vals.output || vals.input === vals.leads || vals.output === vals.leads)
    throw new Error('input, output and leads paths must differ');
  for (const [key, min, max] of [['delay',1000,60000],['timeout',1000,60000],
    ['maxPages',1,5],['maxSites',1,10000]]) {
    const n = Number(vals[key]);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${key} must be an integer ${min}..${max}`);
    vals[key] = n;
  }
  return vals;
}

export async function main(args = process.argv.slice(2)) {
  let opts;
  try { opts = cliArgs(args); } catch (error) { console.error(error.message + '\n\n' + help()); process.exitCode = 2; return; }
  if (opts.help) { process.stdout.write(help()); return; }
  await runBatch(opts);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => { console.error('Error:', err.message); process.exitCode = 1; });
}