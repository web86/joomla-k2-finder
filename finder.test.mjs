import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  normalizeDomain, loadDomains, csvParse, csvStringify, publicIp,
  robotsAllowed, parsePage, parseJoomlaManifest, classify, scanDomain,
  isRussianDomain, parseDomainRecords, normalizeCachedRow, eligibleLead, prospectPriority, runBatch
} from './finder.mjs';

test('normalizes domains, IDNs, rejects local hosts and IPs', () => {
  assert.equal(normalizeDomain('https://a-a.ru/kompaniya?x=1'), 'a-a.ru');
  assert.equal(normalizeDomain('ПРИМЕР.РФ'), 'xn--e1afmkfd.xn--p1ai');
  for (const x of ['localhost', '127.0.0.1', '192.168.0.1', 'http://x.ru:8080/', 'https://test.local/', 'ftp://a.ru'])
    assert.equal(normalizeDomain(x), null, x);
  assert.equal(publicIp('8.8.8.8'), true);
  assert.equal(publicIp('10.1.2.3'), false);
  assert.equal(publicIp('::1'), false);
  assert.equal(publicIp('::ffff:192.168.1.1'), false);
});

test('reads plain domains or CSV with quoted cells and unicode', () => {
  assert.deepEqual(loadDomains('a-a.ru\na-a.ru\n# note\nhttps://rocun.ru/path'), ['a-a.ru','rocun.ru']);
  assert.deepEqual(loadDomains('domain,notes\na-a.ru,"Legal, Russia"\nrocun.ru,"Service"'), ['a-a.ru', 'rocun.ru']);
  const csv = csvStringify([{ domain:'a.ru', evidence:'a "quoted", reason', contact_url:'https://a.ru/' }], ['domain','evidence','contact_url']);
  assert.equal(csvParse(csv)[1][1], 'a "quoted", reason');
});

test('respects robots groups, Allow specificity, wildcard and $', () => {
  const robots = `User-agent: *\nDisallow: /private\nDisallow: /*?secret=\nAllow: /private/open\n\nUser-agent: JoomlaK2Finder\nDisallow: /administrator/\nAllow: /administrator/manifests/files/joomla.xml$`;
  assert.equal(robotsAllowed(robots, '/private'), true); // more-specific UA overrides *
  assert.equal(robotsAllowed(robots, '/administrator/index.php'), false);
  assert.equal(robotsAllowed(robots, '/administrator/manifests/files/joomla.xml'), true);
  assert.equal(robotsAllowed(robots, '/administrator/manifests/files/joomla.xml/more'), false);
  const global = 'User-agent: *\nDisallow: /private\nAllow: /private/open\nDisallow: /*?secret=';
  assert.equal(robotsAllowed(global, '/private/x'), false);
  assert.equal(robotsAllowed(global, '/private/open/x'), true);
  assert.equal(robotsAllowed(global, '/search?secret=123'), false);
});

test('recognizes K2 evidence and old Joomla patterns, extracts contact URL', () => {
  const page = parsePage(`<!doctype html><title>Юридическая компания</title>
    <meta content="Joomla! 3.10.12 - Open Source" name="generator" />
    <script src="/media/jui/js/jquery.min.js"></script>
    <a href="/component/k2/item/123-test">Каталог</a>
    <img src="/media/k2/items/cache/test.jpg">
    <a href="/kontakty/">Контакты</a>`, 'https://legal.ru/');
  assert.equal(page.title, 'Юридическая компания');
  assert.equal(page.versionFromMeta, '3.10.12');
  assert.equal(page.kinds.has('k2'), true);
  assert.equal(page.contactUrl, 'https://legal.ru/kontakty/');
  assert.ok(page.links.includes('https://legal.ru/component/k2/item/123-test'));
  const classification = classify([page]);
  assert.equal(classification.joomla_version, '3.10.12');
  assert.equal(classification.priority, 'high');
});

test('manifest parsed only if it identifies Joomla core, not K2', () => {
  assert.equal(parseJoomlaManifest('<extension type="file"><name>files_joomla</name><version>3.10.12</version></extension>'), '3.10.12');
  assert.equal(parseJoomlaManifest('<extension type="component"><name>COM_K2</name><version>2.28</version></extension>'), '');
  const p = parsePage('<link href="/templates/protostar/css/template.css">', 'https://a.ru/');
  assert.equal(classify([p], '4.4.14').version_confidence, 'high');
  const conflict = parsePage('<meta name="generator" content="Joomla! 3.10.12">', 'https://a.ru/');
  assert.equal(classify([conflict], '4.4.14').version_confidence, 'conflict');
});

test('mocked scan finds K2 on second public page and public core manifest', async () => {
  const hits = [];
  const responses = new Map([
    ['https://company.ru/robots.txt', new Response('User-agent: *\nDisallow: /secret', { status:200, headers:{'content-type':'text/plain'} })],
    ['https://company.ru/', new Response('<title>Company</title><a href="/catalog/">Catalog</a><a href="/contacts/">Contacts</a>', { headers:{'content-type':'text/html'} })],
    ['https://company.ru/catalog/', new Response('<title>Catalog</title><img src="/media/k2/items/img.jpg"><a href="/component/k2/item/12">Detail</a>', { headers:{'content-type':'text/html'} })],
    ['https://company.ru/administrator/manifests/files/joomla.xml', new Response('<extension type="file"><name>files_joomla</name><version>3.10.12</version></extension>', { headers:{'content-type':'application/xml'} })]
  ]);
  const result = await scanDomain('company.ru', { delay:0, maxPages:2, manifest:true }, {
    dnsLookup:async () => [{ address:'8.8.8.8' }],
    fetchImpl:async url => { hits.push(url); return responses.get(url)?.clone() ?? new Response('', {status:404}); }
  });
  assert.equal(result.scan_status, 'ok');
  assert.equal(result.k2_detected, 'yes');
  assert.equal(result.joomla_version, '3.10.12');
  assert.equal(result.version_source, 'public_core_manifest');
  assert.equal(result.pages_checked, 2);
  assert.equal(result.contact_url, 'https://company.ru/contacts/');
  assert.equal(result.priority, 'high');
  assert.ok(hits.includes('https://company.ru/robots.txt'));
});

test('mocked scan obeys robots for homepage and never fetches HTML', async () => {
  const hits = [];
  const result = await scanDomain('blocked.ru', {delay:0}, {
    dnsLookup:async () => [{address:'8.8.8.8'}],
    fetchImpl: async url => { hits.push(url); return new Response('User-agent: *\nDisallow: /', {headers:{'content-type':'text/plain'}}); }
  });
  assert.equal(result.scan_status, 'error');
  assert.match(result.error, /robots_disallowed/);
  assert.deepEqual(hits, ['https://blocked.ru/robots.txt']);
});


test('Russian-domain suffix, IDN and manually supplied company categories', () => {
  assert.equal(isRussianDomain('company.ru'), true);
  assert.equal(isRussianDomain('company.ru.com'), false);
  assert.equal(isRussianDomain('xn--e1afmkfd.xn--p1ai'), true);
  assert.equal(isRussianDomain('company.com'), false);
  const rows = parseDomainRecords('domain,company_name,business_type\na-a.ru,Адвок-Авто,business\ntake-off.ru,Издание,media\nexample.org,X,ngo');
  assert.equal(rows.length, 3);
  assert.deepEqual(rows[0], { domain: 'a-a.ru', company_name: 'Адвок-Авто', business_type: 'business' });
  assert.equal(rows[1].business_type, 'media');
});

test('legacy failed scans are unknown rather than Joomla/K2 negatives', () => {
  const old = normalizeCachedRow({ domain:'farm-treid.ru', scan_status:'error',
    joomla_detected:'false', k2_detected:'false', error:'fetch failed', priority:'low' });
  assert.equal(old.k2_detected, 'unknown');
  assert.equal(old.joomla_detected, 'unknown');
  assert.equal(eligibleLead(old), false);
  const detected = normalizeCachedRow({ domain:'a-a.ru', scan_status:'ok',
    joomla_detected:'true', k2_detected:'true', priority:'medium',
    version_confidence:'low' });
  assert.equal(detected.k2_detected, 'yes');
  assert.equal(detected.lead_priority, 'review');
});

test('leads require K2 evidence and Russian domain; media are excluded', () => {
  const row = {domain:'company.ru', scan_status:'ok', k2_detected:'yes',
    technical_priority:'high', version_confidence:'medium', contact_url:'https://company.ru/contacts'};
  assert.equal(prospectPriority({...row,business_type:'unknown'}), 'review');
  assert.equal(prospectPriority({...row,business_type:'business'}), 'high');
  assert.equal(eligibleLead({...row,business_type:'business'}), true);
  assert.equal(eligibleLead({...row,business_type:'media'}), false);
  assert.equal(eligibleLead({...row,domain:'company.com',business_type:'business'}), false);
  assert.equal(eligibleLead({...row,k2_detected:'unknown',business_type:'business'}), false);
});

test('batch resumes from existing v1 report, retries errors only, creates ordered leads', async () => {
  const dir = await mkdtemp(join(tmpdir(),'k2-finder-'));
  const input = join(dir,'companies.csv'), output = join(dir,'results.csv'), leads = join(dir,'leads.csv');
  await writeFile(input,'domain,company_name,business_type\na-a.ru,Legal,business\nother.ru,Other,business\nnews.ru,Media,media\nforeign.com,US,business');
  const cached = [
    { domain:'a-a.ru', scan_status:'ok', k2_detected:true, joomla_detected:true, priority:'medium', version_confidence:'low', contact_url:'https://a-a.ru/contacts' },
    { domain:'other.ru', scan_status:'error', k2_detected:false, joomla_detected:false, priority:'low', error:'fetch failed' }
  ];
  await writeFile(output, csvStringify(cached, ['domain','scan_status','k2_detected','joomla_detected','priority','version_confidence','contact_url','error']));
  let called = [];
  const scan = async domain => {
    called.push(domain);
    return {domain,scan_status:'ok',k2_detected:'yes',joomla_detected:'yes',
      k2_confidence:'high',joomla_version:'3.x',version_confidence:'medium',version_source:'frontend_assets',
      technical_priority:'medium',contact_url:`https://${domain}/contacts`,evidence:'K2:option=com_k2'};
  };
  const options = {input, output, leads, ruOnly:true, retryErrors:false, fresh:false, maxSites:100};
  const first = await runBatch(options, {scan});
  assert.deepEqual(called,['news.ru']); // existing error is cached until --retry-errors
  assert.equal(first.scanned,1);
  assert.equal(first.leads.length,1);
  assert.equal(first.leads[0].domain,'a-a.ru');
  assert.equal(first.results.find(x=>x.domain==='other.ru').k2_detected,'unknown');
  const second = await runBatch({...options,retryErrors:true},{scan});
  assert.deepEqual(called,['news.ru','other.ru']);
  assert.equal(second.scanned,1);
  assert.equal(second.leads.length,2);
  const csv = csvParse(await readFile(leads,'utf8'));
  assert.equal(csv.length,3);
  assert.equal(second.results.find(x=>x.domain==='other.ru').business_type,'business');
});

test('CSV writes neutralize formula-like titles', () => {
  const csv = csvStringify([{domain:'test.ru',site_title:'=HYPERLINK(\"x\")'}], ['domain','site_title']);
  assert.ok(csv.includes("'=HYPERLINK"));
});

test('detects OpenCart 2-style storefront assets without inventing an exact version', () => {
  const p = parsePage('<link href="/catalog/view/theme/default/stylesheet/stylesheet.css">' +
    '<script src="/catalog/view/javascript/common.js"></script>' +
    '<a href="index.php?route=product/product&product_id=9">Product</a>', 'https://shop.ru/');
  const result = classify([p]);
  assert.equal(result.opencart_detected, 'yes');
  assert.equal(result.opencart_confidence, 'high');
  assert.equal(result.opencart_legacy, 'possible');
  assert.equal(result.opencart_version_confidence, 'low');
  assert.equal(result.opencart_version, '1.x–3.x (asset hypothesis)');
  assert.equal(result.k2_detected, 'no');
  assert.equal(result.technical_priority, 'medium');
  assert.equal(eligibleLead({...result, domain:'shop.ru', scan_status:'ok'}), true);
});

test('generator version distinguishes obsolete OpenCart from current storefront', () => {
  const old = classify([parsePage('<meta name="generator" content="OpenCart 2.1.0.2">' +
    '<a href="index.php?route=product/product&product_id=2">View</a>', 'https://old.ru/')]);
  assert.equal(old.opencart_version, '2.1.0.2');
  assert.equal(old.opencart_legacy, 'yes');
  assert.equal(old.opencart_version_confidence, 'high');
  assert.equal(old.technical_priority, 'high');
  const modern = classify([parsePage('<meta name="generator" content="OpenCart 4.1.0.3">', 'https://modern.ru/')]);
  assert.equal(modern.opencart_detected, 'yes');
  assert.equal(modern.opencart_legacy, 'no');
  assert.equal(modern.technical_priority, 'low');
  assert.equal(eligibleLead({...modern, domain:'modern.ru', scan_status:'ok'}), false);
});

test('generic OpenCart routes are not sufficient on their own; conflicting assets need review', () => {
  const onlyRoute = classify([parsePage('<a href="index.php?route=product/product&product_id=7">Item</a>', 'https://a.ru/')]);
  assert.equal(onlyRoute.opencart_detected, 'no');
  const conflict = classify([parsePage('<meta name="generator" content="OpenCart 4.0.2.3">' +
    '<link href="/catalog/view/theme/default/stylesheet/stylesheet.css">', 'https://b.ru/')]);
  assert.equal(conflict.opencart_version_confidence, 'conflict');
  assert.equal(conflict.opencart_legacy, 'unknown');
  assert.equal(eligibleLead({...conflict, domain:'b.ru', scan_status:'ok'}), false);
});

test('old CSV remains unknown for OpenCart and rescans only when requested', async () => {
  const old = normalizeCachedRow({domain:'a.ru',scan_status:'ok',joomla_detected:'no',
    k2_detected:'no',priority:'low'});
  assert.equal(old.opencart_detected, 'unknown');
  assert.equal(old.opencart_legacy, 'unknown');
  assert.equal(eligibleLead(old), false);
  const dir = await mkdtemp(join(tmpdir(),'legacy-cms-'));
  const input = join(dir,'input.txt'), output=join(dir,'results.csv'), leads=join(dir,'leads.csv');
  await writeFile(input,'a.ru');
  await writeFile(output,csvStringify([old]));
  const called=[];
  const scan=async domain=> { called.push(domain); return {domain,scan_status:'ok',opencart_detected:'yes',
    opencart_confidence:'high',opencart_legacy:'possible',opencart_version:'1.x–3.x (asset hypothesis)',
    opencart_version_confidence:'low',k2_detected:'no',technical_priority:'medium'}; };
  const opts={input,output,leads,ruOnly:true,retryErrors:false,fresh:false,maxSites:10};
  const first=await runBatch(opts,{scan});
  assert.equal(first.scanned,0);
  const second=await runBatch({...opts,rescanOpenCart:true},{scan});
  assert.equal(second.scanned,1);
  assert.deepEqual(called,['a.ru']);
  assert.equal(second.leads.length,1);
  assert.equal(second.leads[0].lead_technology,'opencart_legacy');
});
