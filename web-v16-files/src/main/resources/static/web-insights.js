/* Web 1.4: metadata-only scan history and advisory correlation.
 * Never persist original code, proposed code, finding descriptions or absolute paths.
 * Similar LLM/Semgrep signals are candidates for review, not proven duplicate vulnerabilities.
 */
(function (root) {
  'use strict';
  const KEY = 'csa-web14-scan-history-v1';
  const MAX_ROWS = 60;
  const MAX_FINDINGS = 500;
  const SOURCE = new Set(['FILES', 'ZIP']);
  const STATUSES = new Set(['COMPLETE', 'LIMITED', 'ERROR']);
  const KINDS = ['CWE-89', 'CWE-22', 'CWE-78', 'CWE-79', 'CWE-611', 'CWE-502', 'CWE-798', 'CWE-918'];
  const safeStr = (v, max = 90) => typeof v === 'string' ? v.trim().slice(0, max) : '';
  const integer = (v, cap = 100000) => Number.isInteger(v) && v >= 0 && v <= cap ? v : 0;
  function clean(row) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) return null;
    const id = safeStr(row.id, 80);
    if (!id) return null;
    const when = typeof row.createdAt === 'string' && !Number.isNaN(Date.parse(row.createdAt))
      ? new Date(row.createdAt).toISOString() : new Date().toISOString();
    return {
      id, createdAt:when, model:safeStr(row.model, 90),
      inputKind:SOURCE.has(row.inputKind) ? row.inputKind : 'FILES',
      loadedFiles:integer(row.loadedFiles), signals:integer(row.signals),
      highSignals:integer(row.highSignals), llmComplete:integer(row.llmComplete),
      llmPartial:integer(row.llmPartial), llmFailed:integer(row.llmFailed),
      semgrepCompleted:row.semgrepCompleted === true,
      semgrepFindings:integer(row.semgrepFindings), diagnosticCount:integer(row.diagnosticCount),
      relatedPairs:integer(row.relatedPairs),
      status:STATUSES.has(row.status) ? row.status : 'LIMITED'
    };
  }
  function findings(report) {
    const out = [];
    for (const file of Array.isArray(report?.files) ? report.files : []) {
      for (const finding of Array.isArray(file?.findings) ? file.findings : []) {
        if (out.length >= MAX_FINDINGS) return out;
        if (file && finding && typeof finding === 'object') out.push({file, finding});
      }
    }
    return out;
  }
  function range(text) {
    const match = /^\s*(\d{1,5})(?:\s*[-–]\s*(\d{1,5}))?\s*$/.exec(String(text || ''));
    if (!match) return null;
    const begin = Number(match[1]), end = Number(match[2] || match[1]);
    return begin > 0 && end >= begin && end - begin <= 30 ? {begin, end} : null;
  }
  function category(finding) {
    const code = safeStr(finding?.cwe, 32).toUpperCase();
    if (KINDS.includes(code)) return code;
    // Semgrep rule families: a narrow advisory map, never a vulnerability verdict.
    const title = String(finding?.title || '').toLowerCase();
    if (/formatted-sql-string|sql-injection|sql\.injection/.test(title)) return 'CWE-89';
    if (/path-traversal|directory-traversal/.test(title)) return 'CWE-22';
    if (/command-injection|shell-injection/.test(title)) return 'CWE-78';
    if (/cross-site-scripting|\bxss\b/.test(title)) return 'CWE-79';
    if (/\bxxe\b|xml-external-entity/.test(title)) return 'CWE-611';
    if (/insecure-deseriali[sz]ation/.test(title)) return 'CWE-502';
    return '';
  }
  function distance(a, b) {
    if (a.end < b.begin) return b.begin - a.end;
    if (b.end < a.begin) return a.begin - b.end;
    return 0;
  }
  function relatedSignals(report) {
    const pairs = [];
    for (const file of Array.isArray(report?.files) ? report.files : []) {
      const all = Array.isArray(file?.findings) ? file.findings.slice(0, MAX_FINDINGS) : [];
      const candidates = [];
      for (let i = 0; i < all.length; i++) {
        if (all[i]?.origin !== 'LLM') continue;
        const cat = category(all[i]); const left = range(all[i]?.lines);
        if (!cat || !left) continue;
        for (let j = 0; j < all.length; j++) {
          if (all[j]?.origin !== 'Semgrep' || category(all[j]) !== cat) continue;
          const right = range(all[j]?.lines);
          if (!right) continue;
          const gap = distance(left, right);
          if (gap <= 2) candidates.push({file, llm:all[i], semgrep:all[j], cwe:cat, gap, i, j});
        }
      }
      candidates.sort((x,y) => x.gap - y.gap || x.i - y.i || x.j - y.j);
      const seenLLM = new Set(), seenSAST = new Set();
      for (const candidate of candidates) {
        if (seenLLM.has(candidate.i) || seenSAST.has(candidate.j)) continue;
        pairs.push({file:candidate.file, llm:candidate.llm, semgrep:candidate.semgrep,
          cwe:candidate.cwe, gap:candidate.gap});
        seenLLM.add(candidate.i); seenSAST.add(candidate.j);
      }
    }
    return pairs;
  }
  function summary(report) {
    const found = findings(report);
    const severity = {HIGH:0, MEDIUM:0, LOW:0, OTHER:0};
    const categories = new Map();
    for (const {finding} of found) {
      const sev = String(finding.severity || '').toUpperCase();
      severity[sev in severity ? sev : 'OTHER']++;
      // These are raw CWE labels from findings, not inferred certainty.
      const cwe = /^CWE-\d{1,5}$/i.test(finding.cwe || '') ? finding.cwe.toUpperCase() : 'Без CWE';
      categories.set(cwe, (categories.get(cwe) || 0) + 1);
    }
    return {total:found.length, severity,
      cwe:[...categories].sort((a,b) => b[1]-a[1] || a[0].localeCompare(b[0])).slice(0,8),
      related:relatedSignals(report)};
  }
  function fromReport(report, model, inputKind, createdAt = new Date().toISOString(), id = null) {
    const totals = summary(report);
    const diagnostics = Array.isArray(report?.diagnostics) ? report.diagnostics.length : 0;
    const llmPartial = integer(report?.llmPartial), llmFailed = integer(report?.llmFailed);
    const semgrepCompleted = report?.sastCompleted === true;
    return clean({ id:id || String(Date.now())+'-'+Math.random().toString(36).slice(2,9), createdAt,
      model, inputKind, loadedFiles:integer(report?.loadedFiles), signals:totals.total,
      highSignals:totals.severity.HIGH, llmComplete:integer(report?.llmComplete), llmPartial,
      llmFailed, semgrepCompleted, semgrepFindings:integer(report?.sastFindings),
      diagnosticCount:diagnostics, relatedPairs:totals.related.length,
      status:semgrepCompleted && !llmPartial && !llmFailed && !diagnostics ? 'COMPLETE' : 'LIMITED' });
  }
  function fromFailure(model, inputKind, createdAt = new Date().toISOString(), id = null) {
    return clean({id:id || String(Date.now())+'-'+Math.random().toString(36).slice(2,9),
      createdAt, model, inputKind, status:'ERROR', diagnosticCount:1});
  }
  function load(storage) {
    try {
      const v = JSON.parse(storage.getItem(KEY));
      return Array.isArray(v) ? v.slice(0,MAX_ROWS).map(clean).filter(Boolean) : [];
    } catch (_) {return [];}
  }
  function save(storage, rows) {
    const sanitized = rows.slice(0,MAX_ROWS).map(clean).filter(Boolean);
    storage.setItem(KEY, JSON.stringify(sanitized));
    return sanitized;
  }
  function csvValue(raw) {
    const input = String(raw ?? '');
    const value = /^[\s\u0000-\u001f]*[=+@\-\t\r]/.test(input) ? "'" + input : input;
    return '"' + value.replaceAll('"','""') + '"';
  }
  const COLS = [
    ['createdAt','Дата UTC'],['model','Модель'],['inputKind','Тип загрузки'],
    ['loadedFiles','Файлов'],['signals','Сигналов'],['highSignals','HIGH'],
    ['relatedPairs','Совпадения для ручной проверки'],['llmComplete','LLM завершено'],
    ['llmPartial','LLM частично'],['llmFailed','LLM ошибок'],
    ['semgrepCompleted','Semgrep завершён'],['semgrepFindings','Semgrep сигналов'],
    ['diagnosticCount','Диагностик'],['status','Статус']
  ];
  function toCsv(rows) {
    const cleanRows = rows.map(clean).filter(Boolean);
    return '\uFEFF'+COLS.map(([,name])=>csvValue(name)).join(',')+'\r\n'+
      cleanRows.map(r => COLS.map(([key])=>csvValue(r[key])).join(',')).join('\r\n')+'\r\n';
  }
  function toJson(rows) {
    return JSON.stringify({format:'code-security-web-scan-history',version:1,
      exportedAt:new Date().toISOString(),
      note:'Metadata only: no source code, LLM proposals, finding evidence or user file paths. Related pairs are advisory.',
      scans:rows.map(clean).filter(Boolean)},null,2);
  }
  function htmlEscape(v) {
    return String(v ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;')
      .replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');
  }
  function toReportHtml(report, model = '') {
    const totals = summary(report);
    const files = Array.isArray(report?.files) ? report.files : [];
    const rows = findings(report).map(({file,finding}) => '<tr>' +
      [file.name, finding.title, finding.origin, finding.severity,
        finding.cwe || '—', finding.lines || '—', finding.validation || 'NOT_CHECKED',
        finding.evidenceDiagnostic?.reasonCode || '—']
        .map(v => '<td>'+htmlEscape(v)+'</td>').join('') + '</tr>').join('');
    const sev = Object.entries(totals.severity).map(([name,n]) =>
      '<li>'+htmlEscape(name)+': '+n+'</li>').join('');
    const cwe = totals.cwe.map(([name,n])=>'<li>'+htmlEscape(name)+': '+n+'</li>').join('');
    const related = totals.related.map(x => '<li>'+htmlEscape(x.file.name)+' · '+htmlEscape(x.cwe)+
      ' · LLM '+htmlEscape(x.llm.lines)+' / Semgrep '+htmlEscape(x.semgrep.lines)+'</li>').join('');
    const status = report?.sastCompleted === true && integer(report?.llmPartial) === 0 &&
      integer(report?.llmFailed) === 0 && !((report?.diagnostics||[]).length) ? 'COMPLETE' : 'LIMITED';
    return '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'+
      '<title>Code Security Analyzer — отчёт об аудите</title><style>'+ 
      'body{font:14px/1.5 Arial,sans-serif;color:#17263e;margin:28px auto;max-width:1000px;padding:0 18px}'+
      'h1{font-size:24px}h2{font-size:17px;margin-top:28px}p{color:#445575}'+
      'table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #c7d1df;text-align:left;padding:8px;vertical-align:top;overflow-wrap:anywhere}'+
      'th{background:#ebf1f8}ul{columns:2}li{break-inside:avoid}small{color:#5f718b}'+
      '@media print{body{margin:0;padding:0}tr{break-inside:avoid}}</style></head><body>'+ 
      '<h1>Code Security Analyzer · отчёт об аудите</h1>'+ 
      '<p>Дата (UTC): '+htmlEscape(new Date().toISOString())+'<br>LLM: '+htmlEscape(model)+
      '<br>Файлов: '+integer(report?.loadedFiles)+' · Сигналов: '+totals.total+
      ' · HIGH: '+totals.severity.HIGH+' · Semgrep: '+(report?.sastCompleted ? 'завершён':'не завершён')+
      ' · Статус полноты: '+status+'</p>'+ 
      '<p><strong>Ограничения:</strong> количество сигналов не равно количеству доказанных уязвимостей; '+
      'LLM и Semgrep могут ошибаться; отсутствующие находки не означают безопасность. '+
      'Оригинальный исходный код и предложенные исправления в отчёт не включены.</p>'+ 
      '<h2>Сигналы по критичности</h2><ul>'+sev+'</ul>'+ 
      '<h2>Категории CWE, указанные анализаторами</h2><ul>'+cwe+'</ul>'+ 
      '<h2>Предполагаемые совпадения для ручной проверки ('+totals.related.length+')</h2>'+ 
      '<p>Соседние строки и совпадающая категория не доказывают, что сигналы относятся к одной уязвимости.</p><ul>'+related+'</ul>'+ 
      '<h2>Первичные сигналы ('+totals.total+')</h2><table><thead><tr>'+ 
      ['Файл','Находка','Источник','Риск','CWE','Строки','Проверка','Причина LLM'].map(v=>'<th>'+v+'</th>').join('')+
      '</tr></thead><tbody>'+rows+'</tbody></table>'+ 
      '<p><small>Сформировано локальным прототипом Web 1.6. Не является сертификатом безопасности.</small></p></body></html>';
  }
  root.WebScanInsights = {KEY,MAX_ROWS,clean,findings,range,category,relatedSignals,summary,
    fromReport,fromFailure,load,save,toCsv,toJson,csvValue,toReportHtml};
  if (typeof module !== 'undefined' && module.exports) module.exports = root.WebScanInsights;
})(typeof window !== 'undefined' ? window : globalThis);
