'use strict';
/* Web 1.7: read-only, evidence-aware dashboard projections.
 * Never equate a matching line, an LLM verdict, or a recognized defense with a proven result.
 * No browser storage, requests, source-code persistence, or benchmark ground truth.
 */
(function (root) {
  const MAX_ROWS = 500;
  const SEVERITIES = new Set(['HIGH', 'MEDIUM', 'LOW']);
  const ORIGINS = new Set(['LLM', 'Semgrep']);
  const EVIDENCE_WARNINGS = new Set(['EVIDENCE_UNVERIFIED', 'PARTIAL_RESPONSE']);
  const CWE_WARNINGS = new Set(['SOURCE_TITLE_CONFLICT', 'SOURCE_CWE_MISMATCH',
    'UNSUPPORTED_SQL_CLAIM', 'TITLE_ONLY_MISMATCH']);
  const safe = (value, max = 200) => typeof value === 'string' ? value.slice(0, max) : '';
  const validCwe = value => /^CWE-[1-9][0-9]{0,4}$/.test(safe(value).toUpperCase());

  function review(finding) {
    const diag = finding?.evidenceDiagnostic || {};
    const ai = safe(finding?.aiReview, 60);
    const mechanism = safe(diag.mechanismStatus, 60);
    const evidence = safe(diag.modelOutputStatus, 60);
    const advisor = safe(diag.cweAdvisorStatus, 60);
    const validation = safe(finding?.validation, 60);
    // The strongest *advisory* signal for a potential false positive is an explicit
    // defensive mechanism or a non-binding AI-review assessment.
    if (mechanism === 'DEFENSE_PRESENT' || ai === 'LIKELY_FALSE_POSITIVE') {
      return {code:'POSSIBLE_FP', label:'Возможный FP',
        note:'Отмечен защитный механизм или предварительное мнение ИИ. Это не доказательство ложной тревоги.'};
    }
    if (EVIDENCE_WARNINGS.has(evidence) ||
        (finding?.origin === 'LLM' && ['NEEDS_REVIEW','LOCATION_INFERRED'].includes(validation))) {
      return {code:'UNVERIFIED_EVIDENCE', label:'Непроверенная цитата',
        note:'Цитата или координаты LLM не прошли строгую сверку. Требуется ручная проверка.'};
    }
    if (CWE_WARNINGS.has(advisor)) {
      return {code:'CWE_CONFLICT', label:'Проверить CWE',
        note:'Категория CWE требует дополнительной сверки с исходным кодом.'};
    }
    return {code:'MANUAL_REVIEW', label:'Ручная проверка',
      note:'Автоматическое сообщение или совпадение цитаты не подтверждает реальную уязвимость.'};
  }

  function rows(report) {
    const out = [];
    for (const file of Array.isArray(report?.files) ? report.files : []) {
      if (!file || typeof file !== 'object') continue;
      for (const finding of Array.isArray(file.findings) ? file.findings : []) {
        if (!finding || typeof finding !== 'object') continue;
        if (out.length >= MAX_ROWS) return out;
        const severity = safe(finding.severity, 40).toUpperCase();
        const rawCwe = safe(finding.cwe, 30).toUpperCase();
        out.push({file, finding, severity:SEVERITIES.has(severity) ? severity : 'OTHER',
          cwe: validCwe(rawCwe) ? rawCwe : 'Без CWE',
          origin:ORIGINS.has(finding.origin) ? finding.origin : 'OTHER',
          review:review(finding)});
      }
    }
    return out;
  }
  function options(items) {
    return [...new Set(items)].sort((a,b)=>a.localeCompare(b,'ru'));
  }
  function filter(items, f = {}) {
    const query = safe(f.query, 120).trim().toLocaleLowerCase('ru');
    return items.filter(row => {
      if (f.severity && f.severity !== 'ALL' && row.severity !== f.severity) return false;
      if (f.cwe && f.cwe !== 'ALL' && row.cwe !== f.cwe) return false;
      if (f.origin && f.origin !== 'ALL' && row.origin !== f.origin) return false;
      if (f.review && f.review !== 'ALL' && row.review.code !== f.review) return false;
      if (query && ![row.file?.name, row.finding.title, row.finding.lines, row.cwe]
          .some(value => safe(value, 300).toLocaleLowerCase('ru').includes(query))) return false;
      return true;
    });
  }
  function summary(report, items = rows(report)) {
    const byOrigin = {LLM:0, Semgrep:0, OTHER:0};
    const byReview = {POSSIBLE_FP:0, UNVERIFIED_EVIDENCE:0, CWE_CONFLICT:0, MANUAL_REVIEW:0};
    for (const row of items) {
      byOrigin[row.origin]++;
      byReview[row.review.code]++;
    }
    return {total:items.length, byOrigin, byReview,
      filesScanned:Number.isInteger(report?.loadedFiles) ? report.loadedFiles :
        (Array.isArray(report?.files) ? report.files.length : 0),
      llmComplete:Number.isInteger(report?.llmComplete) ? report.llmComplete : 0,
      llmPartial:Number.isInteger(report?.llmPartial) ? report.llmPartial : 0,
      llmFailed:Number.isInteger(report?.llmFailed) ? report.llmFailed : 0,
      semgrepCompleted:report?.sastCompleted === true};
  }
  // Metadata-only totals from the existing Web 1.4 history; different uploads
  // are not an accuracy benchmark and are never automatically matched by file.
  function models(history) {
    const map = new Map();
    for (const item of Array.isArray(history) ? history.slice(0,60) : []) {
      if (!item || typeof item !== 'object') continue;
      const model = safe(item.model, 90) || 'Не указана';
      if (!map.has(model)) map.set(model,{model, runs:0, complete:0, limited:0,
        errors:0, signals:0, llmPartial:0, pairs:0});
      const row = map.get(model);
      row.runs++;
      if (item.status === 'COMPLETE') row.complete++;
      else if (item.status === 'LIMITED') row.limited++;
      else if (item.status === 'ERROR') row.errors++;
      const count = v => Number.isInteger(v) && v >= 0 && v <= 100000 ? v : 0;
      row.signals += count(item.signals);
      row.llmPartial += count(item.llmPartial);
      row.pairs += count(item.relatedPairs);
    }
    return [...map.values()].sort((a,b)=>b.runs-a.runs || a.model.localeCompare(b.model,'ru')).slice(0,20);
  }
  const api = Object.freeze({MAX_ROWS, review, rows, options, filter, summary, models});
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.WebReviewDashboard = api;
})(typeof window !== 'undefined' ? window : null);
