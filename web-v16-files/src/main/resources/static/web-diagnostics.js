'use strict';
/* Web 1.6: diagnostic projection is intentionally side-effect-free and never
   saves source code or internal evidence to localStorage. */
(function (root) {
  const CODES = new Set(['EVIDENCE_FORMAT', 'EVIDENCE_MISMATCH', 'EVIDENCE_NOT_VERIFIED',
    'PARTIAL_CANDIDATES', 'LOCATION_NEEDS_REVIEW', 'EVIDENCE_STATUS_UNKNOWN']);
  const STATUSES = new Set(['EVIDENCE_MATCHED', 'EVIDENCE_UNVERIFIED', 'PARTIAL_RESPONSE', 'NOT_ASSESSED']);
  const CWE = new Set(['CATEGORY_ALIGNED', 'SOURCE_HINT_UNVERIFIED_LOCATION',
    'SOURCE_TITLE_CONFLICT', 'SOURCE_CWE_MISMATCH', 'UNSUPPORTED_SQL_CLAIM',
    'TITLE_ONLY_MISMATCH', 'REVIEW_REQUIRED', 'NOT_ASSESSED']);
  const CWE_WARNINGS = new Set(['SOURCE_TITLE_CONFLICT', 'SOURCE_CWE_MISMATCH',
    'UNSUPPORTED_SQL_CLAIM', 'TITLE_ONLY_MISMATCH']);
  const safe = (value, max) => typeof value === 'string' ? value.slice(0, max) : '';
  function rows(report) {
    const files = Array.isArray(report?.files) ? report.files : [];
    const out = [];
    for (const file of files) {
      const findings = Array.isArray(file?.findings) ? file.findings : [];
      for (const finding of findings) {
        if (finding?.origin !== 'LLM') continue;
        const d = finding.evidenceDiagnostic || {};
        const status = STATUSES.has(d.modelOutputStatus) ? d.modelOutputStatus : 'NOT_ASSESSED';
        const code = CODES.has(d.reasonCode) ? d.reasonCode : '';
        const cweStatus = CWE.has(d.cweAdvisorStatus) ? d.cweAdvisorStatus : 'NOT_ASSESSED';
        const cweSuggestion = typeof d.cweSuggestion === 'string'
          && /^CWE-[1-9][0-9]{0,4}$/.test(d.cweSuggestion) ? d.cweSuggestion : '';
        const cweAlert = CWE_WARNINGS.has(cweStatus);
        const flagged = code !== '' || cweAlert || finding.validation === 'NEEDS_REVIEW'
          || finding.validation === 'LOCATION_INFERRED';
        if (!flagged) continue;
        out.push({
          file: safe(file.name, 250), title: safe(finding.title, 160),
          lines: safe(finding.lines, 60), status,
          code: code || (cweAlert ? 'CWE_ADVISORY' : 'UNKNOWN_QUALITY'),
          cweStatus, cweSuggestion,
          explanation: code ? safe(d.explanation, 450) : (cweAlert
            ? 'Исходный код и заявленная категория CWE могут противоречить друг другу. Это не подтверждение уязвимости.'
            : 'В ответе сервера нет подробной причины. Обновите backend Web 1.6 и повторите анализ.'),
          nextStep: code ? safe(d.nextStep, 320) : 'Проверьте находку и CWE вручную.'
        });
      }
    }
    return out.slice(0, 100);
  }
  function totals(report) {
    const list = rows(report);
    return Object.freeze({
      llmComplete: Math.max(0, Number(report?.llmComplete) || 0),
      llmPartial: Math.max(0, Number(report?.llmPartial) || 0),
      llmFailed: Math.max(0, Number(report?.llmFailed) || 0),
      details: list
    });
  }
  const api = Object.freeze({ rows, totals });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.WebLlmDiagnostics = api;
})(typeof window !== 'undefined' ? window : null);
