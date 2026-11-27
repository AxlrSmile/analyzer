/* Code Security Analyzer Web 1.3: browser-local experiment metadata only.
 * NO original/proposed source, API tokens, or full logs are saved.
 * Functional tests are user-declared; the website does not execute them.
 */
(function (root) {
  'use strict';
  const KEY = 'csa-web13-experiments-v1';
  const MAX_ROWS = 100;
  const STATES = new Set(['PASSED', 'FAILED', 'SKIPPED', 'NOT_CHECKED']);
  const CHECKS = new Set(['PASSED', 'FAILED', 'NOT_CHECKED']);
  const PREVIEW_STATES = new Set(['GENERATED', 'GENERATION_FAILED']);
  const SEMGREP_STATES = new Set(['COMPLETED', 'NOT_CHECKED']);
  const EVIDENCE = 'USER_DECLARED_EXTERNAL';
  const trim = (v, n = 160) => (typeof v === 'string' ? v.trim().slice(0, n) : '');
  const asInt = v => Number.isInteger(v) && v >= 0 && v <= 100000 ? v : null;
  const state = (v, set, fallback) => set.has(v) ? v : fallback;
  const hex = v => /^[0-9a-f]{64}$/i.test(String(v || '')) ? String(v).toLowerCase() : '';
  const iso = v => typeof v === 'string' && /^\d{4}-\d\d-\d\dT/.test(v) && !isNaN(Date.parse(v)) ? v : new Date().toISOString();
  function clean(record) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
    const id = trim(record.id, 100);
    const fileName = trim(record.fileName, 180);
    if (!id || !fileName) return null;
    const result = {
      id, createdAt: iso(record.createdAt), fileName,
      model: trim(record.model, 100), findingTitle: trim(record.findingTitle, 180),
      origin: trim(record.origin, 24), cwe: trim(record.cwe, 40), severity: trim(record.severity, 20),
      preview: state(record.preview, PREVIEW_STATES, 'GENERATION_FAILED'),
      compilation: state(record.compilation, CHECKS, 'NOT_CHECKED'),
      api: state(record.api, CHECKS, 'NOT_CHECKED'),
      overall: state(record.overall, CHECKS, 'NOT_CHECKED'),
      semgrepStatus: state(record.semgrepStatus, SEMGREP_STATES, 'NOT_CHECKED'),
      semgrepBefore: asInt(record.semgrepBefore), semgrepAfter: asInt(record.semgrepAfter),
      originalSha256: hex(record.originalSha256), proposalSha256: hex(record.proposalSha256),
      scenario1Name: trim(record.scenario1Name, 100) || 'Сценарий 1',
      scenario1: state(record.scenario1, STATES, 'NOT_CHECKED'),
      scenario2Name: trim(record.scenario2Name, 100) || 'Сценарий 2',
      scenario2: state(record.scenario2, STATES, 'NOT_CHECKED'),
      evidenceName: trim(record.evidenceName, 140), notes: trim(record.notes, 350),
      functionalSource: EVIDENCE
    };
    if (result.semgrepStatus !== 'COMPLETED') {
      result.semgrepBefore = null; result.semgrepAfter = null;
    }
    if (result.preview !== 'GENERATED') {
      result.proposalSha256 = ''; result.compilation = 'NOT_CHECKED';
      result.api = 'NOT_CHECKED'; result.overall = 'NOT_CHECKED';
      result.semgrepStatus = 'NOT_CHECKED'; result.semgrepBefore = null; result.semgrepAfter = null;
    }
    return result;
  }
  function fromPreview({ file, finding, model, response, originalHash, proposalHash, createdAt, id }) {
    const s = response?.semgrep || {};
    return clean({
      id: id || Date.now() + '-' + Math.random().toString(36).slice(2, 10),
      createdAt: createdAt || new Date().toISOString(),
      fileName: file?.name, model, findingTitle: finding?.title,
      origin: finding?.origin, cwe: finding?.cwe, severity: finding?.severity,
      preview: response ? 'GENERATED' : 'GENERATION_FAILED',
      compilation: response?.compilation, api: response?.api, overall: response?.overall,
      semgrepStatus: s.status, semgrepBefore: s.before, semgrepAfter: s.after,
      originalSha256: originalHash, proposalSha256: proposalHash,
      scenario1Name: 'Обычный сценарий', scenario2Name: 'Специальный ввод',
      scenario1: 'NOT_CHECKED', scenario2: 'NOT_CHECKED',
      functionalSource: EVIDENCE
    });
  }
  function outcome(record) {
    if (!record || record.preview === 'GENERATION_FAILED' || record.overall === 'FAILED') return 'REJECTED';
    if (record.overall !== 'PASSED' || record.semgrepStatus !== 'COMPLETED') return 'INCOMPLETE';
    if (record.scenario1 === 'FAILED' || record.scenario2 === 'FAILED') return 'MANUAL_FAILED';
    if (record.scenario1 === 'PASSED' && record.scenario2 === 'PASSED') return 'MANUAL_REPORTED_PASSED';
    return 'INCOMPLETE';
  }
  function load(storage) {
    try {
      const raw = JSON.parse(storage.getItem(KEY));
      if (!Array.isArray(raw)) return [];
      return raw.slice(0, MAX_ROWS).map(clean).filter(Boolean);
    } catch (_) { return []; }
  }
  function save(storage, records) {
    const safe = records.slice(0, MAX_ROWS).map(clean).filter(Boolean);
    storage.setItem(KEY, JSON.stringify(safe));
    return safe;
  }
  function csvValue(v) {
    const value = String(v ?? '');
    // Prevent spreadsheet formula injection even in user-provided filenames/notes.
    const neutral = /^[\s\u0000-\u001f]*[=+@\-\t\r]/.test(value) ? "'" + value : value;
    return '"' + neutral.replaceAll('"', '""') + '"';
  }
  const COLS = [
    ['createdAt','Дата UTC'], ['fileName','Файл'], ['model','Модель'], ['findingTitle','Находка'],
    ['origin','Источник'], ['cwe','CWE'], ['severity','Риск'], ['preview','Генерация'],
    ['compilation','Java'], ['api','API'], ['overall','Итог Java'],
    ['semgrepStatus','Статус Semgrep'], ['semgrepBefore','Semgrep до'], ['semgrepAfter','Semgrep после'],
    ['originalSha256','SHA-256 оригинала'], ['proposalSha256','SHA-256 предложения'],
    ['scenario1Name','Сценарий 1'], ['scenario1','Результат 1'],
    ['scenario2Name','Сценарий 2'], ['scenario2','Результат 2'],
    ['functionalSource','Источник функциональной оценки'], ['evidenceName','Имя файла лога'],
    ['notes','Примечание'], ['outcome','Сводный статус']
  ];
  function toCsv(records) {
    const safe = records.map(clean).filter(Boolean);
    return '\uFEFF' + COLS.map(([, title]) => csvValue(title)).join(',') + '\r\n' +
      safe.map(record => COLS.map(([key]) => csvValue(key === 'outcome' ? outcome(record) : record[key])).join(',')).join('\r\n') + '\r\n';
  }
  function toJson(records) {
    return JSON.stringify({ format:'code-security-web-experiments', version:1,
      exportedAt:new Date().toISOString(),
      note:'Functional statuses are user-declared, NOT executed by the website. No source code stored.',
      attempts:records.map(clean).filter(Boolean).map(record => ({...record, outcome:outcome(record)})) }, null, 2);
  }
  async function sha256(text) {
    if (!root.crypto?.subtle || typeof text !== 'string') return '';
    const bytes = new TextEncoder().encode(text);
    const hash = await root.crypto.subtle.digest('SHA-256', bytes);
    return [...new Uint8Array(hash)].map(x => x.toString(16).padStart(2, '0')).join('');
  }
  root.WebExperimentJournal = {KEY, MAX_ROWS, clean, fromPreview, outcome, load, save, csvValue, toCsv, toJson, sha256};
  if (typeof module !== 'undefined' && module.exports) module.exports = root.WebExperimentJournal;
})(typeof window !== 'undefined' ? window : globalThis);
