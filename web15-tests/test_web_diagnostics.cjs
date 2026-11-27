'use strict';
const assert = require('node:assert/strict');
const d = require('../web-v15-files/src/main/resources/static/web-diagnostics.js');
const report = {
  llmComplete: 0, llmPartial: 1, llmFailed: 0,
  files: [{ name:'Case008.java', source:'secret=VERY_PRIVATE;', findings:[
    { origin:'LLM', title:'SQL Injection', lines:'5', validation:'NEEDS_REVIEW',
      evidenceDiagnostic:{modelOutputStatus:'EVIDENCE_UNVERIFIED',reasonCode:'EVIDENCE_MISMATCH',
        explanation:'Цитата не совпадает.',nextStep:'Проверить вручную.'} },
    { origin:'Semgrep', title:'SAST', lines:'6', evidenceDiagnostic:{reasonCode:'SAST_SIGNAL'} }
  ]}]
};
assert.equal(d.totals(report).llmPartial, 1);
const rows=d.rows(report);
assert.equal(rows.length, 1);
assert.equal(rows[0].code,'EVIDENCE_MISMATCH');
assert.equal(rows[0].lines,'5');
assert.ok(!JSON.stringify(rows).includes('VERY_PRIVATE'));
assert.equal(d.rows({files:[{name:'x',findings:[{origin:'LLM',validation:'LOCATION_CHECKED',
  evidenceDiagnostic:{reasonCode:'CITATION_MATCHED',modelOutputStatus:'EVIDENCE_MATCHED'}}]}]}).length,0);
const fallback=d.rows({files:[{name:'x',findings:[{origin:'LLM',validation:'NEEDS_REVIEW'}]}]});
assert.equal(fallback[0].code,'UNKNOWN_QUALITY');
assert.ok(fallback[0].explanation.includes('backend Web 1.5'));
console.log('Web 1.5 diagnostic JS tests: PASS');
