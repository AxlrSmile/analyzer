const assert = require('node:assert/strict');
const d = require('../web-v16-files/src/main/resources/static/web-diagnostics.js');
const report = {llmComplete:0,llmPartial:1,llmFailed:0,files:[{name:'Case008.java',source:'private SECRET_CODE',findings:[
 {origin:'LLM',title:'SQL Injection',lines:'5',validation:'NEEDS_REVIEW',
  evidenceDiagnostic:{modelOutputStatus:'EVIDENCE_UNVERIFIED',reasonCode:'EVIDENCE_MISMATCH',
  explanation:'Цитата не совпадает',nextStep:'Проверить',cweAdvisorStatus:'SOURCE_HINT_UNVERIFIED_LOCATION',cweSuggestion:'CWE-89',mechanismStatus:'UNVERIFIED_LOCATION'}},
 {origin:'Semgrep',title:'SQL Injection',evidenceDiagnostic:{reasonCode:'SAST_SIGNAL',cweAdvisorStatus:'SOURCE_CWE_MISMATCH'}}
]}]};
const rows = d.rows(report);
assert.equal(rows.length,1);
assert.equal(rows[0].cweSuggestion,'CWE-89');
assert.equal(rows[0].code,'EVIDENCE_MISMATCH');
assert.equal(d.totals(report).llmPartial,1);
assert.ok(!JSON.stringify(rows).includes('SECRET_CODE'));
const mismatch=d.rows({files:[{name:'x',findings:[{origin:'LLM',title:'Bad category',validation:'LOCATION_CHECKED',
 evidenceDiagnostic:{modelOutputStatus:'EVIDENCE_MATCHED',reasonCode:'CITATION_MATCHED',cweAdvisorStatus:'SOURCE_CWE_MISMATCH',cweSuggestion:'CWE-78'}}]}]});
assert.equal(mismatch.length,1);
assert.equal(mismatch[0].code,'CWE_ADVISORY');
assert.equal(mismatch[0].cweStatus,'SOURCE_CWE_MISMATCH');
const rejected=d.rows({files:[{name:'x',findings:[{origin:'LLM',evidenceDiagnostic:{
 reasonCode:'CITATION_MATCHED',modelOutputStatus:'EVIDENCE_MATCHED',cweAdvisorStatus:'SECRET_VALUE',cweSuggestion:'CWE-89-PASSWORD'}}]}]});
assert.equal(rejected.length,0);
console.log('Web 1.6 UI metadata tests: PASS');
