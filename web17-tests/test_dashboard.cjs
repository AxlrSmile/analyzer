'use strict';
const assert = require('node:assert/strict');
const D = require('../web-v17-files/src/main/resources/static/web-dashboard.js');
const Q = require('../web-v17-files/src/main/resources/static/web-insights.js');
const made = (name,findings) => ({name, source:'PRIVATE_SOURCE_DO_NOT_EXPORT',findings});
const llm = (title,overrides={}) => ({origin:'LLM',title,severity:'HIGH',cwe:'CWE-89',
  lines:'5',validation:'LOCATION_CHECKED',aiReview:'NOT_REVIEWED',
  evidenceDiagnostic:{modelOutputStatus:'EVIDENCE_MATCHED',reasonCode:'CITATION_MATCHED',
    mechanismStatus:'RELEVANT_PATTERN',cweAdvisorStatus:'CATEGORY_ALIGNED'}, ...overrides});
const sast = {origin:'Semgrep',title:'formatted-sql-string',severity:'HIGH',cwe:'',lines:'6',
 validation:'SAST_REPORTED',aiReview:'NEEDS_REVIEW'};
const report = {loadedFiles:2,llmComplete:2,llmPartial:0,llmFailed:0,sastCompleted:true,
  files:[made('Case008.java',[llm('SQL Injection'),sast]), made('Case011.java',[
    llm('SQL Injection',{evidenceDiagnostic:{modelOutputStatus:'EVIDENCE_MATCHED',
      reasonCode:'CITATION_MATCHED',mechanismStatus:'DEFENSE_PRESENT',cweAdvisorStatus:'CATEGORY_ALIGNED'}})])]};
const rows=D.rows(report);
assert.equal(rows.length,3);
assert.equal(D.summary(report).byOrigin.LLM,2);
assert.equal(D.summary(report).byOrigin.Semgrep,1);
assert.equal(D.summary(report).byReview.POSSIBLE_FP,1);
assert.equal(D.review(rows[2].finding).code,'POSSIBLE_FP');
assert.equal(D.review(sast).code,'MANUAL_REVIEW');
assert.equal(D.filter(rows,{origin:'Semgrep'}).length,1);
assert.equal(D.filter(rows,{cwe:'Без CWE'}).length,1);
assert.equal(D.filter(rows,{severity:'HIGH'}).length,3);
assert.equal(D.filter(rows,{review:'POSSIBLE_FP'})[0].file.name,'Case011.java');
assert.equal(D.filter(rows,{query:'cASe011'}).length,1);
assert.equal(D.filter(rows,{query:'no-match'}).length,0);
assert.equal(D.filter(rows,{origin:'LLM',review:'POSSIBLE_FP'}).length,1);
assert.equal(D.filter(rows,{origin:'Semgrep',review:'POSSIBLE_FP'}).length,0);
const snap=JSON.stringify(report); D.filter(rows,{review:'POSSIBLE_FP'}); assert.equal(JSON.stringify(report),snap);
const partial = llm('SQL Injection',{validation:'NEEDS_REVIEW',evidenceDiagnostic:{modelOutputStatus:'EVIDENCE_UNVERIFIED',reasonCode:'EVIDENCE_MISMATCH',mechanismStatus:'UNVERIFIED_LOCATION'}});
assert.equal(D.review(partial).code,'UNVERIFIED_EVIDENCE');
const conflicting = llm('bad CWE',{evidenceDiagnostic:{modelOutputStatus:'EVIDENCE_MATCHED',cweAdvisorStatus:'SOURCE_CWE_MISMATCH',mechanismStatus:'RELEVANT_PATTERN'}});
assert.equal(D.review(conflicting).code,'CWE_CONFLICT');
assert.equal(D.review({...sast,aiReview:'LIKELY_FALSE_POSITIVE'}).code,'POSSIBLE_FP');
assert.equal(D.rows({files:[]}).length,0);
assert.equal(D.rows({files:[null, {name:'x',findings:[null,{}]}]}).length,1);
const lots=Array.from({length:700},(_,i)=>llm('n'+i));
assert.equal(D.rows({files:[made('many',lots)]}).length,D.MAX_ROWS);
assert.deepEqual(D.options(['Без CWE','CWE-89','CWE-89']),['Без CWE','CWE-89']);
const escaped=made('evil<script>alert(1)</script>.java',[llm('evil<img onerror=alert(1)>')]);
const reportHtml=Q.toReportHtml({...report,files:[escaped]},'mistral<unsafe>');
assert.ok(reportHtml.includes('mistral&lt;unsafe&gt;'));
assert.ok(reportHtml.includes('evil&lt;script&gt;'));
assert.ok(!reportHtml.includes('PRIVATE_SOURCE_DO_NOT_EXPORT'));
assert.ok(!reportHtml.includes('title>evil<img'));
assert.ok(reportHtml.includes('Precision, Recall и F1'));
assert.equal(Q.relatedSignals(report).length,1); // original cross-source signals retained
assert.equal(rows.length,3); // filtering does not deduplicate findings
const aggregate=D.models([{model:'mistral:7b',status:'COMPLETE',signals:2,llmPartial:0,relatedPairs:1},
 {model:'qwen2.5-coder:7b',status:'LIMITED',signals:2,llmPartial:1},
 {model:'mistral:7b',status:'COMPLETE',signals:1,llmPartial:0}]);
assert.equal(aggregate.length,2);
assert.equal(aggregate[0].runs,2);
assert.equal(aggregate[0].signals,3);
assert.equal(aggregate[1].llmPartial,1);
assert.ok(!JSON.stringify(aggregate).includes('PRIVATE_SOURCE_DO_NOT_EXPORT'));
console.log('Web 1.7 dashboard tests: PASS (24 assertions + safety invariants)');
