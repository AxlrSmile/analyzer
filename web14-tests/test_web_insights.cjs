'use strict';
const assert = require('node:assert/strict');
const I = require('../web-v14-files/src/main/resources/static/web-insights.js');
const src = 'SECRET_SOURCE_DO_NOT_PERSIST';
const example = { loadedFiles:2, llmComplete:1, llmPartial:1, llmFailed:0,
  sastCompleted:true, sastFindings:1, diagnostics:['Unverified code evidence: '+src],
  files:[
    {name:'Case008.java',source:src,findings:[
      {origin:'LLM',title:'SQL Injection',severity:'HIGH',cwe:'CWE-89',lines:'5',description:src,validation:'NEEDS_REVIEW'},
      {origin:'Semgrep',title:'Semgrep: java.lang.security.audit.formatted-sql-string.formatted-sql-string',severity:'HIGH',cwe:'',lines:'6',description:src,validation:'SAST_REPORTED'}]},
    {name:'Case011.java',source:src,findings:[
      {origin:'LLM',title:'Possible SQL Injection',severity:'MEDIUM',cwe:'CWE-89',lines:'5',description:src,validation:'NEEDS_REVIEW'}]}
  ]};
const pairs=I.relatedSignals(example);
assert.equal(pairs.length,1);
assert.equal(pairs[0].file.name,'Case008.java');
assert.equal(pairs[0].cwe,'CWE-89');
assert.equal(pairs[0].llm.lines,'5');
assert.equal(pairs[0].semgrep.lines,'6');
assert.equal(I.summary(example).total,3);
assert.deepEqual(I.summary(example).severity,{HIGH:2,MEDIUM:1,LOW:0,OTHER:0});
const history=I.fromReport(example,'qwen2.5-coder:7b','ZIP','2026-11-15T10:00:00Z','x1');
assert.equal(history.loadedFiles,2);assert.equal(history.signals,3);
assert.equal(history.relatedPairs,1);assert.equal(history.status,'LIMITED');
assert.equal(history.inputKind,'ZIP');
assert.equal(history.model,'qwen2.5-coder:7b');
assert.equal(history.llmPartial,1);
const exported=I.toJson([history]);
assert.equal(JSON.parse(exported).scans.length,1);
assert(!exported.includes(src));
assert(!exported.includes('Case008.java'));
assert(!exported.includes('SQL Injection'));
const data=I.toCsv([history]);
assert(!data.includes(src));assert(data.includes('Case008')===false);
assert(I.csvValue('=HYPERLINK("x","y")').startsWith('"\'=HYPERLINK'));
assert(I.csvValue('\t+1').startsWith('"\'\t+1'));
assert.equal(I.range('0'),null);
assert.equal(I.range('5-45'),null);
assert.deepEqual(I.range('5-6'),{begin:5,end:6});
const unrelated={files:[{name:'other.java',findings:[
  {origin:'LLM',title:'SQL injection',cwe:'CWE-89',lines:'5'},
  {origin:'Semgrep',title:'command-injection',cwe:'',lines:'5'},
  {origin:'Semgrep',title:'formatted-sql-string',cwe:'',lines:'50'},
]}]};
assert.equal(I.relatedSignals(unrelated).length,0);
const sameOrigin={files:[{name:'other.java',findings:[
  {origin:'LLM',title:'SQL Injection',cwe:'CWE-89',lines:'5'},
  {origin:'LLM',title:'SQL Injection',cwe:'CWE-89',lines:'6'},
]}]};
assert.equal(I.relatedSignals(sameOrigin).length,0);
const duplicate={files:[{name:'other.java',findings:[
  {origin:'LLM',title:'SQL Injection',cwe:'CWE-89',lines:'5'},
  {origin:'LLM',title:'SQL Injection',cwe:'CWE-89',lines:'6'},
  {origin:'Semgrep',title:'formatted-sql-string',lines:'6'},
]}]};
assert.equal(I.relatedSignals(duplicate).length,1);
const successful=I.fromReport({...example,llmPartial:0,diagnostics:[]},'mistral:7b','FILES','2026-11-15T10:00:00Z','x2');
assert.equal(successful.status,'COMPLETE');
const failed=I.fromFailure('mistral:7b','FILES','2026-11-15T10:00:00Z','x3');
assert.equal(failed.status,'ERROR');assert.equal(failed.signals,0);
const fake={db:new Map(),getItem(k){return this.db.get(k)||null;},setItem(k,v){this.db.set(k,v);}};
assert.equal(I.load(fake).length,0);
I.save(fake,[history,failed]);assert.equal(I.load(fake).length,2);
assert.equal(I.save(fake,Array.from({length:80},(_,i)=>({...failed,id:'v'+i}))).length,60);
fake.setItem(I.KEY,'invalid');assert.deepEqual(I.load(fake),[]);
const tricky={...example,files:[{name:'</td><script>alert(1)</script>.java',source:src,findings:[{
  origin:'LLM',title:'<img src=x onerror=alert(1)>',severity:'HIGH',cwe:'CWE-89',lines:'5',validation:'NEEDS_REVIEW'
}]}]};
const html=I.toReportHtml(tricky,'<script>alert(2)</script>');
assert(html.includes('&lt;script&gt;alert(2)&lt;/script&gt;'));
assert(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
assert(!html.includes(src));assert(!html.includes('<script>'));
assert(!html.includes('<img src=x'));
assert(html.includes('исходный код'));
console.log('Web 1.4: all insights/history/correlation/exports tests PASSED');
