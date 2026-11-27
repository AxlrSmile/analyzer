'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const J = require('../src/main/resources/static/web-journal.js');

const finding = {origin:'Semgrep', title:'SQL injection', cwe:'CWE-89', severity:'HIGH'};
const file = {name:'Case008.java', source:'secret original code should not be persisted'};
const response = {
  original:file.source,
  proposed:'secret candidate code should not be persisted',
  diff:'secret diff', validationDetails:'private compiler diagnostics',
  compilation:'PASSED', api:'PASSED', overall:'PASSED',
  semgrep:{status:'COMPLETED',before:1,after:0}
};
function one() {return J.fromPreview({file, finding, model:'qwen2.5-coder:7b', response,
  originalHash:'f'.repeat(64), proposalHash:'a'.repeat(64),
  createdAt:'2026-11-15T18:00:00.000Z', id:'run-one'});}

test('records automatic checks but functional statuses start NOT_CHECKED', () => {
  const r=one(); assert.equal(r.compilation,'PASSED'); assert.equal(r.api,'PASSED');
  assert.equal(r.overall,'PASSED'); assert.equal(r.semgrepBefore,1); assert.equal(r.semgrepAfter,0);
  assert.equal(r.scenario1,'NOT_CHECKED'); assert.equal(r.scenario2,'NOT_CHECKED');
  assert.equal(J.outcome(r),'INCOMPLETE');
});
test('functional results remain explicitly user-declared and never browser-executed',()=>{
  const r=J.clean({...one(),scenario1:'PASSED',scenario2:'PASSED',
    evidenceName:'Case008-Web12-H2.log',notes:'2/2 external H2 tests'});
  assert.equal(r.functionalSource,'USER_DECLARED_EXTERNAL');
  assert.equal(J.outcome(r),'MANUAL_REPORTED_PASSED');
  assert.equal(J.outcome(J.clean({...r,scenario2:'FAILED'})),'MANUAL_FAILED');
});
test('failures and skipped tests cannot become a verified pass',()=>{
  const r=one();
  assert.equal(J.outcome(J.clean({...r,overall:'FAILED',scenario1:'PASSED',scenario2:'PASSED'})),'REJECTED');
  assert.equal(J.outcome(J.clean({...r,scenario2:'SKIPPED',scenario1:'PASSED'})),'INCOMPLETE');
  assert.equal(J.outcome(J.fromPreview({file,finding,model:'qwen',response:null})),'REJECTED');
});
test('JSON/CSV and storage omit original, proposal, diff and full diagnostics',()=>{
  const storage = new Map(); const api={setItem:(key,value)=>storage.set(key,value),getItem:key=>storage.get(key)};
  J.save(api,[one()]); const loaded=J.load(api);
  assert.equal(loaded.length,1);
  const combined = storage.get(J.KEY)+J.toJson(loaded)+J.toCsv(loaded);
  for(const text of [response.original,response.proposed,response.diff,response.validationDetails]) {
    assert.equal(combined.includes(text),false);
  }
  assert.equal(combined.includes('USER_DECLARED_EXTERNAL'),true);
});
test('CSV escapes quotes, separator/newlines and formula-like user text',()=>{
  const r=J.clean({...one(),fileName:'=HYPERLINK("bad","click")', notes:'hello,"world"\nline'});
  const csv=J.toCsv([r]); assert.equal(csv.includes('"\'=HYPERLINK('),true);
  assert.equal(csv.includes('"hello,""world""\nline"'),true);
  assert.equal(csv.startsWith('\uFEFF'),true);
});
test('malformed stored records are ignored or constrained',()=>{
  const storage={getItem:()=>'{bad json'}; assert.deepEqual(J.load(storage),[]);
  const invalid=J.clean({...one(),scenario1:'ADMIN-VERIFIED', proposed:'malicious',
    evidenceName:'z'.repeat(600), cwe:'Q'.repeat(600)});
  assert.equal(invalid.scenario1,'NOT_CHECKED');
  assert.equal(invalid.evidenceName.length,140);
  assert.equal(invalid.cwe.length,40);
  assert.equal('proposed' in invalid,false);
});
test('sha256 matches expected digest on a test string',async()=>{
  const hash=await J.sha256('abc');
  assert.equal(hash,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
