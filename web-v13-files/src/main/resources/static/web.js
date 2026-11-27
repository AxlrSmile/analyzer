'use strict';

const byId = id => document.getElementById(id);
const $ = {
  theme: byId('themeButton'), models: byId('modelSelect'), modelHint: byId('modelHint'),
  refresh: byId('refreshModels'), input: byId('filesInput'), drop: byId('dropZone'),
  selected: byId('selectedList'), selectedCount: byId('selectedCount'), zip: byId('zipInput'),
  progress: byId('scanProgress'), tree: byId('projectTree'), sourcePane: byId('sourceWorkspace'), sourceLines: byId('sourceLines'),
  scan: byId('scanButton'), export: byId('exportButton'), notice: byId('notice'),
  tbody: byId('findingsBody'), diagnostic: byId('diagnostics'),
  diagnosticList: byId('diagnosticsList'), detail: byId('findingDetails'),
  fixWorkspace: byId('fixWorkspace'), fixSelected: byId('fixSelected'), fixRun: byId('fixRunButton'),
  fixDownload: byId('fixDownloadButton'), fixProgress: byId('fixProgress'),
  fixNotice: byId('fixNotice'), fixResult: byId('fixResult')
};
let chosenFiles = [];
let chosenZip = null;
let activeFile = null;
let currentReport = null;
let scanning = false;
let selectedFixTarget = null;
let currentFix = null;
let fixBusy = false;

function showNotice(text, type = '') {
  $.notice.textContent = text;
  $.notice.className = 'notice' + (type ? ' ' + type : '');
}
function setTheme(theme) {
  const chosen = theme === 'light' ? 'light' : 'dark';
  document.body.dataset.theme = chosen;
  $.theme.textContent = chosen === 'light' ? '☀ Светлая' : '☾ Тёмная';
  try { localStorage.setItem('csa-web-theme', chosen); } catch (_) { /* optional */ }
}
try { setTheme(localStorage.getItem('csa-web-theme') || 'dark'); } catch (_) { setTheme('dark'); }
$.theme.addEventListener('click', () => setTheme(document.body.dataset.theme === 'dark' ? 'light' : 'dark'));

async function refreshModels() {
  const previous = $.models.value;
  $.models.replaceChildren(new Option('Загрузка моделей…', ''));
  $.models.disabled = true;
  $.modelHint.textContent = 'Запрос к локальной Ollama…';
  try {
    const response = await fetch('/api/models');
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const json = await response.json();
    const names = Array.isArray(json.models) ? json.models : [];
    $.models.replaceChildren(...names.map(name => new Option(name, name)));
    if (names.includes(previous)) $.models.value = previous;
    $.models.disabled = names.length === 0;
    $.modelHint.textContent = 'Список от Ollama. При отключённом сервере может отображаться модель по умолчанию.';
  } catch (_) {
    $.models.replaceChildren(new Option('Ollama недоступна', ''));
    $.modelHint.textContent = 'Не удалось получить модели. Запустите Ollama и обновите список.';
  }
  updateScanButton();
}
$.refresh.addEventListener('click', refreshModels);

function isSourceFile(file) {
  return /\.(java|kt|scala|c|h|cpp|cc|cxx|hpp|py|js|mjs|jsx|ts|tsx|php|rb|go|rs|cs|sql)$/i.test(file.name);
}
function changeFiles(fileList) {
  chosenFiles = Array.from(fileList || []);
  chosenZip = null;
  $.zip.value = '';
  $.selected.replaceChildren();
  if (chosenFiles.length === 0) {
    const li = document.createElement('li'); li.className = 'empty-small'; li.textContent = 'Файлы ещё не выбраны'; $.selected.append(li);
  }
  chosenFiles.forEach(file => {
    const li = document.createElement('li');
    const name = document.createElement('span'); name.textContent = file.name;
    const size = document.createElement('span'); size.className = 'file-size'; size.textContent = Math.round(file.size / 1024) + ' КБ';
    li.append(name, size); $.selected.append(li);
  });
  $.selectedCount.textContent = chosenFiles.length + ' / 5';
  if (chosenFiles.length > 5) showNotice('Можно выбрать не более 5 файлов.', 'warn');
  else if (chosenFiles.some(file => !isSourceFile(file))) showNotice('Выберите только поддерживаемые файлы исходного кода.', 'warn');
  else showNotice('Файлы выбраны. Можно начинать анализ.');
  updateScanButton();
}
$.zip.addEventListener('change', () => {
  const file = $.zip.files && $.zip.files[0];
  if (!file) return;
  chosenZip = file;
  chosenFiles = [];
  $.input.value = '';
  $.selected.replaceChildren();
  const li = document.createElement('li');
  const title = document.createElement('span'); title.textContent = file.name;
  const size = document.createElement('span'); size.textContent = Math.round(file.size / 1024) + ' КБ'; size.className = 'file-size';
  li.append(title, size); $.selected.append(li);
  $.selectedCount.textContent = 'ZIP';
  showNotice('Архив выбран. Сервер извлечёт только поддерживаемые исходники в временную папку.');
  updateScanButton();
});
function updateScanButton() {
  const validZip = chosenZip && /\.zip$/i.test(chosenZip.name) && chosenZip.size > 0 && chosenZip.size <= 2 * 1024 * 1024;
  const validFiles = chosenFiles.length > 0 && chosenFiles.length <= 5
    && !chosenFiles.some(file => !isSourceFile(file) || file.size <= 0 || file.size > 256 * 1024);
  $.scan.disabled = scanning || !(validZip || validFiles) || $.models.disabled || !$.models.value;
}
$.drop.addEventListener('click', () => $.input.click());
$.drop.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); $.input.click(); } });
$.input.addEventListener('change', () => changeFiles($.input.files));
for (const eventName of ['dragenter', 'dragover']) $.drop.addEventListener(eventName, event => { event.preventDefault(); $.drop.classList.add('dragover'); });
for (const eventName of ['dragleave', 'drop']) $.drop.addEventListener(eventName, event => { event.preventDefault(); $.drop.classList.remove('dragover'); });
$.drop.addEventListener('drop', event => changeFiles(event.dataTransfer.files));

function resetResults() {
  byId('filesStat').textContent = '0'; byId('findingsStat').textContent = '0';
  byId('highStat').textContent = '0'; byId('semgrepStat').textContent = 'Не запускался';
  $.tbody.replaceChildren(); $.detail.hidden = true; $.diagnostic.hidden = true;
  $.export.disabled = true; currentReport = null; activeFile = null;
  $.sourcePane.hidden = true; $.tree.replaceChildren(); $.sourceLines.replaceChildren();
  resetFix();
}
function addTextCell(tr, text) { const td = document.createElement('td'); td.textContent = String(text ?? ''); tr.append(td); return td; }
function resetFix() {
  selectedFixTarget = null; currentFix = null;
  $.fixWorkspace.hidden = true;
  $.fixResult.hidden = true;
  $.fixProgress.hidden = true;
  $.fixRun.disabled = true;
  $.fixDownload.disabled = true;
  $.fixNotice.textContent = 'Исправления модели требуют ручной проверки.';
}
function selectFinding(file, finding) {
  showSourceFile(file, finding);
  if (/\.java$/i.test(file.name)) {
    selectedFixTarget = { file, finding };
    $.fixWorkspace.hidden = false;
    $.fixSelected.textContent = 'Выбрано: ' + file.name + ' · ' + (finding.title || 'находка') +
      '. Результат модели не является подтверждённой уязвимостью.';
    $.fixRun.disabled = fixBusy;
  }
  $.detail.hidden = false;
  byId('detailTitle').textContent = finding.title || 'Находка';
  byId('detailOrigin').textContent = (finding.origin || '?') + ' · ' + file.name;
  byId('detailDescription').textContent = finding.description || 'Описание отсутствует';
  byId('detailRecommendation').textContent = finding.recommendation || 'Рекомендация отсутствует';
  byId('detailValidation').textContent = 'Статус: ' + (finding.validation || 'NOT_CHECKED') +
    '. Оценка ИИ: ' + (finding.aiReview || 'NOT_REVIEWED') + '. Требуется ручная проверка.';
}

function lineNumbers(value) {
  const text = String(value || '');
  if (!text.trim()) return new Set();
  const numbers = new Set();
  // Do not interpret unreasonable ranges from untrusted scanner output.
  for (const match of text.matchAll(/(\d{1,5})(?:\s*[-–]\s*(\d{1,5}))?/g)) {
    const start = Number(match[1]); const end = Number(match[2] || match[1]);
    if (start > 0 && end >= start && end - start < 30) for (let n = start; n <= end; n++) numbers.add(n);
  }
  return numbers;
}
function showSourceFile(file, finding = null) {
  if (!file) return;
  activeFile = file;
  resetFix();
  byId('sourceTitle').textContent = file.name + (finding ? ' · ' + (finding.origin || 'находка') : '');
  $.sourceLines.replaceChildren();
  const lines = typeof file.source === 'string' ? file.source.split(/\r?\n/) : [];
  const mark = finding ? lineNumbers(finding.lines) : new Set();
  lines.forEach((line, index) => {
    const row = document.createElement('div'); row.className = 'code-line' + (mark.has(index + 1) ? ' marked' : '');
    const number = document.createElement('span'); number.className = 'line-number'; number.textContent = index + 1;
    const body = document.createElement('span'); body.className = 'line-code'; body.textContent = line || ' ';
    row.append(number, body); $.sourceLines.append(row);
  });
  if (mark.size) {
    const first = $.sourceLines.querySelector('.marked');
    if (first) first.scrollIntoView({block:'nearest'});
  }
  $.tree.querySelectorAll('.tree-file').forEach(button => button.classList.toggle('active', button.dataset.path === file.name));
}
function renderTree(files) {
  $.sourcePane.hidden = false;
  $.tree.replaceChildren();
  const root = { children:new Map(), file:null };
  files.forEach(file => {
    let node = root;
    const path = String(file.name || '').replace(/\\/g, '/');
    path.split('/').filter(Boolean).forEach(part => {
      if (!node.children.has(part)) node.children.set(part, {children:new Map(), file:null, name:part});
      node = node.children.get(part);
    });
    node.file = file;
  });
  function write(parent, node) {
    for (const [, child] of node.children) {
      if (child.file) {
        const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'tree-file';
        btn.dataset.path = child.file.name; btn.textContent = child.name + ' · ' + (child.file.findings || []).length;
        btn.addEventListener('click', () => showSourceFile(child.file)); parent.append(btn);
      } else {
        const details = document.createElement('details'); details.open = true;
        const summary = document.createElement('summary'); summary.textContent = child.name;
        const body = document.createElement('div'); body.className = 'tree-children';
        write(body, child); details.append(summary, body); parent.append(details);
      }
    }
  }
  write($.tree, root);
  if (files.length) showSourceFile(files[0]);
}

function renderResults(report) {
  currentReport = report;
  $.export.disabled = false;
  const files = Array.isArray(report.files) ? report.files : [];
  const found = files.flatMap(file => (file.findings || []).map(f => ({ file, finding:f })));
  byId('filesStat').textContent = String(report.loadedFiles ?? files.length);
  byId('findingsStat').textContent = String(found.length);
  byId('highStat').textContent = String(found.filter(row => row.finding.severity === 'HIGH').length);
  byId('semgrepStat').textContent = report.sastCompleted ? 'Завершён' : 'Не выполнен';
  $.tbody.replaceChildren(); $.detail.hidden = true;
  resetFix();
  renderTree(files);
  if (found.length === 0) {
    const tr = document.createElement('tr'); const td = addTextCell(tr,
      'Находок в ответе нет. Это не доказывает безопасность проверенных файлов.');
    td.colSpan = 5; td.className = 'empty-table'; $.tbody.append(tr);
  }
  found.forEach(({file, finding}) => {
    const tr = document.createElement('tr'); tr.className = 'finding-row'; tr.tabIndex = 0;
    const first = document.createElement('td'); const fname = document.createElement('span'); fname.className = 'file-name'; fname.textContent = file.name;
    const title = document.createElement('span'); title.className = 'finding-title'; title.textContent = finding.title || 'Находка';
    first.append(fname, title); tr.append(first);
    const risk = document.createElement('td'); const chip = document.createElement('span');
    chip.className = 'severity ' + (['HIGH','MEDIUM','LOW'].includes(finding.severity) ? finding.severity.toLowerCase() : 'other');
    chip.textContent = finding.severity || '?'; risk.append(chip); tr.append(risk);
    addTextCell(tr, finding.cwe || '—'); addTextCell(tr, finding.lines || '—'); addTextCell(tr, finding.origin || '?');
    tr.addEventListener('click', () => selectFinding(file, finding));
    tr.addEventListener('keydown', e => { if (e.key === 'Enter') selectFinding(file, finding); });
    $.tbody.append(tr);
  });
  const diagnostics = Array.isArray(report.diagnostics) ? report.diagnostics : [];
  $.diagnostic.hidden = diagnostics.length === 0;
  $.diagnosticList.replaceChildren();
  diagnostics.forEach(message => { const li=document.createElement('li'); li.textContent=String(message); $.diagnosticList.append(li); });
  const complete = Boolean(report.sastCompleted) && Number(report.llmFailed) === 0 && Number(report.llmPartial) === 0 && diagnostics.length === 0;
  showNotice('Файлов: ' + (report.loadedFiles ?? files.length) + ' · LLM завершила: ' + report.llmComplete +
    ' · Частично: ' + report.llmPartial + ' · С ошибкой: ' + report.llmFailed +
    ' · Semgrep: ' + (report.sastCompleted ? 'выполнен' : 'не выполнен') +
    (complete ? '. Проверьте находки вручную.' : '. Результат неполный — изучите диагностику.'), complete ? '' : 'warn');
}
$.scan.addEventListener('click', async () => {
  if (scanning || $.scan.disabled) return;
  scanning = true; updateScanButton(); $.scan.textContent = 'Выполняется анализ…'; resetResults();
  $.progress.hidden = false;
  showNotice('Анализ запущен. Ollama может обрабатывать выбранные файлы несколько минут.');
  const data = new FormData(); data.append('model', $.models.value);
  if (chosenZip) data.append('archive', chosenZip, chosenZip.name);
  else chosenFiles.forEach(file => data.append('files', file, file.name));
  try {
    const resp = await fetch(chosenZip ? '/api/scan-zip' : '/api/scan', {method:'POST', headers:{'X-Code-Analyzer':'web1'}, body:data});
    let json = null; try { json = await resp.json(); } catch (_) { /* fallback */ }
    if (!resp.ok) throw new Error(json?.error || json?.detail || json?.message || 'Ошибка HTTP ' + resp.status);
    renderResults(json);
  } catch (error) {
    showNotice('Анализ не завершён: ' + error.message, 'error');
    const tr = document.createElement('tr'); const td = addTextCell(tr, 'Нет достоверных результатов этого запуска.');
    td.colSpan = 5; td.className = 'empty-table'; $.tbody.replaceChildren(tr);
  } finally { scanning = false; $.progress.hidden = true; $.scan.textContent = 'Запустить анализ'; updateScanButton(); }
});
$.fixRun.addEventListener('click', async () => {
  if (!selectedFixTarget || fixBusy || !$.models.value) return;
  const { file, finding } = selectedFixTarget;
  if (!/\.java$/i.test(file.name)) return;
  fixBusy = true;
  currentFix = null;
  $.fixRun.disabled = true;
  $.fixDownload.disabled = true;
  $.fixResult.hidden = true;
  $.fixProgress.hidden = false;
  $.fixNotice.textContent = 'Генерация и проверки выполняются в отдельных временных каталогах. Оригинал не меняется.';
  try {
    const request = {
      fileName: file.name, source: file.source, model: $.models.value,
      finding: {
        origin: finding.origin, title: finding.title, severity: finding.severity,
        cwe: finding.cwe || '', lines: finding.lines, description: finding.description || '',
        recommendation: finding.recommendation || ''
      }
    };
    const response = await fetch('/api/fix-preview', {
      method: 'POST', headers: {'X-Code-Analyzer':'web1', 'Content-Type':'application/json'},
      body: JSON.stringify(request)
    });
    let result = null;
    try { result = await response.json(); } catch (_) { /* empty response */ }
    if (!response.ok) throw new Error(result?.error || 'Ошибка HTTP ' + response.status);
    currentFix = result;
    $.fixResult.hidden = false;
    byId('fixCompilation').textContent = result.compilation || 'NOT_CHECKED';
    byId('fixApi').textContent = result.api || 'NOT_CHECKED';
    byId('fixOverall').textContent = result.overall || 'NOT_CHECKED';
    byId('fixSemgrep').textContent = result.semgrep?.status === 'COMPLETED'
      ? String(result.semgrep.before) + ' → ' + String(result.semgrep.after)
      : 'NOT_CHECKED';
    byId('fixSemgrepNote').textContent = result.semgrep?.details || '';
    byId('fixOriginal').textContent = result.original || '';
    byId('fixProposed').textContent = result.proposed || '';
    byId('fixDiff').textContent = result.diff || '';
    byId('fixValidation').textContent = result.validationDetails || '';
    byId('fixNotes').textContent = result.notes || '';
    $.fixNotice.textContent = result.overall === 'PASSED'
      ? 'Предложение прошло предварительную проверку Java. Выполните функциональные тесты и ручное ревью.'
      : 'Предложение не прошло все проверки Java или требует дополнительных зависимостей. Не используйте его без ревью.';
    $.fixDownload.disabled = typeof result.proposed !== 'string' || !result.proposed;
    await recordFixAttempt({file, finding}, request.model, result);
    $.fixResult.scrollIntoView({block:'nearest'});
  } catch (error) {
    $.fixNotice.textContent = 'Предложение не создано: ' + error.message + '. Исходный файл не изменён.';
    await recordFixAttempt({file, finding}, $.models.value, null);
  } finally {
    fixBusy = false;
    $.fixProgress.hidden = true;
    $.fixRun.disabled = !selectedFixTarget;
  }
});
$.fixDownload.addEventListener('click', () => {
  if (!currentFix || typeof currentFix.proposed !== 'string') return;
  const filename = String(currentFix.fileName || 'Proposal.java').replace(/[^a-zA-Z0-9_.-]/g, '_');
  const base = filename.replace(/\.java$/i, '') || 'Proposal';
  const blob = new Blob([currentFix.proposed], {type:'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = base + '.proposed.java';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$.export.addEventListener('click', () => {
  if (!currentReport) return;
  // Source text is intentionally excluded from exported reports.
  const safe = {...currentReport, files:(currentReport.files || []).map(({source, ...metadata}) => metadata)};
  const blob = new Blob([JSON.stringify(safe, null, 2)], {type:'application/json;charset=utf-8'});
  const url = URL.createObjectURL(blob); const a = document.createElement('a');
  a.href = url; a.download = 'code-security-web-report.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

// Web 1.3: metadata-only experiment journal, persisted in this browser.
// The website does not execute functional tests. No source/LLM proposal is stored.
const J = window.WebExperimentJournal;
const je = {
  body: byId('journalBody'), count: byId('journalCount'), notice: byId('journalNotice'),
  csv: byId('journalCsv'), json: byId('journalJson'), clear: byId('journalClear'),
  editor: byId('journalEditor'), selected: byId('journalSelected'),
  name1: byId('journalCase1Name'), test1: byId('journalCase1'),
  name2: byId('journalCase2Name'), test2: byId('journalCase2'),
  evidence: byId('journalEvidence'), notes: byId('journalNotes'), save: byId('journalSave')
};
let journalRows = [];
let journalActive = null;
let journalStorageAvailable = true;
try { journalRows = J.load(localStorage); }
catch (_) { journalStorageAvailable = false; }
function journalPersist() {
  try { journalRows = J.save(localStorage, journalRows); journalStorageAvailable = true; return true; }
  catch (_) { journalStorageAvailable = false; je.notice.textContent = 'Не удалось сохранить в браузере. Экспортируйте CSV/JSON, пока страница открыта.'; return false; }
}
function journalCell(tr, value, css = '') {
  const td = document.createElement('td'); td.textContent = String(value ?? '—');
  if (css) td.className = css;
  tr.append(td); return td;
}
function journalChoose(id) {
  const record = journalRows.find(r => r.id === id);
  if (!record) return;
  journalActive = id;
  je.editor.hidden = false;
  je.selected.textContent = record.fileName + ' · ' + record.model + ' · ' +
    (record.proposalSha256 ? 'SHA-256 ' + record.proposalSha256 : 'Предложение не сформировано');
  je.name1.value = record.scenario1Name;
  je.test1.value = record.scenario1;
  je.name2.value = record.scenario2Name;
  je.test2.value = record.scenario2;
  je.evidence.value = record.evidenceName;
  je.notes.value = record.notes;
  journalRender();
}
function journalRender() {
  je.body.replaceChildren();
  je.count.textContent = journalRows.length + ' записей · локально в браузере';
  je.csv.disabled = je.json.disabled = je.clear.disabled = journalRows.length === 0;
  if (!journalRows.length) {
    const tr = document.createElement('tr'); const td = journalCell(tr, 'Журнал пока пуст.', 'journal-empty');
    td.colSpan = 7; je.body.append(tr);
    je.editor.hidden = true; journalActive = null;
  }
  journalRows.forEach(record => {
    const tr = document.createElement('tr');
    if (journalActive === record.id) tr.className = 'journal-row-active';
    const date = journalCell(tr, record.fileName);
    const sub = document.createElement('small'); sub.className = 'journal-small';
    sub.textContent = new Date(record.createdAt).toLocaleString('ru-RU'); date.append(sub);
    journalCell(tr, record.model || '—');
    journalCell(tr, record.compilation + ' / ' + record.api);
    journalCell(tr, record.semgrepStatus === 'COMPLETED'
      ? record.semgrepBefore + ' → ' + record.semgrepAfter : 'NOT_CHECKED');
    journalCell(tr, record.scenario1 + ' / ' + record.scenario2);
    const status = J.outcome(record);
    journalCell(tr, status, 'journal-status ' + (status === 'MANUAL_REPORTED_PASSED' ? 'manual' : status === 'REJECTED' ? 'rejected' : ''));
    const td = document.createElement('td'); const btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'secondary-btn'; btn.textContent = 'Открыть';
    btn.setAttribute('aria-label', 'Редактировать ручные проверки для ' + record.fileName);
    btn.addEventListener('click', () => journalChoose(record.id)); td.append(btn); tr.append(td);
    je.body.append(tr);
  });
}
async function recordFixAttempt(target, model, response) {
  try {
    const [originalHash, proposalHash] = response
      ? await Promise.all([J.sha256(response.original), J.sha256(response.proposed)]) : ['', ''];
    const record = J.fromPreview({
      file:target.file, finding:target.finding, model,
      response, originalHash, proposalHash
    });
    if (!record) return;
    journalRows.unshift(record);
    journalRows = journalRows.slice(0, J.MAX_ROWS);
    const saved = journalPersist();
    journalRender();
    journalChoose(record.id);
    if (saved) je.notice.textContent = response
      ? 'Попытка записана. Функциональные тесты пока NOT_CHECKED. Подтвердите их вручную по внешнему логу.'
      : 'Неудачная генерация записана как REJECTED. Оригинал не изменён.';
  } catch (_) {
    je.notice.textContent = 'Не удалось записать попытку в журнал. Проверьте хранилище браузера.';
  }
}
je.save.addEventListener('click', () => {
  const original = journalRows.find(r => r.id === journalActive);
  if (!original) return;
  // Filename only, not absolute paths. The log itself is not copied or read.
  const evidence = String(je.evidence.value || '').split(/[\\/]/).pop().trim();
  if ((je.test1.value === 'PASSED' || je.test2.value === 'PASSED') && !evidence) {
    je.notice.textContent = 'Для отметки PASSED укажи имя файла внешнего тестового лога. Сам сайт функциональные тесты не выполняет.';
    je.evidence.focus(); return;
  }
  const edited = J.clean({
    ...original,
    scenario1Name:je.name1.value, scenario1:je.test1.value,
    scenario2Name:je.name2.value, scenario2:je.test2.value,
    evidenceName:evidence, notes:je.notes.value,
    functionalSource:'USER_DECLARED_EXTERNAL'
  });
  journalRows = journalRows.map(r => r.id === journalActive ? edited : r);
  const saved = journalPersist(); journalRender();
  je.notice.textContent = saved
    ? 'Ручная оценка сохранена. Статусы отражают запись пользователя, а не запуск тестов на сайте.'
    : 'Изменения доступны только до закрытия вкладки. Экспортируйте журнал.';
});
function journalDownload(filename, content, mime) {
  const blob = new Blob([content], {type:mime});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
je.csv.addEventListener('click', () => {
  if (journalRows.length) journalDownload('code-security-web13-experiments.csv',
    J.toCsv(journalRows), 'text/csv;charset=utf-8');
});
je.json.addEventListener('click', () => {
  if (journalRows.length) journalDownload('code-security-web13-experiments.json',
    J.toJson(journalRows), 'application/json;charset=utf-8');
});
je.clear.addEventListener('click', () => {
  if (!journalRows.length || !window.confirm('Удалить локальный журнал? Экспортируйте его перед очисткой.')) return;
  journalRows = []; journalActive = null; const saved = journalPersist(); journalRender();
  je.notice.textContent = saved ? 'Локальный журнал очищен.' : 'Очистка не сохранена. Проверьте настройки браузера.';
});
journalRender();

refreshModels();
