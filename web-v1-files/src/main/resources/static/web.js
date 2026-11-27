'use strict';

const byId = id => document.getElementById(id);
const $ = {
  theme: byId('themeButton'), models: byId('modelSelect'), modelHint: byId('modelHint'),
  refresh: byId('refreshModels'), input: byId('filesInput'), drop: byId('dropZone'),
  selected: byId('selectedList'), selectedCount: byId('selectedCount'),
  scan: byId('scanButton'), export: byId('exportButton'), notice: byId('notice'),
  tbody: byId('findingsBody'), diagnostic: byId('diagnostics'),
  diagnosticList: byId('diagnosticsList'), detail: byId('findingDetails')
};
let chosenFiles = [];
let currentReport = null;
let scanning = false;

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
function updateScanButton() {
  $.scan.disabled = scanning || chosenFiles.length === 0 || chosenFiles.length > 5
    || chosenFiles.some(file => !isSourceFile(file) || file.size <= 0 || file.size > 256 * 1024)
    || $.models.disabled || !$.models.value;
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
  $.export.disabled = true; currentReport = null;
}
function addTextCell(tr, text) { const td = document.createElement('td'); td.textContent = String(text ?? ''); tr.append(td); return td; }
function selectFinding(file, finding) {
  $.detail.hidden = false;
  byId('detailTitle').textContent = finding.title || 'Находка';
  byId('detailOrigin').textContent = (finding.origin || '?') + ' · ' + file.name;
  byId('detailDescription').textContent = finding.description || 'Описание отсутствует';
  byId('detailRecommendation').textContent = finding.recommendation || 'Рекомендация отсутствует';
  byId('detailValidation').textContent = 'Статус: ' + (finding.validation || 'NOT_CHECKED') +
    '. Оценка ИИ: ' + (finding.aiReview || 'NOT_REVIEWED') + '. Требуется ручная проверка.';
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
  showNotice('Анализ запущен. Ollama может обрабатывать выбранные файлы несколько минут.');
  const data = new FormData(); data.append('model', $.models.value);
  chosenFiles.forEach(file => data.append('files', file, file.name));
  try {
    const resp = await fetch('/api/scan', {method:'POST', headers:{'X-Code-Analyzer':'web1'}, body:data});
    let json = null; try { json = await resp.json(); } catch (_) { /* fallback */ }
    if (!resp.ok) throw new Error(json?.error || json?.detail || json?.message || 'Ошибка HTTP ' + resp.status);
    renderResults(json);
  } catch (error) {
    showNotice('Анализ не завершён: ' + error.message, 'error');
    const tr = document.createElement('tr'); const td = addTextCell(tr, 'Нет достоверных результатов этого запуска.');
    td.colSpan = 5; td.className = 'empty-table'; $.tbody.replaceChildren(tr);
  } finally { scanning = false; $.scan.textContent = 'Запустить анализ'; updateScanButton(); }
});
$.export.addEventListener('click', () => {
  if (!currentReport) return;
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], {type:'application/json;charset=utf-8'});
  const url = URL.createObjectURL(blob); const a = document.createElement('a');
  a.href = url; a.download = 'code-security-web-report.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
refreshModels();
