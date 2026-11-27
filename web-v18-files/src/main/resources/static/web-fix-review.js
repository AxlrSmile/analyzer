'use strict';
/* Web 1.8: advisory review and metadata-only export for proposed fixes.
 * This is never an exploit proof, scanner override, or ground-truth classifier.
 * Never store or export file.source, original, proposed, diff, or validationDetails.
 */
(function (root) {
  const safe = (value, max = 180) => typeof value === 'string' ? value.slice(0, max) : '';
  const VALID_STATUS = new Set(['PASSED','FAILED','NOT_CHECKED']);
  const VALID_ASSESSMENT = new Set(['NO_CHANGE','NOT_VALIDATED','API_UNVERIFIED',
    'SAST_NOT_CHECKED','STATIC_REGRESSION','STATIC_SIGNALS_REDUCED','STATIC_SIGNALS_UNCHANGED']);
  const status = value => VALID_STATUS.has(value) ? value : 'NOT_CHECKED';
  const count = value => Number.isInteger(value) && value >= 0 && value <= 100000 ? value : null;
  function parameterizedSql(source) {
    if (typeof source !== 'string' || source.length > 256 * 1024) return false;
    // A very narrow code hint, NOT an SQL parser. Deliberately abstain if any
    // statement-style API or dynamic string construction is visible elsewhere.
    const binds = /\.set(?:String|Int|Long|Object|Boolean|Date|Timestamp)\s*\(\s*\d+\s*,/.test(source);
    const literal = /\.prepareStatement\s*\(\s*"[^"\n]*\?[^"\n]*"\s*\)/.test(source);
    const other = /\.createStatement\s*\(|\.execute(?:Query|Update)\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/.test(source);
    return binds && literal && !other;
  }
  function triage(file, finding, dashboardReview = {}) {
    const code = safe(finding?.cwe, 30).toUpperCase();
    const title = safe(finding?.title, 220);
    const sql = code === 'CWE-89' || /sql[\s-]*injection|sql-инъек/i.test(title);
    const defense = sql && parameterizedSql(file?.source);
    const possibleFp = dashboardReview?.code === 'POSSIBLE_FP' || defense;
    if (possibleFp) return Object.freeze({
      code:'POSSIBLE_FP', requiresAcknowledgment:true, title:'Возможный False Positive — сначала проверьте код',
      explanation: defense
        ? 'В выбранном файле видны параметризованный SQL-запрос и отдельная передача параметра. Это узкая подсказка о защите, а не доказательство отсутствия иных SQL-инъекций. Предложение ИИ может ухудшить код.'
        : 'Другой этап анализа отметил возможный защитный механизм или предположительно ложный сигнал. Перед генерацией исправления проверьте конкретный путь данных.'
    });
    if (dashboardReview?.code === 'UNVERIFIED_EVIDENCE') return Object.freeze({
      code:'UNVERIFIED_EVIDENCE', requiresAcknowledgment:false, title:'Цитата не подтверждена — сначала проверьте строки',
      explanation:'Генерация исправления допустима только как черновик: координаты или evidence требуют ручной проверки. Оригинал не будет изменён.'
    });
    return Object.freeze({
      code:'REVIEW_REQUIRED', requiresAcknowledgment:false, title:'Предварительная находка — требуется проверка',
      explanation:'Перед применением предложения проверьте реальный поток данных, все изменения API и результаты функциональных тестов. Оригинальный файл не будет перезаписан.'
    });
  }
  const assessmentMessages = {
    NO_CHANGE:['Изменения отсутствуют','Предложенный исходник совпадает с оригиналом. Нельзя считать его исправлением.'],
    NOT_VALIDATED:['Проверка Java не пройдена','Компиляция не подтверждена; предложение нельзя считать пригодным для применения.'],
    API_UNVERIFIED:['API не подтверждён','Проверьте совместимость публичных интерфейсов и внешние зависимости вручную.'],
    SAST_NOT_CHECKED:['Повторный Semgrep не завершён','Нет сопоставимого результата до/после, поэтому снижение сигналов неизвестно.'],
    STATIC_REGRESSION:['После исправления стало больше сигналов','Повторный Semgrep сообщил больше предупреждений. Требуется изучить новые находки.'],
    STATIC_SIGNALS_REDUCED:['Число сигналов Semgrep уменьшилось','Уменьшение числа предупреждений не доказывает отсутствие уязвимостей.'],
    STATIC_SIGNALS_UNCHANGED:['Число сигналов не изменилось','Это не подтверждает ни безопасность предложения, ни его неэффективность.']
  };
  function assess(result) {
    // Prefer server conclusion; compatibility fallback is conservative.
    const server = result?.assessment || {};
    let code = VALID_ASSESSMENT.has(server.category) ? server.category : 'SAST_NOT_CHECKED';
    if (!VALID_ASSESSMENT.has(server.category)) {
      if (typeof result?.original === 'string' && result.original === result?.proposed) code = 'NO_CHANGE';
      else if (result?.compilation !== 'PASSED') code = 'NOT_VALIDATED';
      else if (result?.api !== 'PASSED') code = 'API_UNVERIFIED';
      else if (result?.semgrep?.status === 'COMPLETED' && count(result.semgrep.before) !== null
          && count(result.semgrep.after) !== null) {
        code = result.semgrep.after > result.semgrep.before ? 'STATIC_REGRESSION' :
          result.semgrep.after < result.semgrep.before ? 'STATIC_SIGNALS_REDUCED' : 'STATIC_SIGNALS_UNCHANGED';
      }
    }
    return Object.freeze({code, title:assessmentMessages[code][0], explanation:assessmentMessages[code][1]});
  }
  function protocolInput(file, finding, model) {
    return Object.freeze({fileName:safe(file?.name, 220).split(/[\\/]/).pop(),
      model:safe(model,90), origin:safe(finding?.origin,30),
      findingTitle:safe(finding?.title,180), cwe:safe(finding?.cwe,30),
      lines:safe(finding?.lines,50)});
  }
  function protocol(input, result) {
    const s = result?.semgrep || {};
    const a = assess(result);
    return {
      format:'code-security-web18-fix-review', version:1,
      exportedAt:new Date().toISOString(),
      source:'LOCAL_TOOL_OUTPUT',
      note:'Предварительная автоматическая проверка. Без исходного кода, предложения и логов. Функциональные тесты здесь не выполнялись.',
      fileName:safe(input?.fileName,220), model:safe(input?.model,90),
      finding:{origin:safe(input?.origin,30),title:safe(input?.findingTitle,180),
        cwe:safe(input?.cwe,30),lines:safe(input?.lines,50)},
      validation:{compilation:status(result?.compilation),api:status(result?.api),
        overall:status(result?.overall)},
      semgrep:{status:s.status === 'COMPLETED' ? 'COMPLETED':'NOT_CHECKED',
        before:s.status === 'COMPLETED' ? count(s.before) : null,
        after:s.status === 'COMPLETED' ? count(s.after) : null},
      assessmentCode:a.code, manualReviewRequired:true, functionalTests:'NOT_RUN_BY_WEB'
    };
  }
  const api = Object.freeze({parameterizedSql,triage,assess,protocolInput,protocol});
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.WebFixReview = api;
})(typeof window !== 'undefined' ? window : null);
