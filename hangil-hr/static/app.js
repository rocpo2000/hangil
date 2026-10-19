/* 한길 인사·근태 관리
 * - 모든 인사 데이터는 이 브라우저에서 AES-256-GCM으로 암호화한 뒤 사내 서버로 보낸다.
 * - 키는 비밀번호로부터 PBKDF2-SHA256(12만 회)으로 만든다. 64바이트 중 앞 32바이트는 암호화 키,
 *   뒤 32바이트는 서버 접속 확인용 토큰이다. 서버는 토큰의 해시만 보관하므로 데이터를 풀 수 없다.
 */
(function () {
  'use strict';

  // ================= 공통 도구 =================
  const C = window.HRCrypto;
  const te = new TextEncoder(), td = new TextDecoder();
  const $ = (s, el) => (el || document).querySelector(s);
  const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const pad = (n) => String(n).padStart(2, '0');
  const ymd = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const todayStr = () => ymd(new Date());
  const parseYMD = (s) => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
  const addDays = (s, n) => { const d = parseYMD(s); d.setDate(d.getDate() + n); return ymd(d); };
  const diffDays = (a, b) => Math.round((parseYMD(a) - parseYMD(b)) / 86400000);
  const WD = ['일', '월', '화', '수', '목', '금', '토'];
  const tmin = (t) => { if (!t) return null; const [h, m] = t.split(':').map(Number); return h * 60 + m; };
  const fmtH = (h) => (h == null || h === '' ? '' : (Math.round(h * 100) / 100).toFixed(2).replace(/\.?0+$/, ''));
  const uid = () => Array.from(C.randomBytes(8), (b) => b.toString(16).padStart(2, '0')).join('');
  const b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = (s) => { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
  const monthDays = (ym) => { const [y, m] = ym.split('-').map(Number); return new Date(y, m, 0).getDate(); };
  const addMonths = (ym, n) => { const [y, m] = ym.split('-').map(Number); const d = new Date(y, m - 1 + n, 1); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}`; };

  const DEFAULT_SETTINGS = {
    start: '08:00', end: '17:00', brk: 1, warn: 90, lockMin: 15,
    docNo: 'HG-26-A-02', company: '한길주식회사',
    depts: ['대표이사', '관리부', '연구부', '생산부', '물류부', '지입기사'],
    positions: ['대표이사', '상무', '이사', '부장', '차장', '과장', '대리', '주임', '사원', '지입기사'],
    types: ['정상', '지각', '조퇴', '외출', '결근', '연차', '반차', '병가', '경조휴가', '공가', '출장', '휴일근무'],
  };
  const LEAVE_TYPES = ['병가', '경조휴가', '공가'];
  const DIFF = [['dept', '부서'], ['pos', '직책'], ['hire', '입사일'], ['exp', '체류만료일'], ['visa', '국적/비자'], ['task', '소속/업무']];

  // ================= 상태 =================
  let state = null;          // 복호화된 데이터 (메모리에만 존재)
  let KEY = null, AUTH = null, SALT = null, KDF = { c: 120000, dkLen: 64 };
  let VERSION = 0, dirty = false, saving = false, saveTimer = null, saveErr = '';
  let serverLocal = false;
  const ui = { view: 'dash', date: todayStr(), month: todayStr().slice(0, 7), q: '', dept: '', status: '재직', rrnUntil: 0, lastAct: Date.now() };

  function emptyState() {
    return { v: 1, settings: JSON.parse(JSON.stringify(DEFAULT_SETTINGS)), employees: [], att: {}, dayMeta: {}, history: [], sample: false };
  }
  function normalize(s) {
    const e = emptyState();
    s = Object.assign(e, s || {});
    s.settings = Object.assign(JSON.parse(JSON.stringify(DEFAULT_SETTINGS)), s.settings || {});
    return s;
  }
  const S = () => state.settings;
  const stdHours = () => Math.max(0, ((tmin(S().end) - tmin(S().start) + 1440) % 1440) / 60 - Number(S().brk || 0));

  // ================= 서버·암호화 =================
  async function api(method, path, body) {
    const h = { 'Content-Type': 'application/json' };
    if (AUTH) h['X-HR-Auth'] = AUTH;
    const res = await fetch(path, { method, headers: h, body: body ? JSON.stringify(body) : undefined, cache: 'no-store', credentials: 'same-origin' });
    let data = null;
    try { data = await res.json(); } catch (e) { /* 본문 없음 */ }
    return { ok: res.ok, status: res.status, data: data || {} };
  }
  async function derive(pw, saltB64, kdf) {
    const out = await C.pbkdf2Async(C.sha256, te.encode(pw.normalize('NFC')), unb64(saltB64), { c: (kdf || KDF).c, dkLen: 64 });
    return { key: out.slice(0, 32), auth: hex(out.slice(32)) };
  }
  function seal(obj, key) {
    const iv = C.randomBytes(12);
    const ct = C.gcm(key || KEY, iv).encrypt(te.encode(JSON.stringify(obj)));
    return { iv: b64(iv), ct: b64(ct) };
  }
  function unseal(box, key) {
    return JSON.parse(td.decode(C.gcm(key || KEY, unb64(box.iv)).decrypt(unb64(box.ct))));
  }

  function save() {
    dirty = true; setSync();
    clearTimeout(saveTimer);
    saveTimer = setTimeout(persist, 600);
  }
  async function persist() {
    clearTimeout(saveTimer); saveTimer = null;
    if (!state || !KEY || !dirty) return;
    if (saving) { saveTimer = setTimeout(persist, 400); return; }
    saving = true; setSync();
    const snapshot = state;
    try {
      const r = await api('PUT', '/api/vault', { base: VERSION, box: seal(snapshot) });
      if (r.ok) {
        VERSION = r.data.version; saveErr = '';
        if (snapshot === state) dirty = false;
      } else if (r.status === 409) {
        await reloadLatest('다른 PC에서 먼저 저장한 내용이 있어 최신 내용으로 다시 불러왔습니다. 방금 입력한 내용이 반영됐는지 확인해 주세요.');
      } else if (r.status === 401) {
        saveErr = '인증이 만료되었습니다. 다시 로그인해 주세요.'; lock();
      } else {
        saveErr = '저장 실패 (' + r.status + ')';
        saveTimer = setTimeout(persist, 5000);
      }
    } catch (e) {
      saveErr = '서버에 연결할 수 없어 저장하지 못했습니다. 자동으로 다시 시도합니다.';
      saveTimer = setTimeout(persist, 5000);
    }
    saving = false; setSync();
  }
  async function reloadLatest(msg) {
    const r = await api('GET', '/api/vault');
    if (!r.ok || !r.data.box) return;
    state = normalize(unseal(r.data.box));
    VERSION = r.data.version; dirty = false;
    render();
    if (msg) toast(msg, { bad: true, ms: 7000 });
  }
  async function poll() {
    if (!state || dirty || saving) return;
    try {
      const r = await api('GET', '/api/version');
      if (r.ok && r.data.version > VERSION) {
        const a = document.activeElement;
        if (a && /INPUT|SELECT|TEXTAREA/.test(a.tagName) && $('#app').contains(a)) return; // 입력 중이면 다음에
        await reloadLatest();
        toast('다른 PC에서 바뀐 내용을 불러왔습니다.');
      }
    } catch (e) { /* 다음 주기에 재시도 */ }
  }
  function setSync() {
    const el = $('#sync');
    if (!el) return;
    let cls = 'ok', txt = '저장됨 · 암호화';
    if (saveErr) { cls = 'err'; txt = saveErr; } else if (saving || dirty) { cls = 'busy'; txt = '저장 중…'; }
    el.innerHTML = `<span class="dot ${cls}"></span>${esc(txt)}`;
  }

  // ================= 잠금 화면 =================
  async function boot() {
    if (!C || !window.XLSX) { $('#app').innerHTML = '<div class="boot">구성 파일(vendor)을 불러오지 못했습니다. 서버 폴더가 온전한지 확인해 주세요.</div>'; return; }
    let meta;
    try { meta = (await api('GET', '/api/meta')).data; } catch (e) {
      $('#app').innerHTML = '<div class="boot">서버에 연결할 수 없습니다. 서버 프로그램(server.py)이 켜져 있는지 확인해 주세요.</div>'; return;
    }
    serverLocal = !!meta.local;
    if (meta.kdf) KDF = meta.kdf;
    if (!meta.initialized) renderSetup(); else { SALT = meta.salt; renderUnlock(); }
  }

  function lockShell(inner) {
    $('#app').innerHTML = `<div class="lock"><div class="lock-card">
      <div class="brand"><div class="brand-mark">${ICON}</div><div><b>한길 인사·근태</b><small>사내망 전용</small></div></div>
      ${inner}</div></div>`;
  }
  function renderSetup() {
    lockShell(`<h1>처음 사용 설정</h1>
      <p>인사 데이터를 잠글 관리 비밀번호를 정해 주세요. 인사 담당자끼리만 공유하세요.</p>
      <div class="shield">${SHIELD}<span>주민등록번호·연락처·주소를 포함한 모든 데이터는 이 비밀번호로 암호화되어 저장됩니다. 비밀번호를 잊으면 데이터를 복구할 수 없으니 안전한 곳에 적어 두세요.</span></div>
      <form id="f-setup" autocomplete="off">
        <label class="fld">관리 비밀번호 (8자 이상)<input class="input" type="password" id="pw1" autocomplete="new-password" required minlength="8"></label>
        <label class="fld">비밀번호 확인<input class="input" type="password" id="pw2" autocomplete="new-password" required></label>
        <div class="err" id="lock-err"></div>
        <button class="btn primary" type="submit">시작하기</button>
      </form>`);
    $('#pw1').focus();
    $('#f-setup').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const p1 = $('#pw1').value, p2 = $('#pw2').value, err = $('#lock-err');
      if (p1.length < 8) { err.textContent = '비밀번호는 8자 이상이어야 합니다.'; return; }
      if (p1 !== p2) { err.textContent = '두 비밀번호가 다릅니다.'; return; }
      err.textContent = '암호 키를 만드는 중…';
      SALT = b64(C.randomBytes(16));
      const d = await derive(p1, SALT);
      KEY = d.key; AUTH = d.auth; state = emptyState();
      const r = await api('POST', '/api/init', { salt: SALT, auth: AUTH, box: seal(state) });
      if (!r.ok) { err.textContent = r.status === 409 ? '이미 설정된 서버입니다. 새로고침 후 로그인해 주세요.' : '설정에 실패했습니다 (' + r.status + ')'; KEY = AUTH = null; return; }
      VERSION = r.data.version;
      enterApp();
    });
  }
  function renderUnlock(msg) {
    lockShell(`<h1>로그인</h1>
      <p>관리 비밀번호를 입력하면 암호화된 인사 데이터를 엽니다.</p>
      <form id="f-unlock" autocomplete="off">
        <label class="fld">관리 비밀번호<input class="input" type="password" id="pw" autocomplete="current-password" required></label>
        <div class="err" id="lock-err">${esc(msg || '')}</div>
        <button class="btn primary" type="submit">열기</button>
      </form>
      <details><summary class="lockmsg">비밀번호를 잊었나요?</summary>
        <p class="lockmsg">암호화되어 있어 비밀번호 없이는 데이터를 열 수 없습니다. 서버 PC에서 <b>http://localhost</b> 주소로 접속하면 저장소를 초기화(모든 데이터 삭제 후 새로 시작)할 수 있습니다. 이전 파일은 서버 data 폴더에 보관됩니다.</p>
        ${serverLocal ? `<div class="bar"><input class="input" id="reset-confirm" placeholder="초기화 입력"><button class="btn danger" id="btn-reset" type="button">저장소 초기화</button></div>` : ''}
      </details>`);
    $('#pw').focus();
    $('#f-unlock').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const err = $('#lock-err'), btn = $('#f-unlock button');
      btn.disabled = true; err.textContent = '여는 중…';
      try {
        const d = await derive($('#pw').value, SALT);
        AUTH = d.auth;
        const r = await api('GET', '/api/vault');
        if (r.status === 401) { AUTH = null; err.textContent = '비밀번호가 맞지 않습니다.'; btn.disabled = false; return; }
        if (r.status === 429) { AUTH = null; err.textContent = `여러 번 틀려 잠시 잠겼습니다. ${r.data.retry}초 뒤에 다시 시도하세요.`; btn.disabled = false; return; }
        if (!r.ok) throw new Error(r.status);
        KEY = d.key;
        state = normalize(r.data.box ? unseal(r.data.box) : null);
        VERSION = r.data.version;
        enterApp();
      } catch (e) {
        KEY = AUTH = null; err.textContent = '데이터를 열지 못했습니다. 서버 연결을 확인해 주세요.'; btn.disabled = false;
      }
    });
    const rb = $('#btn-reset');
    if (rb) rb.addEventListener('click', async () => {
      if ($('#reset-confirm').value.trim() !== '초기화') { $('#lock-err').textContent = '확인란에 "초기화"를 입력하세요.'; return; }
      const r = await api('POST', '/api/reset', { confirm: '초기화' });
      if (r.ok) { toast('저장소를 초기화했습니다.'); boot(); } else $('#lock-err').textContent = '초기화 실패 (' + r.status + ')';
    });
  }
  async function lock(msg) {
    if (dirty && KEY) { try { await persist(); } catch (e) { /* ignore */ } }
    state = null; KEY = null; AUTH = null; dirty = false;
    closeModal(); $('#print-root').innerHTML = '';
    renderUnlock(msg || '');
  }

  // ================= 앱 셸 =================
  const ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M5 4v16M5 12h7M12 4v16M16 8h4M16 12h4M16 16h4"/></svg>';
  const SHIELD = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex:none"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>';
  const VIEWS = [['dash', '현황'], ['emp', '인사기록부'], ['daily', '일일 근태'], ['month', '월간 근태'], ['hist', '인사변동'], ['set', '설정·데이터']];

  function enterApp() {
    ui.lastAct = Date.now();
    $('#app').innerHTML = `<header class="top"><div class="top-in">
        <div class="brand"><div class="brand-mark">${ICON}</div><div><b>한길 인사·근태</b><small id="sync"></small></div></div>
        <button class="btn quiet sm" data-act="lock" title="잠금">잠금</button>
      </div><nav class="tabs-in" aria-label="메뉴">${VIEWS.map(([k, l]) => `<button class="tab" data-act="view" data-v="${k}">${l}</button>`).join('')}</nav></header>
      <main class="main" id="main"></main>`;
    setSync();
    render();
  }
  function render() {
    if (!state) return;
    $$('.tab').forEach((t) => t.setAttribute('aria-current', t.dataset.v === ui.view ? 'page' : 'false'));
    const fn = { dash: vDash, emp: vEmp, daily: vDaily, month: vMonth, hist: vHist, set: vSet }[ui.view];
    const banner = state.sample ? '<div class="banner info">지금 보이는 것은 <b>예시 데이터</b>입니다. 설정·데이터에서 직원명부 엑셀을 가져오면 예시는 지워지고 실제 데이터로 바뀝니다.</div>' : '';
    $('#main').innerHTML = banner + fn();
    setSync();
  }

  // ================= 직원 계산 =================
  const digits = (s) => String(s || '').replace(/\D/g, '');
  function birthOf(rrn) {
    const s = digits(rrn);
    if (s.length < 6) return null;
    const yy = +s.slice(0, 2), mm = +s.slice(2, 4), dd = +s.slice(4, 6);
    if (mm < 1 || mm > 12 || dd < 1 || dd > 31) return 'invalid';
    const g = s[6];
    const cent = g && '3478'.includes(g) ? 2000 : (g === '9' || g === '0') ? 1800 : 1900;
    return `${cent + yy}-${pad(mm)}-${pad(dd)}`;
  }
  function ageOf(birth) {
    if (!birth || birth === 'invalid') return '';
    const b = parseYMD(birth), t = new Date();
    let a = t.getFullYear() - b.getFullYear();
    if (t.getMonth() < b.getMonth() || (t.getMonth() === b.getMonth() && t.getDate() < b.getDate())) a--;
    return a;
  }
  function tenure(e) {
    if (!e.hire) return '';
    if (e.status === '퇴사' && !e.leave) return '퇴사일 미입력';
    const a = parseYMD(e.hire), b = parseYMD(e.leave || todayStr());
    let m = (b.getFullYear() - a.getFullYear()) * 12 + b.getMonth() - a.getMonth();
    if (b.getDate() < a.getDate()) m--;
    if (m < 0) return '입사 예정';
    return (m >= 12 ? Math.floor(m / 12) + '년 ' : '') + (m % 12) + '개월';
  }
  function visaState(e) {
    if (!e.exp || e.status === '퇴사') return '';
    const d = diffDays(e.exp, todayStr());
    return d < 0 ? '만료' : d <= Number(S().warn || 90) ? '갱신임박' : '정상';
  }
  const isForeign = (e) => /E-\d|F-\d|H-2|D-\d/i.test(e.visa || '') || '5678'.includes(digits(e.rrn)[6] || 'x');
  const maskRrn = (r) => { const s = String(r || ''); if (!s) return ''; const i = s.indexOf('-'); return i >= 0 ? s.slice(0, i + 2) + '●'.repeat(Math.max(0, s.length - i - 2)) : s.slice(0, 6) + '●●●●●●●'; };
  const showRrn = () => ui.rrnUntil > Date.now();
  function issues(e) {
    const out = [];
    if (e.status === '퇴사') { if (!e.leave) out.push('퇴사일 미입력'); return out; }
    const n = digits(e.rrn).length;
    if (!e.rrn) out.push('주민번호 없음'); else if (n === 6) out.push('주민번호 뒷자리 없음'); else if (n !== 13 || birthOf(e.rrn) === 'invalid') out.push('주민번호 확인');
    if (!e.mobile) out.push('휴대폰 없음');
    if (!e.hire && e.dept !== '대표이사') out.push('입사일 없음');
    const v = visaState(e); if (v === '만료') out.push('체류기간 만료'); else if (v === '갱신임박') out.push('체류기간 갱신임박');
    return out;
  }
  const empById = (id) => state.employees.find((e) => e.id === id);
  const employed = (e, date) => (!e.hire || e.hire <= date) && (e.leave ? e.leave >= date : e.status !== '퇴사');
  function nextSabun() {
    let max = 0;
    state.employees.forEach((e) => { const m = /(\d+)$/.exec(e.sabun || ''); if (m) max = Math.max(max, +m[1]); });
    return 'HG-' + String(max + 1).padStart(3, '0');
  }
  function addHist(date, type, e, content, src) {
    state.history.push({ id: uid(), date: date || todayStr(), type, empId: e ? e.id : '', name: e ? e.name : '', dept: e ? e.dept : '', content, src: src || '직접 입력' });
  }

  // ================= 근태 계산 =================
  const getRec = (date, id) => (state.att[date] || {})[id] || null;
  const hasRec = (r) => !!(r && (r.type || r.in || r.out));
  function calc(r) {
    if (!hasRec(r)) return null;
    const std = stdHours();
    let h;
    if (r.in && r.out) {
      let m = tmin(r.out) - tmin(r.in); if (m < 0) m += 1440;
      const brk = r.brk === '' || r.brk == null ? Number(S().brk || 0) : Number(r.brk);
      h = Math.max(0, m / 60 - brk);
    } else if (r.type === '정상' || r.type === '출장') h = std;
    else if (r.type === '반차') h = std / 2;
    else h = 0;
    h = Math.round(h * 100) / 100;
    return { h, ot: Math.round(Math.max(0, h - std) * 100) / 100 };
  }
  function dailyRoster(date) {
    const recs = state.att[date] || {};
    return state.employees.filter((e) => (e.target && employed(e, date)) || hasRec(recs[e.id]));
  }
  function monthStats(ym) {
    const by = {}, tot = { h: 0, ot: 0 };
    Object.keys(state.att).forEach((d) => {
      if (!d.startsWith(ym)) return;
      const day = state.att[d];
      Object.keys(day).forEach((id) => {
        const r = day[id], c = calc(r); if (!c) return;
        const s = by[id] || (by[id] = { days: 0, h: 0, ot: 0, 지각: 0, 조퇴: 0, 결근: 0, 연차: 0, 반차: 0, 휴가: 0 });
        if (c.h > 0) s.days++;
        s.h += c.h; s.ot += c.ot; tot.h += c.h; tot.ot += c.ot;
        if (r.type in s) s[r.type]++;
        if (LEAVE_TYPES.includes(r.type)) s.휴가++;
      });
    });
    return { by, tot };
  }
  function monthRoster(ym) {
    const first = ym + '-01', last = ym + '-' + pad(monthDays(ym));
    const st = monthStats(ym).by;
    return state.employees.filter((e) => st[e.id] || (e.target && (!e.hire || e.hire <= last) && (e.leave ? e.leave >= first : e.status !== '퇴사')));
  }

  // ================= 화면: 현황 =================
  function vDash() {
    const E = state.employees;
    if (!E.length) return `<div class="page-h"><div><h1>시작하기</h1><p>직원명부 엑셀을 가져오면 인사기록부와 근태 명단이 자동으로 만들어집니다.</p></div></div>
      <section class="sec"><h2>1. 엑셀 가져오기</h2>
        <p class="muted">아래 파일을 한 번에 여러 개 선택할 수 있습니다.</p>
        <ul class="muted"><li><b>직원명부</b> (날짜별 시트가 있는 파일) → 최신 시트로 인사기록부를 만들고, 이전 시트와 비교해 입사·퇴사·변경 이력을 정리합니다.</li>
        <li><b>근무시간보고서</b> 양식 → 보고서에 있는 사람을 근태 대상으로 지정합니다.</li>
        <li>이 프로그램이나 <b>인사·근태 통합관리 엑셀</b>에서 내보낸 파일 → 인사기록부·근태기록·변동이력을 그대로 불러옵니다.</li></ul>
        <div class="bar"><label class="btn primary">엑셀 파일 선택<input type="file" id="imp-file" accept=".xlsx,.xls" multiple hidden data-ch="import"></label>
        <button class="btn" data-act="sample">예시 데이터로 둘러보기</button></div></section>`;
    const t = todayStr(), ym = t.slice(0, 7);
    const act = E.filter((e) => e.status !== '퇴사');
    const staff = act.filter((e) => e.dept !== '지입기사');
    const foreign = act.filter(isForeign);
    const visaAlert = act.filter((e) => ['만료', '갱신임박'].includes(visaState(e)));
    const roster = dailyRoster(t), entered = roster.filter((e) => hasRec(getRec(t, e.id))).length;
    const ms = monthStats(ym);
    const depts = Array.from(new Set(S().depts.concat(E.map((e) => e.dept).filter(Boolean))));
    const deptRows = depts.map((d) => {
      const a = act.filter((e) => e.dept === d); if (!a.length) return '';
      const h = a.reduce((s, e) => s + ((ms.by[e.id] || {}).h || 0), 0), ot = a.reduce((s, e) => s + ((ms.by[e.id] || {}).ot || 0), 0);
      return `<tr><td>${esc(d)}</td><td class="r num">${a.length}</td><td class="r num">${a.filter((e) => e.sex === '남').length}</td><td class="r num">${a.filter((e) => e.sex === '여').length}</td><td class="r num">${a.filter(isForeign).length}</td><td class="r num">${a.filter((e) => e.target).length}</td><td class="r num">${fmtH(h) || '-'}</td><td class="r num">${fmtH(ot) || '-'}</td></tr>`;
    }).join('');
    const visaList = act.filter((e) => e.exp).sort((a, b) => (a.exp < b.exp ? -1 : 1)).slice(0, 8).map((e) => {
      const d = diffDays(e.exp, t), v = visaState(e);
      return `<tr class="click" data-act="edit" data-id="${e.id}"><td class="nm"><b>${esc(e.name)}</b><small>${esc(e.eng)}</small></td><td>${esc(e.visa)}</td><td class="num c">${e.exp}</td><td class="r num">${d}일</td><td class="c"><span class="pill ${v === '정상' ? 'ok' : v === '만료' ? 'bad' : 'warn'}">${v}</span></td></tr>`;
    }).join('');
    const iss = E.map((e) => [e, issues(e)]).filter(([, i]) => i.length);
    const hist = state.history.slice().sort((a, b) => (a.date < b.date ? 1 : -1)).slice(0, 6);
    return `<div class="page-h"><div><h1>인사 현황</h1><p>${t} (${WD[parseYMD(t).getDay()]}) 기준</p></div></div>
      <div class="tiles">
        <div class="tile"><span>재직 인원</span><b>${staff.length}<small>명</small></b><em>지입기사 ${act.length - staff.length}명 별도</em></div>
        <div class="tile"><span>외국인 근로자</span><b>${foreign.length}<small>명</small></b><em>재직 기준</em></div>
        <div class="tile ${visaAlert.length ? 'warn' : ''}"><span>체류기간 확인 필요</span><b>${visaAlert.length}<small>명</small></b><em>만료 또는 ${S().warn}일 이내</em></div>
        <div class="tile ${entered < roster.length ? 'warn' : ''}"><span>오늘 근태 입력</span><b>${entered}<small>/ ${roster.length}명</small></b><em><a href="#" data-act="go-daily" data-d="${t}">일일 근태로 이동</a></em></div>
        <div class="tile"><span>${+ym.slice(5)}월 총 근무시간</span><b>${fmtH(ms.tot.h) || 0}<small>시간</small></b><em>연장 ${fmtH(ms.tot.ot) || 0}시간</em></div>
      </div>
      <div class="grid2">
        <section class="sec"><h2>부서별 인원 <small>재직 · ${+ym.slice(5)}월 근무시간</small></h2><div class="tw"><table class="t"><thead><tr><th>부서</th><th>인원</th><th>남</th><th>여</th><th>외국인</th><th>근태대상</th><th>근무시간</th><th>연장</th></tr></thead><tbody>${deptRows}</tbody>
          <tfoot><tr><td>합계</td><td class="r num">${act.length}</td><td class="r num">${act.filter((e) => e.sex === '남').length}</td><td class="r num">${act.filter((e) => e.sex === '여').length}</td><td class="r num">${foreign.length}</td><td class="r num">${act.filter((e) => e.target).length}</td><td class="r num">${fmtH(ms.tot.h) || '-'}</td><td class="r num">${fmtH(ms.tot.ot) || '-'}</td></tr></tfoot></table></div></section>
        <section class="sec"><h2>체류만료 빠른 순 <small>외국인 근로자</small></h2>${visaList ? `<div class="tw"><table class="t"><thead><tr><th>성명</th><th>국적/비자</th><th>만료일</th><th>남은 일수</th><th>상태</th></tr></thead><tbody>${visaList}</tbody></table></div>` : '<div class="empty">체류만료일이 입력된 직원이 없습니다.</div>'}</section>
        <section class="sec"><h2>확인이 필요한 정보 <small>${iss.length}명</small></h2>${iss.length ? `<div class="tw"><table class="t"><tbody>${iss.map(([e, i]) => `<tr class="click" data-act="edit" data-id="${e.id}"><td class="nm"><b>${esc(e.name)}</b><small>${esc(e.dept)} · ${esc(e.sabun)}</small></td><td class="wrap">${i.map((x) => `<span class="pill ${/만료|퇴사/.test(x) ? 'bad' : 'warn'}">${esc(x)}</span>`).join(' ')}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">모든 정보가 채워져 있습니다.</div>'}</section>
        <section class="sec"><h2>최근 인사변동</h2>${hist.length ? `<div class="tw"><table class="t"><tbody>${hist.map((h) => `<tr><td class="num">${h.date}</td><td><span class="pill ${histCls(h.type)}">${esc(h.type)}</span></td><td><b>${esc(h.name)}</b></td><td class="wrap">${esc(h.content)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">기록이 없습니다.</div>'}
          <div class="bar"><button class="btn sm" data-act="view" data-v="hist">전체 보기</button></div></section>
      </div>`;
  }
  const histCls = (t) => (t === '입사' || t === '복직' ? 'ok' : t === '퇴사' ? 'bad' : t === '휴직' ? 'warn' : 'acc');

  // ================= 화면: 인사기록부 =================
  function deptRank(d) { const i = S().depts.indexOf(d); return i < 0 ? 99 : i; }
  function posRank(p) { const i = S().positions.indexOf(p); return i < 0 ? 99 : i; }
  function empRows() {
    const q = ui.q.trim().toLowerCase();
    return state.employees.filter((e) => {
      if (ui.dept && e.dept !== ui.dept) return false;
      if (ui.status === '재직' && e.status === '퇴사') return false;
      if (ui.status === '퇴사' && e.status !== '퇴사') return false;
      if (q && ![e.name, e.eng, e.sabun, e.task, e.pos, e.mobile, e.visa, e.note].join(' ').toLowerCase().includes(q)) return false;
      return true;
    });
  }
  function vEmp() {
    const rows = empRows(), reveal = showRrn();
    const tbody = rows.map((e) => {
      const b = birthOf(e.rrn), v = visaState(e);
      const d = e.exp && e.status !== '퇴사' ? diffDays(e.exp, todayStr()) : null;
      return `<tr class="click ${e.status === '퇴사' ? 'retired' : ''}" data-act="edit" data-id="${e.id}">
        <td class="num">${esc(e.sabun)}</td>
        <td class="c"><span class="pill ${e.status === '재직' ? 'ok' : e.status === '휴직' ? 'warn' : 'mute'}">${esc(e.status)}</span></td>
        <td>${esc(e.dept)}</td><td class="nm"><b>${esc(e.name)}</b>${e.eng ? `<small>${esc(e.eng)}</small>` : ''}</td>
        <td>${esc(e.pos)}</td><td>${esc(e.task)}</td>
        <td class="num">${e.hire || ''}</td><td>${tenure(e)}</td>
        <td class="num">${reveal ? esc(e.rrn) : esc(maskRrn(e.rrn))}</td>
        <td class="num">${b === 'invalid' ? '<span class="pill bad">확인</span>' : b ? `${b} <span class="faint">(${ageOf(b)})</span>` : ''}</td>
        <td class="num">${esc(e.mobile)}</td>
        <td>${esc(e.visa)}</td>
        <td class="num">${e.exp ? `${e.exp} ${v ? `<span class="pill ${v === '정상' ? 'ok' : v === '만료' ? 'bad' : 'warn'}">${v === '정상' ? 'D-' + d : v}</span>` : ''}` : ''}</td>
        <td class="c"><input type="checkbox" data-ch="target" data-id="${e.id}" ${e.target ? 'checked' : ''} aria-label="${esc(e.name)} 근태대상"></td>
        <td class="wrap faint">${esc(e.note)}</td></tr>`;
    }).join('');
    const act = state.employees.filter((e) => e.status !== '퇴사').length;
    return `<div class="page-h"><div><h1>인사기록부</h1><p>재직 ${act}명 · 퇴사 ${state.employees.length - act}명 · 행을 누르면 상세 정보를 보고 고칠 수 있습니다.</p></div>
        <div class="bar"><button class="btn primary" data-act="new-emp">직원 추가</button></div></div>
      <div class="bar">
        <input class="input" type="search" id="emp-q" placeholder="이름·사번·업무·연락처 검색" value="${esc(ui.q)}" data-in="q" style="min-width:200px;flex:1">
        <select class="input" data-ch="dept" aria-label="부서"><option value="">전체 부서</option>${S().depts.map((d) => `<option ${ui.dept === d ? 'selected' : ''}>${esc(d)}</option>`).join('')}</select>
        <select class="input" data-ch="status" aria-label="재직상태">${['재직', '퇴사', '전체'].map((s) => `<option ${ui.status === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
        <button class="btn" data-act="rrn">${reveal ? '주민번호 가리기' : '주민번호 보기 (1분)'}</button>
        <button class="btn" data-act="sort-emp" title="부서 → 직책 → 입사일 순">부서순 정렬</button>
      </div>
      <div class="tw"><table class="t"><thead><tr><th>사번</th><th>상태</th><th>부서</th><th>성명</th><th>직책</th><th>소속/업무</th><th>입사일</th><th>근속</th><th>주민등록번호</th><th>생년월일(나이)</th><th>휴대폰</th><th>국적/비자</th><th>체류만료</th><th title="일일 근태·근무시간보고서 명단에 포함">근태대상</th><th>비고</th></tr></thead>
      <tbody id="emp-body">${tbody || '<tr><td colspan="15" class="empty">조건에 맞는 직원이 없습니다.</td></tr>'}</tbody></table></div>`;
  }

  function empModal(id) {
    const isNew = !id;
    const e = isNew ? { id: '', sabun: nextSabun(), status: '재직', dept: '', name: '', eng: '', pos: '', task: '', hire: todayStr(), leave: '', sex: '', rrn: '', mobile: '', home: '', addr: '', visa: '', exp: '', target: true, mark: '', note: '' } : empById(id);
    const opt = (list, v) => `<option value=""></option>` + Array.from(new Set(list.concat(v ? [v] : []))).map((x) => `<option ${x === v ? 'selected' : ''}>${esc(x)}</option>`).join('');
    const recCount = isNew ? 0 : Object.values(state.att).filter((d) => d[id]).length;
    const b = birthOf(e.rrn);
    openModal(`<div class="mdl"><form id="f-emp" autocomplete="off">
      <div class="mdl-h"><h3>${isNew ? '직원 추가' : esc(e.name) + ' · ' + esc(e.sabun)}</h3><button class="btn quiet sm" type="button" data-act="close">닫기</button></div>
      <div class="mdl-b">
        <fieldset class="grp"><legend>기본 정보</legend><div class="fgrid">
          <label class="fld">사번<input class="input" name="sabun" value="${esc(e.sabun)}"></label>
          <label class="fld">재직상태<select class="input" name="status">${['재직', '휴직', '퇴사'].map((s) => `<option ${s === e.status ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
          <label class="fld">성명 *<input class="input" name="name" value="${esc(e.name)}" required></label>
          <label class="fld">영문명<input class="input" name="eng" value="${esc(e.eng)}"></label>
          <label class="fld">부서 *<select class="input" name="dept" required>${opt(S().depts, e.dept)}</select></label>
          <label class="fld">직책<select class="input" name="pos">${opt(S().positions, e.pos)}</select></label>
          <label class="fld">소속/업무<input class="input" name="task" value="${esc(e.task)}"></label>
          <label class="fld">성별<select class="input" name="sex">${opt(['남', '여'], e.sex)}</select></label>
          <label class="fld">입사일<input class="input" type="date" name="hire" value="${esc(e.hire)}"></label>
          <label class="fld">퇴사일<input class="input" type="date" name="leave" value="${esc(e.leave)}"></label>
          <label class="fld">근속<input class="input" value="${esc(tenure(e))}" disabled></label>
        </div></fieldset>
        <fieldset class="grp"><legend>개인정보 · 암호화 저장</legend><div class="fgrid">
          <label class="fld">주민등록번호 / 외국인등록번호<span class="rrn-wrap"><input class="input num" type="password" name="rrn" id="f-rrn" value="${esc(e.rrn)}" placeholder="000000-0000000" autocomplete="off"><button class="btn sm" type="button" data-act="rrn-peek">보기</button></span></label>
          <label class="fld">생년월일 (나이)<input class="input" value="${b === 'invalid' ? '번호 확인 필요' : b ? b + ' (' + ageOf(b) + '세)' : ''}" disabled></label>
          <label class="fld">휴대폰<input class="input num" name="mobile" value="${esc(e.mobile)}" placeholder="010-0000-0000"></label>
          <label class="fld">자택·기타 연락처<input class="input num" name="home" value="${esc(e.home)}"></label>
          <label class="fld wall">주소<input class="input" name="addr" value="${esc(e.addr)}"></label>
        </div></fieldset>
        <fieldset class="grp"><legend>외국인 근로자 · 근태</legend><div class="fgrid">
          <label class="fld">국적/비자·특이사항<input class="input" name="visa" value="${esc(e.visa)}" placeholder="예: 미얀마(E-9), 관리감독자"></label>
          <label class="fld">체류만료일<input class="input" type="date" name="exp" value="${esc(e.exp)}"></label>
          <label class="fld">원본 표시<input class="input" name="mark" value="${esc(e.mark)}"></label>
          <label class="chk fld" style="justify-content:flex-end;flex-direction:row"><input type="checkbox" name="target" ${e.target ? 'checked' : ''}> 근태 대상 (일일 근태·보고서 명단 포함)</label>
          <label class="fld wall">비고<textarea class="input" name="note">${esc(e.note)}</textarea></label>
        </div></fieldset>
        <div class="err" id="emp-err"></div>
      </div>
      <div class="mdl-f">${isNew ? '' : `<button class="btn danger" type="button" data-act="del-emp" data-id="${e.id}">삭제</button><span class="grow faint" style="font-size:12px">퇴사자는 삭제하지 말고 재직상태를 '퇴사'로 바꾸세요.${recCount ? ` (근태기록 ${recCount}건)` : ''}</span>`}
        <button class="btn" type="button" data-act="close">취소</button><button class="btn primary" type="submit">저장</button></div>
    </form></div>`);
    $('#f-emp').addEventListener('submit', (ev) => { ev.preventDefault(); saveEmp(ev.target, id); });
    $('#f-emp [name=name]').focus();
  }
  function saveEmp(f, id) {
    const g = (n) => (f.elements[n].value || '').trim();
    const d = { sabun: g('sabun'), status: g('status'), name: g('name'), eng: g('eng'), dept: g('dept'), pos: g('pos'), task: g('task'), sex: g('sex'),
      hire: g('hire'), leave: g('leave'), rrn: normRrn(g('rrn')).v, mobile: normPhone(g('mobile')), home: normPhone(g('home')), addr: g('addr'),
      visa: g('visa'), exp: g('exp'), mark: g('mark'), note: g('note'), target: f.elements.target.checked };
    if (!d.name || !d.dept) { $('#emp-err').textContent = '성명과 부서는 꼭 입력해야 합니다.'; return; }
    if (d.status === '퇴사' && !d.leave) d.leave = todayStr();
    if (d.status === '퇴사') d.target = false;
    if (!id) {
      const e = Object.assign({ id: uid() }, d);
      state.employees.push(e);
      addHist(d.hire, '입사', e, `${d.pos || ''} 입사`.trim());
    } else {
      const e = empById(id);
      DIFF.forEach(([k, l]) => { if ((e[k] || '') !== (d[k] || '') && k !== 'hire') addHist(todayStr(), k === 'dept' ? '부서이동' : k === 'pos' ? '승진' : '정보변경', e, `${l}: ${e[k] || '(없음)'} → ${d[k] || '(없음)'}`); });
      if (e.status !== d.status) {
        const t = d.status === '퇴사' ? '퇴사' : d.status === '휴직' ? '휴직' : e.status === '휴직' ? '복직' : '재입사';
        addHist(d.status === '퇴사' ? d.leave : todayStr(), t, Object.assign({}, e, d), t === '퇴사' ? `퇴사 (${d.leave})` : `${e.status} → ${d.status}`);
      }
      Object.assign(e, d);
    }
    save(); closeModal(); render(); toast('저장했습니다.');
  }

  // ================= 화면: 일일 근태 =================
  function vDaily() {
    const d = ui.date, roster = dailyRoster(d), meta = state.dayMeta[d] || {};
    const types = S().types;
    const rows = roster.map((e, i) => {
      const r = getRec(d, e.id) || {}, c = calc(r);
      return `<tr data-row="${e.id}" class="${rowCls(r)}"><td class="c num">${i + 1}</td><td>${esc(e.dept)}</td><td>${esc(e.pos)}</td>
        <td class="nm"><b>${esc(e.name)}</b>${e.eng ? `<small>${esc(e.eng)}</small>` : ''}</td>
        <td><select class="input" data-att="type" data-id="${e.id}" aria-label="${esc(e.name)} 근태구분"><option value="">미입력</option>${types.map((t) => `<option ${r.type === t ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></td>
        <td><input class="input num" type="time" data-att="in" data-id="${e.id}" value="${esc(r.in || '')}" aria-label="출근"></td>
        <td><input class="input num" type="time" data-att="out" data-id="${e.id}" value="${esc(r.out || '')}" aria-label="퇴근"></td>
        <td><input class="input num brk" type="number" min="0" step="0.5" data-att="brk" data-id="${e.id}" value="${esc(r.brk == null ? '' : r.brk)}" placeholder="${esc(S().brk)}" aria-label="휴게시간"></td>
        <td class="r num" data-o="h">${c ? fmtH(c.h) : ''}</td><td class="r num" data-o="ot">${c && c.ot ? fmtH(c.ot) : ''}</td>
        <td><input class="input note" data-att="note" data-id="${e.id}" value="${esc(r.note || '')}" aria-label="비고"></td></tr>`;
    }).join('');
    const dt = parseYMD(d);
    return `<div class="page-h"><div><h1>일일 근태 · 근무시간보고서</h1><p>출퇴근 시각을 비워 두고 '정상'을 고르면 기본 ${S().start}~${S().end}(휴게 ${S().brk}시간) = ${fmtH(stdHours())}시간으로 계산합니다.</p></div>
        <div class="bar"><button class="btn primary" data-act="print-daily">보고서 인쇄</button></div></div>
      <div class="bar">
        <button class="btn" data-act="day" data-n="-1" aria-label="전날">◀</button>
        <input class="input num" type="date" value="${d}" data-ch="date" aria-label="날짜">
        <b class="${dt.getDay() === 0 ? 'pill bad' : dt.getDay() === 6 ? 'pill acc' : 'pill mute'}">${WD[dt.getDay()]}요일</b>
        <button class="btn" data-act="day" data-n="1" aria-label="다음날">▶</button>
        <button class="btn quiet" data-act="day" data-n="0">오늘</button>
        <span class="grow"></span>
        <button class="btn" data-act="fill-normal">미입력자 모두 '정상'</button>
        <button class="btn danger" data-act="clear-day">이 날짜 기록 지우기</button>
      </div>
      <div class="bar"><label class="fld" style="flex:0 1 200px">작성자<input class="input" data-meta="writer" value="${esc(meta.writer || '')}"></label>
        <label class="fld" style="flex:1 1 320px">작업내용<input class="input" data-meta="work" value="${esc(meta.work || '')}"></label></div>
      <div class="chips" id="day-sum">${daySummary(d)}</div>
      <div class="tw"><table class="t"><thead><tr><th>번호</th><th>부서</th><th>직책</th><th>이름</th><th>근태구분</th><th>출근</th><th>퇴근</th><th>휴게(h)</th><th>근무시간</th><th>연장</th><th>비고</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="11" class="empty">근태 대상 직원이 없습니다. 인사기록부에서 근태대상을 체크하세요.</td></tr>'}</tbody></table></div>`;
  }
  function rowCls(r) { if (!hasRec(r)) return 'miss'; if (r.type === '결근') return 'absent'; return ''; }
  function daySummary(d) {
    const roster = dailyRoster(d); let ent = 0, abs = 0, h = 0, ot = 0, late = 0, lv = 0;
    roster.forEach((e) => { const r = getRec(d, e.id), c = calc(r); if (!c) return; ent++; h += c.h; ot += c.ot; if (r.type === '결근') abs++; if (r.type === '지각' || r.type === '조퇴') late++; if (['연차', '반차'].concat(LEAVE_TYPES).includes(r.type)) lv++; });
    const miss = roster.length - ent;
    return `<span class="chip">대상 <b>${roster.length}</b></span><span class="chip">입력 <b>${ent}</b></span><span class="chip ${miss ? 'warn' : ''}">미입력 <b>${miss}</b></span>
      <span class="chip ${abs ? 'bad' : ''}">결근 <b>${abs}</b></span><span class="chip">지각·조퇴 <b>${late}</b></span><span class="chip">휴가 <b>${lv}</b></span>
      <span class="chip">총 근무 <b>${fmtH(h) || 0}</b>시간</span><span class="chip">연장 <b>${fmtH(ot) || 0}</b>시간</span>`;
  }
  function setAtt(id, f, val) {
    const d = ui.date;
    const day = state.att[d] || (state.att[d] = {});
    const r = day[id] || (day[id] = {});
    if (val === '' || val == null) delete r[f]; else r[f] = val;
    if ((f === 'in' || f === 'out') && val && !r.type) {
      r.type = '정상';
      const sel = $(`select[data-att="type"][data-id="${id}"]`); if (sel) sel.value = '정상';
    }
    if (!hasRec(r) && !r.note && r.brk == null) delete day[id];
    if (!Object.keys(day).length) delete state.att[d];
    save();
    const tr = $(`tr[data-row="${id}"]`);
    if (tr) {
      const c = calc(getRec(d, id));
      tr.className = rowCls(getRec(d, id));
      $('[data-o="h"]', tr).textContent = c ? fmtH(c.h) : '';
      $('[data-o="ot"]', tr).textContent = c && c.ot ? fmtH(c.ot) : '';
    }
    const s = $('#day-sum'); if (s) s.innerHTML = daySummary(d);
  }

  // ================= 화면: 월간 근태 =================
  function cellOf(r) {
    const c = calc(r); if (!c) return null;
    if (r.type === '결근') return { t: '결', cls: 'code-결' };
    if (r.type === '연차' && !c.h) return { t: '연', cls: 'code-연' };
    if (r.type === '반차' && !(r.in && r.out)) return { t: '반', cls: 'code-반' };
    if (LEAVE_TYPES.includes(r.type) && !c.h) return { t: '휴', cls: 'code-휴' };
    return { t: fmtH(c.h), cls: c.ot ? 'ot' : '' };
  }
  function monthTable(ym, forPrint) {
    const n = monthDays(ym), st = monthStats(ym).by, roster = monthRoster(ym);
    const days = Array.from({ length: n }, (_, i) => `${ym}-${pad(i + 1)}`);
    const dayTot = days.map(() => 0);
    const tot = { days: 0, h: 0, ot: 0, 지각: 0, 조퇴: 0, 결근: 0, 연차: 0, 반차: 0, 휴가: 0 };
    const body = roster.map((e, i) => {
      const s = st[e.id] || { days: 0, h: 0, ot: 0, 지각: 0, 조퇴: 0, 결근: 0, 연차: 0, 반차: 0, 휴가: 0 };
      Object.keys(tot).forEach((k) => (tot[k] += s[k]));
      const cells = days.map((d, j) => {
        const r = getRec(d, e.id), c = cellOf(r), w = parseYMD(d).getDay();
        if (r) { const cc = calc(r); if (cc) dayTot[j] += cc.h; }
        const we = w === 0 || w === 6 ? ' we' : '';
        return `<td class="d num${we}${c ? ' has ' + c.cls : ''}" ${!forPrint ? `data-act="go-daily" data-d="${d}"` : ''} ${r ? `title="${esc(r.type || '')} ${esc(r.in || '')}${r.out ? '~' + esc(r.out) : ''} ${esc(r.note || '')}"` : ''}>${c ? esc(c.t) : ''}</td>`;
      }).join('');
      return `<tr><td class="c num">${i + 1}</td><td class="stick nm"><b>${esc(e.name)}</b></td><td>${esc(e.dept)}</td><td>${esc(e.pos)}</td>
        <td class="r num">${s.days || '-'}</td><td class="r num">${fmtH(s.h) || '-'}</td><td class="r num">${fmtH(s.ot) || '-'}</td>
        <td class="r num">${s.지각 || '-'}</td><td class="r num">${s.조퇴 || '-'}</td><td class="r num">${s.결근 || '-'}</td><td class="r num">${s.연차 + s.반차 / 2 || '-'}</td><td class="r num">${s.휴가 || '-'}</td>${cells}</tr>`;
    }).join('');
    const head = days.map((d) => { const w = parseYMD(d).getDay(); return `<th class="d ${w === 0 ? 'sun' : w === 6 ? 'sat' : ''}">${+d.slice(8)}<br>${WD[w]}</th>`; }).join('');
    return `<table class="t month"><thead><tr><th>번호</th><th class="stick">성명</th><th>부서</th><th>직책</th><th>근무<br>일수</th><th>총근무<br>시간</th><th>연장<br>시간</th><th>지각</th><th>조퇴</th><th>결근</th><th>연차</th><th>기타<br>휴가</th>${head}</tr></thead>
      <tbody>${body || `<tr><td colspan="${12 + n}" class="empty">이 달의 근태 대상·기록이 없습니다.</td></tr>`}</tbody>
      <tfoot><tr><td colspan="4" class="stick">합계</td><td class="r num">${tot.days}</td><td class="r num">${fmtH(tot.h) || 0}</td><td class="r num">${fmtH(tot.ot) || 0}</td><td class="r num">${tot.지각}</td><td class="r num">${tot.조퇴}</td><td class="r num">${tot.결근}</td><td class="r num">${tot.연차 + tot.반차 / 2}</td><td class="r num">${tot.휴가}</td>${dayTot.map((h) => `<td class="d num">${fmtH(h) || ''}</td>`).join('')}</tr></tfoot></table>`;
  }
  function vMonth() {
    const ym = ui.month;
    return `<div class="page-h"><div><h1>월간 근태</h1><p>칸 숫자 = 근무시간 · <b>결</b> 결근 · <b>연</b> 연차 · <b>반</b> 반차 · <b>휴</b> 병가·경조·공가 · 주황 숫자 = 연장근무. 날짜 칸을 누르면 그날 근태로 이동합니다.</p></div>
      <div class="bar"><button class="btn" data-act="xlsx-month">엑셀로 저장</button><button class="btn primary" data-act="print-month">인쇄</button></div></div>
      <div class="bar"><button class="btn" data-act="mon" data-n="-1" aria-label="이전 달">◀</button>
        <input class="input num" type="month" value="${ym}" data-ch="month" aria-label="조회 월">
        <button class="btn" data-act="mon" data-n="1" aria-label="다음 달">▶</button><button class="btn quiet" data-act="mon" data-n="0">이번 달</button></div>
      <div class="tw">${monthTable(ym)}</div>`;
  }

  // ================= 화면: 인사변동 =================
  function vHist() {
    const H = state.history.slice().sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
    const names = state.employees.map((e) => `<option value="${esc(e.name)}">`).join('');
    return `<div class="page-h"><div><h1>인사변동 이력</h1><p>인사기록부에서 입사·퇴사·부서·직책·체류만료일을 바꾸면 자동으로 기록됩니다. 그 밖의 일은 직접 추가하세요.</p></div></div>
      <form class="sec" id="f-hist" autocomplete="off"><h2>이력 추가</h2><div class="fgrid">
        <label class="fld">일자<input class="input" type="date" name="date" value="${todayStr()}" required></label>
        <label class="fld">구분<select class="input" name="type">${['입사', '퇴사', '부서이동', '승진', '휴직', '복직', '체류연장', '교육', '포상', '징계', '정보변경', '기타'].map((t) => `<option>${t}</option>`).join('')}</select></label>
        <label class="fld">성명<input class="input" name="name" list="dl-names" required><datalist id="dl-names">${names}</datalist></label>
        <label class="fld w2">내용<input class="input" name="content" required></label>
      </div><div class="bar" style="margin-top:10px"><button class="btn primary" type="submit">추가</button></div></form>
      <div class="tw"><table class="t"><thead><tr><th>일자</th><th>구분</th><th>성명</th><th>부서</th><th>내용</th><th>근거</th><th></th></tr></thead>
      <tbody>${H.map((h) => `<tr><td class="num">${h.date}</td><td class="c"><span class="pill ${histCls(h.type)}">${esc(h.type)}</span></td><td><b>${esc(h.name)}</b></td><td>${esc(h.dept)}</td><td class="wrap">${esc(h.content)}</td><td class="faint">${esc(h.src)}</td><td><button class="btn quiet sm" data-act="del-hist" data-id="${h.id}" aria-label="삭제">삭제</button></td></tr>`).join('') || '<tr><td colspan="7" class="empty">기록이 없습니다.</td></tr>'}</tbody></table></div>`;
  }

  // ================= 화면: 설정·데이터 =================
  function vSet() {
    const s = S();
    return `<div class="page-h"><div><h1>설정 · 데이터</h1><p>바꾼 값은 바로 저장됩니다.</p></div></div>
      <div class="grid2">
        <section class="sec"><h2>근무 기준</h2><div class="fgrid">
          <label class="fld">기본 출근<input class="input" type="time" data-set="start" value="${esc(s.start)}"></label>
          <label class="fld">기본 퇴근<input class="input" type="time" data-set="end" value="${esc(s.end)}"></label>
          <label class="fld">기본 휴게(시간)<input class="input" type="number" min="0" step="0.5" data-set="brk" value="${esc(s.brk)}"></label>
          <label class="fld">1일 소정근로<input class="input" value="${fmtH(stdHours())}시간" disabled></label>
          <label class="fld">체류만료 경고(일)<input class="input" type="number" min="0" data-set="warn" value="${esc(s.warn)}"></label>
          <label class="fld">자동 잠금(분, 0=끔)<input class="input" type="number" min="0" data-set="lockMin" value="${esc(s.lockMin)}"></label>
          <label class="fld">보고서 문서번호<input class="input" data-set="docNo" value="${esc(s.docNo)}"></label>
          <label class="fld">회사명<input class="input" data-set="company" value="${esc(s.company)}"></label>
        </div></section>
        <section class="sec"><h2>선택 목록 <small>쉼표로 구분</small></h2><div class="fgrid">
          <label class="fld wall">부서<textarea class="input" data-setlist="depts">${esc(s.depts.join(', '))}</textarea></label>
          <label class="fld wall">직책<textarea class="input" data-setlist="positions">${esc(s.positions.join(', '))}</textarea></label>
          <label class="fld wall">근태구분<textarea class="input" data-setlist="types">${esc(s.types.join(', '))}</textarea></label>
        </div></section>
        <section class="sec"><h2>엑셀 가져오기</h2>
          <p class="muted">직원명부(날짜별 시트), 근무시간보고서 양식, 이 프로그램에서 내보낸 엑셀을 가져올 수 있습니다. 이미 있는 직원은 이름으로 찾아 정보를 갱신하고, 바뀐 내용은 인사변동에 기록합니다.</p>
          <label class="btn primary">엑셀 파일 선택<input type="file" accept=".xlsx,.xls" multiple hidden data-ch="import"></label></section>
        <section class="sec"><h2>내보내기 · 백업</h2>
          <p class="muted"><b>암호화 백업</b>은 지금 비밀번호로 잠긴 파일이라 USB 등에 보관해도 안전합니다. 서버는 저장할 때마다 data/backups 폴더에 자동 백업도 남깁니다.</p>
          <div class="bar"><button class="btn primary" data-act="backup">암호화 백업 저장</button><label class="btn">백업 파일로 복원<input type="file" accept=".json,.hrbak" hidden data-ch="restore"></label></div>
          <p class="muted" style="margin-top:12px"><b>엑셀 내보내기</b> 파일은 암호화되지 않습니다. 외부로 보내지 마세요.</p>
          <div class="bar"><label class="chk"><input type="checkbox" id="mask-xlsx" checked> 주민번호 뒷자리 가리기</label><button class="btn" data-act="xlsx-all">엑셀로 내보내기</button></div></section>
        <section class="sec"><h2>보안</h2>
          <form id="f-pw" class="fgrid" autocomplete="off">
            <label class="fld">현재 비밀번호<input class="input" type="password" name="cur" autocomplete="current-password" required></label>
            <label class="fld">새 비밀번호 (8자 이상)<input class="input" type="password" name="p1" autocomplete="new-password" required minlength="8"></label>
            <label class="fld">새 비밀번호 확인<input class="input" type="password" name="p2" autocomplete="new-password" required></label>
            <div class="wall bar"><button class="btn primary" type="submit">비밀번호 변경</button><span class="err" id="pw-err"></span></div>
          </form>
          <p class="muted">암호화: AES-256-GCM · 키 생성: PBKDF2-SHA256 ${KDF.c.toLocaleString()}회 · 서버에는 암호문만 저장됩니다.</p></section>
        <section class="sec"><h2>모든 데이터 지우기</h2>
          <p class="muted">직원·근태·이력을 모두 지웁니다. 서버의 자동 백업은 남습니다.</p>
          <button class="btn danger" data-act="wipe">모든 데이터 지우기</button></section>
      </div>`;
  }
  async function changePw(f) {
    const err = $('#pw-err'), cur = f.elements.cur.value, p1 = f.elements.p1.value, p2 = f.elements.p2.value;
    if (p1.length < 8) { err.textContent = '새 비밀번호는 8자 이상이어야 합니다.'; return; }
    if (p1 !== p2) { err.textContent = '새 비밀번호 두 개가 다릅니다.'; return; }
    err.textContent = '확인 중…';
    const old = await derive(cur, SALT);
    if (old.auth !== AUTH) { err.textContent = '현재 비밀번호가 맞지 않습니다.'; return; }
    await persist();
    const salt = b64(C.randomBytes(16)), nk = await derive(p1, salt);
    const r = await api('POST', '/api/rekey', { base: VERSION, salt, auth: nk.auth, box: seal(state, nk.key) });
    if (!r.ok) { err.textContent = r.status === 409 ? '다른 PC에서 방금 저장했습니다. 잠시 후 다시 시도하세요.' : '변경 실패 (' + r.status + ')'; return; }
    SALT = salt; KEY = nk.key; AUTH = nk.auth; VERSION = r.data.version;
    f.reset(); err.textContent = ''; toast('비밀번호를 바꿨습니다. 다른 PC에서는 새 비밀번호로 다시 로그인해야 합니다.');
  }

  // ================= 엑셀 가져오기 =================
  const cellStr = (v) => (v == null ? '' : String(v).trim());
  function grid(ws) {
    if (!ws || !ws['!ref']) return [];
    const r = XLSX.utils.decode_range(ws['!ref']), out = [];
    for (let R = 0; R <= r.e.r; R++) {
      const row = [];
      for (let c = 0; c <= r.e.c; c++) { const cell = ws[XLSX.utils.encode_cell({ r: R, c })]; row.push(cell ? cell.v : null); }
      out.push(row);
    }
    return out;
  }
  function toYMD(v) {
    if (v == null || v === '') return '';
    if (typeof v === 'number') { const d = new Date(Math.round((v - 25569) * 86400000)); return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`; }
    const m = String(v).trim().match(/^(\d{4})[-./년\s]+(\d{1,2})[-./월\s]+(\d{1,2})/);
    return m ? `${m[1]}-${pad(m[2])}-${pad(m[3])}` : '';
  }
  function toHM(v) {
    if (v == null || v === '') return '';
    if (typeof v === 'number') { const mins = Math.round((v % 1) * 1440) % 1440; return pad(Math.floor(mins / 60)) + ':' + pad(mins % 60); }
    const m = String(v).match(/(\d{1,2}):(\d{2})/); return m ? pad(m[1]) + ':' + m[2] : '';
  }
  function normPhone(p) {
    let s = cellStr(p);
    if (/^\d{10}$/.test(s) && s.startsWith('10')) s = '0' + s;
    if (/^010\d{8}$/.test(s)) return `${s.slice(0, 3)}-${s.slice(3, 7)}-${s.slice(7)}`;
    return s;
  }
  function normRrn(x) {
    const raw = cellStr(x), s = digits(raw);
    if (!raw) return { v: '' };
    if (s.length === 13) return { v: `${s.slice(0, 6)}-${s.slice(6)}` };
    if (s.length === 6) return { v: s + '-' };
    return { v: raw };
  }
  const defaultTarget = (e) => e.status !== '퇴사' && (e.dept === '생산부' || e.dept === '물류부') && !['이사', '상무', '대표이사'].includes(e.pos);
  const norm = (s) => cellStr(s).replace(/\s+/g, '');

  function isRosterSheet(g) { return g.slice(0, 8).some((row) => row.some((c) => /직원명부/.test(cellStr(c)))) || (g[4] && norm(g[4][3]) === '성명'); }
  function isReportSheet(g) { return g.slice(0, 4).some((row) => row.some((c) => norm(c).includes('근무시간보고서'))); }
  function sheetDate(name) { const m = name.match(/(\d{4})[.\-_](\d{1,2})[.\-_](\d{1,2})/); return m ? `${m[1]}-${pad(m[2])}-${pad(m[3])}` : ''; }
  function parseRoster(g) {
    const rows = [];
    for (let r = 6; r < g.length; r++) {
      const v = g[r] || [];
      const name = cellStr(v[3]);
      if (!name || norm(v[1]) === '비고') continue;
      let home = cellStr(v[9]), eng = '';
      if (/[A-Za-z]/.test(home)) { eng = home; home = ''; }
      rows.push({ mark: cellStr(v[0]), dept: cellStr(v[2]), name, pos: cellStr(v[4]), hire: toYMD(v[5]), sex: cellStr(v[6]), rrn: normRrn(v[7]).v,
        mobile: normPhone(v[8]), home: normPhone(home), eng, addr: cellStr(v[10]), task: cellStr(v[14]), visa: cellStr(v[15]), exp: toYMD(v[16]), note: cellStr(v[18]) });
    }
    return rows;
  }
  function headerIndex(g, must) {
    for (let r = 0; r < Math.min(g.length, 8); r++) {
      const map = {}; (g[r] || []).forEach((c, i) => { const k = norm(c); if (k && !(k in map)) map[k] = i; });
      if (must.every((m) => m in map)) return { row: r, map };
    }
    return null;
  }
  function blankEmp(o) {
    return Object.assign({ id: uid(), sabun: '', status: '재직', dept: '', name: '', eng: '', pos: '', task: '', hire: '', leave: '', sex: '', rrn: '', mobile: '', home: '', addr: '', visa: '', exp: '', target: false, mark: '', note: '' }, o);
  }
  function findEmp(r) {
    return state.employees.find((x) => x.name === r.name && (!x.rrn || !r.rrn || digits(x.rrn).slice(0, 6) === digits(r.rrn).slice(0, 6)));
  }
  function mergeRow(r, src, date) {
    const e = findEmp(r);
    if (!e) {
      const n = blankEmp(r); n.sabun = r.sabun || nextSabun();
      if (r.target == null) n.target = defaultTarget(n);
      state.employees.push(n);
      addHist(r.hire || date, '입사', n, `${n.pos || ''} 입사${n.visa ? ' · ' + n.visa : ''}`.trim(), src);
      return 'added';
    }
    let ch = false;
    DIFF.forEach(([k, l]) => { if (r[k] && r[k] !== e[k]) { addHist(date, '정보변경', e, `${l}: ${e[k] || '(없음)'} → ${r[k]}`, src); e[k] = r[k]; ch = true; } });
    ['eng', 'sex', 'rrn', 'mobile', 'home', 'addr', 'mark', 'note', 'status', 'leave', 'sabun'].forEach((k) => { if (r[k] && r[k] !== e[k]) { e[k] = r[k]; ch = true; } });
    if (r.target != null && r.target !== e.target) { e.target = r.target; ch = true; }
    return ch ? 'updated' : 'same';
  }

  function importRosterBook(wb, fname) {
    const snaps = wb.SheetNames.map((n) => ({ n, g: grid(wb.Sheets[n]) })).filter((s) => isRosterSheet(s.g))
      .map((s) => ({ name: s.n, date: sheetDate(s.n), rows: parseRoster(s.g) })).filter((s) => s.rows.length);
    if (!snaps.length) return null;
    if (snaps.every((s) => s.date)) snaps.sort((a, b) => (a.date < b.date ? -1 : 1));
    const latest = snaps[snaps.length - 1];
    const src = (s) => `명부 ${s.name}`;
    const out = { added: 0, updated: 0, left: [] };
    if (!state.employees.length) {
      // 처음: 최신 명부를 기준으로 만들고, 이전 명부와 비교해 이력·퇴사자를 정리
      const latestNames = latest.rows.map((r) => r.name);
      const leavers = {};
      snaps.slice(0, -1).forEach((s, i) => s.rows.forEach((r) => {
        if (latestNames.includes(r.name)) return;
        const gone = snaps.slice(i + 1).find((x) => !x.rows.some((y) => y.name === r.name));
        const prev = s.rows[s.rows.indexOf(r) - 1];
        leavers[r.name] = { r, last: s, gone, prev: prev ? prev.name : null };
      }));
      latest.rows.forEach((r) => {
        const e = blankEmp(r); e.sabun = nextSabun(); e.target = defaultTarget(e); state.employees.push(e);
        Object.values(leavers).filter((l) => l.prev === r.name).forEach((l) => {
          const x = blankEmp(l.r); x.sabun = nextSabun(); x.status = '퇴사'; x.target = false;
          x.note = [l.r.note, `${l.last.name} 명부까지 재직, ${l.gone.name} 명부에서 제외(퇴사일 확인 필요)`].filter(Boolean).join(' / ');
          state.employees.push(x); out.left.push(x.name);
        });
      });
      for (let i = 1; i < snaps.length; i++) {
        const a = snaps[i - 1], b = snaps[i], date = b.date || todayStr();
        b.rows.forEach((r) => {
          const p = a.rows.find((x) => x.name === r.name), e = state.employees.find((x) => x.name === r.name);
          if (!p) addHist(r.hire || date, '입사', e, `${r.pos || ''} 입사${r.visa ? ' · ' + r.visa : ''}`.trim(), src(b));
          else DIFF.forEach(([k, l]) => { if ((p[k] || '') !== (r[k] || '')) addHist(date, '정보변경', e, `${l}: ${p[k] || '(없음)'} → ${r[k] || '(없음)'}`, src(b)); });
        });
        a.rows.forEach((r) => { if (!b.rows.some((x) => x.name === r.name)) addHist(date, '퇴사', state.employees.find((x) => x.name === r.name), `${a.name} 명부 이후 제외 – 실제 퇴사일 확인 필요`, src(b)); });
      }
      out.added = state.employees.length;
    } else {
      latest.rows.forEach((r) => { const k = mergeRow(r, src(latest), latest.date || todayStr()); if (k === 'added') out.added++; if (k === 'updated') out.updated++; });
    }
    return `${fname}: 직원명부 ${snaps.length}개 시트(최신 ${latest.name}) → 추가 ${out.added}명, 갱신 ${out.updated}명${out.left.length ? `, 퇴사 처리 ${out.left.join(', ')}(퇴사일 확인 필요)` : ''}`;
  }
  function importReportBook(wb, fname) {
    for (const n of wb.SheetNames) {
      const g = grid(wb.Sheets[n]);
      if (!isReportSheet(g)) continue;
      const h = headerIndex(g, ['이름']); if (!h) continue;
      const col = h.map['이름'], names = [];
      for (let r = h.row + 1; r < g.length; r++) { const v = norm(g[r][col]); if (!v || /한길/.test(v)) continue; names.push(v); }
      if (!names.length) continue;
      const missing = names.filter((x) => !state.employees.some((e) => e.name === x));
      state.employees.forEach((e) => { e.target = e.status !== '퇴사' && names.includes(e.name); });
      return `${fname}: 근무시간보고서 명단 ${names.length}명을 근태 대상으로 지정${missing.length ? ` (명부에 없는 이름: ${missing.join(', ')})` : ''}`;
    }
    return null;
  }
  function importAppBook(wb, fname) {
    const ws = wb.Sheets['인사기록부']; if (!ws) return null;
    const g = grid(ws), h = headerIndex(g, ['성명', '부서']); if (!h) return null;
    const F = { 사번: 'sabun', 재직상태: 'status', 부서: 'dept', 성명: 'name', 영문명: 'eng', 직책: 'pos', '소속/업무': 'task', 입사일: 'hire', 퇴사일: 'leave', 성별: 'sex',
      주민등록번호: 'rrn', 휴대폰: 'mobile', '자택/기타연락처': 'home', 주소: 'addr', '국적/비자·특이': 'visa', 체류만료일: 'exp', 근태대상: 'target', 원본표시: 'mark', 비고: 'note' };
    const fresh = !state.employees.length; let added = 0, updated = 0, recs = 0, hs = 0;
    for (let r = h.row + 1; r < g.length; r++) {
      const v = g[r]; const o = {};
      Object.keys(F).forEach((k) => { if (k in h.map) o[F[k]] = v[h.map[k]]; });
      o.name = cellStr(o.name); if (!o.name) continue;
      ['sabun', 'status', 'dept', 'eng', 'pos', 'task', 'sex', 'addr', 'visa', 'mark', 'note'].forEach((k) => (o[k] = cellStr(o[k])));
      ['hire', 'leave', 'exp'].forEach((k) => (o[k] = toYMD(o[k])));
      o.rrn = normRrn(o.rrn).v; o.mobile = normPhone(o.mobile); o.home = normPhone(o.home);
      o.target = o.target == null ? null : cellStr(o.target).toUpperCase() === 'Y';
      if (/●|\*/.test(o.rrn)) delete o.rrn; // 가린 번호는 덮어쓰지 않음
      if (!o.status) o.status = '재직';
      if (fresh) { const e = blankEmp(o); if (!e.sabun) e.sabun = nextSabun(); if (o.target == null) e.target = defaultTarget(e); state.employees.push(e); added++; }
      else { const k = mergeRow(o, fname, todayStr()); if (k === 'added') added++; if (k === 'updated') updated++; }
    }
    const wa = wb.Sheets['근태입력'] || wb.Sheets['근태기록'];
    if (wa) {
      const ga = grid(wa), ha = headerIndex(ga, ['날짜', '성명']);
      if (ha) for (let r = ha.row + 1; r < ga.length; r++) {
        const v = ga[r], m = ha.map, date = toYMD(v[m['날짜']]), name = cellStr(v[m['성명']]);
        const note = cellStr(v[m['비고']]);
        if (!date || !name || /예시/.test(note)) continue;
        const e = state.employees.find((x) => x.name === name); if (!e) continue;
        const rec = {};
        const t = cellStr(v[m['근태구분']]); if (t) rec.type = t;
        const i = toHM(v[m['출근']]), o = toHM(v[m['퇴근']]); if (i) rec.in = i; if (o) rec.out = o;
        const b = v[m['휴게(h)']]; if (b !== null && b !== undefined && b !== '') rec.brk = Number(b);
        if (note) rec.note = note;
        if (!hasRec(rec)) continue;
        (state.att[date] || (state.att[date] = {}))[e.id] = rec; recs++;
      }
    }
    const wh = wb.Sheets['인사변동이력'];
    if (wh) {
      const gh = grid(wh), hh = headerIndex(gh, ['일자', '구분', '성명']);
      if (hh) for (let r = hh.row + 1; r < gh.length; r++) {
        const v = gh[r], m = hh.map, date = toYMD(v[m['일자']]), name = cellStr(v[m['성명']]);
        if (!date || !name) continue;
        const item = { id: uid(), date, type: cellStr(v[m['구분']]), name, dept: cellStr(v[m['부서']]), content: cellStr(v[m['내용']]), src: cellStr(v[m['근거']]) || fname };
        const e = state.employees.find((x) => x.name === name); item.empId = e ? e.id : '';
        if (!state.history.some((x) => x.date === item.date && x.name === item.name && x.content === item.content)) { state.history.push(item); hs++; }
      }
    }
    return `${fname}: 인사기록부 추가 ${added}명·갱신 ${updated}명, 근태기록 ${recs}건, 변동이력 ${hs}건`;
  }
  async function importFiles(files) {
    if (state.sample) { const keep = state.settings; state = emptyState(); state.settings = keep; }
    const msgs = [];
    // 명부/통합파일을 먼저 처리해야 보고서 명단을 맞출 수 있다
    const books = [];
    for (const f of files) {
      try { books.push({ f, wb: XLSX.read(new Uint8Array(await f.arrayBuffer()), { type: 'array' }) }); }
      catch (e) { msgs.push(`${f.name}: 엑셀 파일을 읽지 못했습니다.`); }
    }
    books.sort((a, b) => (isReportOnly(a.wb) ? 1 : 0) - (isReportOnly(b.wb) ? 1 : 0));
    for (const { f, wb } of books) {
      const m = importAppBook(wb, f.name) || importRosterBook(wb, f.name) || importReportBook(wb, f.name);
      msgs.push(m || `${f.name}: 알아볼 수 있는 양식이 아닙니다 (직원명부·근무시간보고서·내보낸 엑셀만 지원).`);
    }
    save(); render();
    openModal(`<div class="mdl sm"><div class="mdl-h"><h3>가져오기 결과</h3></div><div class="mdl-b">${msgs.map((m) => `<p style="margin:0">${esc(m)}</p>`).join('')}
      <p class="muted" style="margin:0">근무시간보고서 파일을 함께 가져오지 않았다면, 근태 대상은 생산부·물류부(임원 제외)로 정했습니다. 인사기록부의 근태대상 칸에서 바꿀 수 있습니다.</p></div>
      <div class="mdl-f"><button class="btn primary" data-act="close">확인</button></div></div>`);
  }
  const isReportOnly = (wb) => !wb.Sheets['인사기록부'] && wb.SheetNames.every((n) => !isRosterSheet(grid(wb.Sheets[n])));

  // ================= 내보내기·백업 =================
  function download(blob, name) {
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function monthSheetRows(ym) {
    const n = monthDays(ym), st = monthStats(ym).by;
    return monthRoster(ym).map((e) => {
      const s = st[e.id] || { days: 0, h: 0, ot: 0, 지각: 0, 조퇴: 0, 결근: 0, 연차: 0, 반차: 0, 휴가: 0 };
      const o = { 사번: e.sabun, 성명: e.name, 부서: e.dept, 직책: e.pos, 근무일수: s.days, 총근무시간: Math.round(s.h * 100) / 100, 연장시간: Math.round(s.ot * 100) / 100, 지각: s.지각, 조퇴: s.조퇴, 결근: s.결근, 연차: s.연차 + s.반차 / 2, 기타휴가: s.휴가 };
      for (let d = 1; d <= n; d++) { const c = cellOf(getRec(`${ym}-${pad(d)}`, e.id)); o[d + '일'] = c ? (isNaN(+c.t) ? c.t : +c.t) : ''; }
      return o;
    });
  }
  function exportXlsx(all) {
    const wb = XLSX.utils.book_new();
    if (all) {
      const mask = $('#mask-xlsx') ? $('#mask-xlsx').checked : true;
      const emp = state.employees.map((e) => { const b = birthOf(e.rrn); return { 사번: e.sabun, 재직상태: e.status, 부서: e.dept, 성명: e.name, 영문명: e.eng, 직책: e.pos, '소속/업무': e.task, 입사일: e.hire, 퇴사일: e.leave, 근속기간: tenure(e), 성별: e.sex,
        주민등록번호: mask ? maskRrn(e.rrn) : e.rrn, 생년월일: b === 'invalid' ? '확인필요' : b || '', 휴대폰: e.mobile, '자택/기타연락처': e.home, 주소: e.addr, '국적/비자·특이': e.visa, 체류만료일: e.exp, 체류상태: visaState(e), 근태대상: e.target ? 'Y' : 'N', 원본표시: e.mark, 비고: e.note }; });
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(emp), '인사기록부');
      const att = [];
      Object.keys(state.att).sort().forEach((d) => state.employees.forEach((e) => {
        const r = getRec(d, e.id), c = calc(r); if (!r) return;
        att.push({ 날짜: d, 성명: e.name, 사번: e.sabun, 부서: e.dept, 직책: e.pos, 근태구분: r.type || '', 출근: r.in || '', 퇴근: r.out || '', '휴게(h)': r.brk == null ? '' : r.brk, 근무시간: c ? c.h : '', 연장시간: c ? c.ot : '', 비고: r.note || '' });
      }));
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(att.length ? att : [{ 날짜: '', 성명: '' }]), '근태입력');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(monthSheetRows(ui.month)), `월간근태 ${ui.month}`);
      const hist = state.history.slice().sort((a, b) => (a.date < b.date ? -1 : 1)).map((h) => ({ 일자: h.date, 구분: h.type, 성명: h.name, 부서: h.dept, 내용: h.content, 근거: h.src }));
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(hist.length ? hist : [{ 일자: '' }]), '인사변동이력');
      XLSX.writeFile(wb, `한길_인사근태_${todayStr()}.xlsx`);
    } else {
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(monthSheetRows(ui.month)), `월간근태 ${ui.month}`);
      XLSX.writeFile(wb, `한길_월간근태_${ui.month}.xlsx`);
    }
  }
  function backup() {
    const box = seal(state);
    const file = { app: 'hangil-hr-backup', v: 1, salt: SALT, kdf: KDF, iv: box.iv, ct: box.ct, exportedAt: new Date().toISOString() };
    download(new Blob([JSON.stringify(file)], { type: 'application/json' }), `한길_인사근태_암호화백업_${todayStr()}.json`);
    toast('암호화 백업 파일을 저장했습니다.');
  }
  async function restoreFile(file) {
    let data;
    try { data = JSON.parse(await file.text()); } catch (e) { toast('백업 파일을 읽지 못했습니다.', { bad: true }); return; }
    if (data.app !== 'hangil-hr-backup') { toast('이 프로그램의 백업 파일이 아닙니다.', { bad: true }); return; }
    openModal(`<div class="mdl sm"><form id="f-restore" autocomplete="off"><div class="mdl-h"><h3>백업 복원</h3></div><div class="mdl-b">
      <p style="margin:0">${esc(file.name)} (${esc((data.exportedAt || '').slice(0, 10))} 저장)</p>
      <p class="muted" style="margin:0">복원하면 지금 데이터가 백업 내용으로 <b>모두 바뀝니다</b>. 백업을 만들 때의 비밀번호를 입력하세요.</p>
      <label class="fld">백업 파일 비밀번호<input class="input" type="password" id="rs-pw" required></label><div class="err" id="rs-err"></div></div>
      <div class="mdl-f"><button class="btn" type="button" data-act="close">취소</button><button class="btn primary" type="submit">복원</button></div></form></div>`);
    $('#rs-pw').focus();
    $('#f-restore').addEventListener('submit', async (ev) => {
      ev.preventDefault(); $('#rs-err').textContent = '확인 중…';
      try {
        const d = await derive($('#rs-pw').value, data.salt, data.kdf);
        state = normalize(unseal({ iv: data.iv, ct: data.ct }, d.key));
        save(); closeModal(); render(); toast('백업을 복원했습니다.');
      } catch (e) { $('#rs-err').textContent = '비밀번호가 맞지 않거나 파일이 손상되었습니다.'; }
    });
  }

  // ================= 인쇄 =================
  function printWith(html, landscape) {
    $('#print-root').innerHTML = `<style>@page{size:A4 ${landscape ? 'landscape' : 'portrait'};margin:10mm}</style>` + html;
    setTimeout(() => window.print(), 50);
  }
  function printDaily() {
    const d = ui.date, dt = parseYMD(d), roster = dailyRoster(d), meta = state.dayMeta[d] || {};
    let tot = 0, ot = 0, ent = 0;
    const rows = roster.map((e, i) => {
      const r = getRec(d, e.id) || {}, c = calc(r); if (c) { tot += c.h; ot += c.ot; ent++; }
      return `<tr><td>${i + 1}</td><td>${esc(e.dept)}</td><td>${esc(e.pos)}</td><td>${esc(e.name)}</td><td>${esc(r.in || '')}</td><td>${esc(r.out || '')}</td><td>${c ? fmtH(c.h) : ''}</td><td>${c && c.ot ? fmtH(c.ot) : ''}</td><td>${esc(r.type || '')}</td><td class="l">${esc(r.note || '')}</td></tr>`;
    });
    while (rows.length < 30) rows.push('<tr>' + '<td>&nbsp;</td>'.repeat(10) + '</tr>');
    printWith(`<div class="pr"><div class="docno">문서번호 : ${esc(S().docNo)}</div><h1>근무시간보고서</h1>
      <div class="head"><table class="info" style="width:60%"><tr><td class="k">일 자</td><td>${dt.getFullYear()}년 ${dt.getMonth() + 1}월 ${dt.getDate()}일 ${WD[dt.getDay()]}요일</td></tr>
        <tr><td class="k">작성자</td><td>${esc(meta.writer || '')}</td></tr><tr><td class="k">작업내용</td><td>${esc(meta.work || '')}</td></tr></table>
        <table class="sign"><tr><th>담당</th><th>팀장</th><th>대표</th></tr><tr><td></td><td></td><td></td></tr></table></div>
      <table><thead><tr><th style="width:8mm">번호</th><th>부서</th><th>직책</th><th>이름</th><th>출근</th><th>퇴근</th><th>근무시간</th><th>연장</th><th>근태내용</th><th style="width:45mm">비고</th></tr></thead>
      <tbody>${rows.join('')}<tr class="sum"><td colspan="4">합 계</td><td colspan="2">출근 ${roster.filter((e) => { const c = calc(getRec(d, e.id)); return c && c.h > 0; }).length}명</td><td>${fmtH(tot)}</td><td>${fmtH(ot)}</td><td colspan="2">입력 ${ent} / 대상 ${roster.length}</td></tr></tbody></table>
      <div class="foot">${esc(S().company)}</div></div>`, false);
  }
  function printMonth() {
    printWith(`<div class="pr month"><h1>${ui.month.slice(0, 4)}년 ${+ui.month.slice(5)}월 근태 현황</h1>${monthTable(ui.month, true).replace(/class="t month"/, '')}<div class="docno">${esc(S().company)} · 출력 ${todayStr()}</div></div>`, true);
  }

  // ================= 모달·토스트 =================
  function openModal(html) { $('#modal-root').innerHTML = `<div class="ov" data-act="ov">${html}</div>`; }
  function closeModal() { $('#modal-root').innerHTML = ''; }
  function toast(msg, o) {
    o = o || {};
    const el = document.createElement('div'); el.className = 'toast' + (o.bad ? ' bad' : '');
    el.innerHTML = `<span>${esc(msg)}</span>`;
    if (o.undo) { const b = document.createElement('button'); b.textContent = '되돌리기'; b.onclick = () => { o.undo(); el.remove(); }; el.appendChild(b); }
    $('#toast-root').appendChild(el);
    setTimeout(() => el.remove(), o.ms || (o.undo ? 6000 : 3000));
  }
  function arm(btn, label) { // 두 번 눌러야 실행되는 위험 버튼
    if (btn.dataset.armed) return true;
    btn.dataset.armed = '1'; btn.dataset.label = btn.textContent; btn.textContent = label || '한 번 더 누르면 실행'; btn.classList.add('armed');
    setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = btn.dataset.label; btn.classList.remove('armed'); } }, 3500);
    return false;
  }

  // ================= 예시 데이터 =================
  function loadSample() {
    state = emptyState(); state.sample = true;
    const t = todayStr();
    const list = [
      ['관리부', '예시 김관리', '대리', '2021-03-05', '남', '950205-1******', '', ''],
      ['생산부', '예시 이생산', '부장', '2003-12-01', '남', '671215-1******', '', ''],
      ['생산부', '예시 박작업', '사원', '2018-04-23', '여', '651130-2******', '', ''],
      ['생산부', '예시 아웅', '사원', '2024-09-26', '남', '870806-5******', '미얀마(E-9)', addDays(t, 60)],
      ['생산부', '예시 수닐', '사원', '2023-03-29', '남', '960620-5******', '네팔(E-9)', addDays(t, 400)],
      ['물류부', '예시 최물류', '사원', '2025-04-24', '남', '681011-1******', '', ''],
    ];
    list.forEach(([dept, name, pos, hire, sex, rrn, visa, exp]) => {
      const e = blankEmp({ dept, name, pos, hire, sex, rrn, visa, exp, mobile: '010-0000-0000', note: '예시 데이터' });
      e.sabun = nextSabun(); e.target = defaultTarget(e); state.employees.push(e);
      addHist(hire, '입사', e, `${pos} 입사`, '예시');
    });
    const days = [addDays(t, -2), addDays(t, -1)];
    days.forEach((d) => {
      state.employees.filter((e) => e.target).forEach((e, i) => {
        (state.att[d] || (state.att[d] = {}))[e.id] = i === 1 && d === days[1] ? { type: '연차' } : i === 3 ? { type: '정상', in: '08:00', out: '19:30', brk: 1.5 } : { type: '정상' };
      });
    });
    save(); render(); toast('예시 데이터를 불러왔습니다.');
  }

  // ================= 이벤트 =================
  document.addEventListener('click', async (ev) => {
    ui.lastAct = Date.now();
    const el = ev.target.closest('[data-act]'); if (!el) return;
    const act = el.dataset.act;
    if (act === 'ov') { if (ev.target === el) closeModal(); return; }
    if (el.tagName === 'A') ev.preventDefault();
    if (ev.target.closest('input[type=checkbox]') && act === 'edit') return;
    switch (act) {
      case 'view': ui.view = el.dataset.v; render(); window.scrollTo(0, 0); break;
      case 'lock': lock(); break;
      case 'close': closeModal(); break;
      case 'edit': empModal(el.dataset.id); break;
      case 'new-emp': empModal(null); break;
      case 'del-emp': {
        if (!arm(el, '근태기록까지 삭제 · 한 번 더')) return;
        const id = el.dataset.id;
        state.employees = state.employees.filter((e) => e.id !== id);
        Object.keys(state.att).forEach((d) => { delete state.att[d][id]; if (!Object.keys(state.att[d]).length) delete state.att[d]; });
        save(); closeModal(); render(); toast('직원을 삭제했습니다.'); break;
      }
      case 'rrn-peek': { const i = $('#f-rrn'); const show = i.type === 'password'; i.type = show ? 'text' : 'password'; el.textContent = show ? '가리기' : '보기'; break; }
      case 'rrn': ui.rrnUntil = showRrn() ? 0 : Date.now() + 60000; render(); if (showRrn()) setTimeout(() => { if (ui.view === 'emp' && state) render(); }, 60500); break;
      case 'sort-emp':
        state.employees.sort((a, b) => (a.status === '퇴사') - (b.status === '퇴사') || deptRank(a.dept) - deptRank(b.dept) || posRank(a.pos) - posRank(b.pos) || String(a.hire || '9').localeCompare(String(b.hire || '9')));
        save(); render(); toast('부서 → 직책 → 입사일 순으로 정렬했습니다.'); break;
      case 'day': ui.date = el.dataset.n === '0' ? todayStr() : addDays(ui.date, +el.dataset.n); render(); break;
      case 'go-daily': ui.date = el.dataset.d; ui.view = 'daily'; render(); window.scrollTo(0, 0); break;
      case 'mon': ui.month = el.dataset.n === '0' ? todayStr().slice(0, 7) : addMonths(ui.month, +el.dataset.n); render(); break;
      case 'fill-normal': {
        let n = 0; const d = ui.date;
        dailyRoster(d).forEach((e) => { if (!hasRec(getRec(d, e.id))) { const day = state.att[d] || (state.att[d] = {}); day[e.id] = Object.assign(day[e.id] || {}, { type: '정상' }); n++; } });
        save(); render(); toast(`${n}명을 '정상'으로 입력했습니다.`); break;
      }
      case 'clear-day': {
        if (!arm(el)) return;
        const d = ui.date, prev = state.att[d], prevMeta = state.dayMeta[d];
        delete state.att[d]; delete state.dayMeta[d]; save(); render();
        toast(`${d} 기록을 지웠습니다.`, { undo: () => { if (prev) state.att[d] = prev; if (prevMeta) state.dayMeta[d] = prevMeta; save(); render(); } });
        break;
      }
      case 'print-daily': printDaily(); break;
      case 'print-month': printMonth(); break;
      case 'xlsx-month': exportXlsx(false); break;
      case 'xlsx-all': exportXlsx(true); break;
      case 'backup': backup(); break;
      case 'sample': loadSample(); break;
      case 'del-hist': {
        const i = state.history.findIndex((h) => h.id === el.dataset.id); if (i < 0) return;
        const [item] = state.history.splice(i, 1); save(); render();
        toast('이력을 삭제했습니다.', { undo: () => { state.history.push(item); save(); render(); } }); break;
      }
      case 'wipe': {
        if (!arm(el, '정말 모두 지울까요? 한 번 더')) return;
        const keep = state.settings; state = emptyState(); state.settings = keep; save(); ui.view = 'dash'; render(); toast('모든 데이터를 지웠습니다.'); break;
      }
    }
  });
  document.addEventListener('change', (ev) => {
    if (!state) return;
    const el = ev.target; ui.lastAct = Date.now();
    if (el.dataset.att) { setAtt(el.dataset.id, el.dataset.att, el.dataset.att === 'brk' ? (el.value === '' ? '' : Number(el.value)) : el.value); return; }
    if (el.dataset.meta) { const m = state.dayMeta[ui.date] || (state.dayMeta[ui.date] = {}); m[el.dataset.meta] = el.value; save(); return; }
    if (el.dataset.set) { const k = el.dataset.set; S()[k] = ['brk', 'warn', 'lockMin'].includes(k) ? Number(el.value || 0) : el.value; save(); if (k === 'start' || k === 'end' || k === 'brk') render(); return; }
    if (el.dataset.setlist) { S()[el.dataset.setlist] = el.value.split(/[,\n]/).map((x) => x.trim()).filter(Boolean); save(); return; }
    switch (el.dataset.ch) {
      case 'target': { const e = empById(el.dataset.id); e.target = el.checked; save(); break; }
      case 'dept': ui.dept = el.value; render(); break;
      case 'status': ui.status = el.value; render(); break;
      case 'date': if (el.value) { ui.date = el.value; render(); } break;
      case 'month': if (el.value) { ui.month = el.value; render(); } break;
      case 'import': if (el.files.length) importFiles(Array.from(el.files)); el.value = ''; break;
      case 'restore': if (el.files[0]) restoreFile(el.files[0]); el.value = ''; break;
    }
  });
  document.addEventListener('input', (ev) => {
    if (ev.target.dataset.in === 'q') {
      ui.q = ev.target.value;
      const pos = ev.target.selectionStart; render();
      const q = $('#emp-q'); if (q) { q.focus(); q.setSelectionRange(pos, pos); }
    }
  });
  document.addEventListener('submit', (ev) => {
    if (ev.target.id === 'f-hist') {
      ev.preventDefault();
      const f = ev.target, name = f.elements.name.value.trim(), e = state.employees.find((x) => x.name === name);
      state.history.push({ id: uid(), date: f.elements.date.value, type: f.elements.type.value, empId: e ? e.id : '', name, dept: e ? e.dept : '', content: f.elements.content.value.trim(), src: '직접 입력' });
      save(); render(); toast('이력을 추가했습니다.');
    } else if (ev.target.id === 'f-pw') { ev.preventDefault(); changePw(ev.target); }
  });
  document.addEventListener('keydown', (ev) => { ui.lastAct = Date.now(); if (ev.key === 'Escape' && $('#modal-root').innerHTML) closeModal(); });
  ['mousemove', 'touchstart', 'scroll'].forEach((t) => document.addEventListener(t, () => (ui.lastAct = Date.now()), { passive: true }));
  window.addEventListener('beforeunload', (ev) => { if (dirty) { persist(); ev.preventDefault(); ev.returnValue = ''; } });
  window.addEventListener('afterprint', () => { $('#print-root').innerHTML = ''; });

  setInterval(() => { // 자동 잠금
    if (state && S().lockMin > 0 && Date.now() - ui.lastAct > S().lockMin * 60000) lock('오래 사용하지 않아 자동으로 잠갔습니다.');
  }, 20000);
  setInterval(poll, 30000);

  boot();
})();
