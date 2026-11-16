/* nuvem.js — o Controle de Gastos rodando pelo GitHub (sem o computador ligado).
 *
 * COMO FUNCIONA
 * - O código do app fica num repositório PÚBLICO servido pelo GitHub Pages (só código, nenhum dado).
 * - Os dados ficam num repositório PRIVADO, na pasta dados/, e vão CRIPTOGRAFADOS (AES-GCM 256): o GitHub (e quem
 *   vir o repositório) só enxerga bytes embaralhados. A chave dos dados (DEK) é aleatória e fica guardada em
 *   dados/cofre.json, trancada por uma chave derivada da SENHA DO COFRE (PBKDF2-SHA256, 600 mil voltas).
 * - Cada aparelho guarda, no IndexedDB, a chave de acesso do GitHub + a DEK trancadas duas vezes: pelo PIN do aparelho
 *   (PBKDF2) e por uma chave do próprio navegador que não pode ser exportada. Abrir o app = digitar só o PIN.
 *   5 PINs errados apagam essa caixa do aparelho (aí é preciso a senha do cofre de novo).
 * - Sincronização: cada lançamento tem a hora da última alteração; ao juntar o que está no GitHub com o que está no
 *   aparelho vence a alteração mais recente DE CADA LANÇAMENTO (dois aparelhos mexendo em coisas diferentes não perdem
 *   nada). Exclusões ficam marcadas (apagados.enc) para não "ressuscitar". A configuração vence pela mais recente.
 *   O histórico de commits do repositório privado é o backup de todas as versões.
 *
 * ARQUIVOS NO REPOSITÓRIO PRIVADO (pasta dados/)
 *   cofre.json      sal + DEK trancada pela senha (não tem dado nenhum)
 *   config.enc      {mod, config}
 *   apagados.enc    {del: {id: quando}}
 *   tx-AAAA.enc     {recs: {id: [quando, lançamento]}}  (lançamentos pelo ano da data)
 *   galeria.enc     imagens da galeria de cartões (só baixada quando a galeria é aberta)
 *
 * Fica ligado quando o app é aberto pelo GitHub Pages (*.github.io) ou com ?nuvem=1 (testes no computador).
 */
(function (raiz) {
  'use strict';
  const C = raiz.crypto && raiz.crypto.subtle ? raiz.crypto : null;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const PASTA = 'dados';
  const ITER_SENHA = 600000, ITER_PIN = 300000, MAX_ERROS_PIN = 5, MIN_SENHA = 8;
  const RE_DADOS = /^(config|apagados|tx-\d{4})\.enc$/;

  /* ------------------------------------------------------------------ utilidades */
  const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = s => { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
  const b64url = s => b64(enc.encode(s)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64url = s => dec.decode(unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)));
  const rand = n => C.getRandomValues(new Uint8Array(n));
  const clone = x => JSON.parse(JSON.stringify(x));
  const escH = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const erro = (code, msg) => Object.assign(new Error(msg), { code, msg });
  const espera = ms => new Promise(r => setTimeout(r, ms));

  /* ------------------------------------------------------------------ criptografia */
  async function pbkdf2(segredo, salt, iter) {
    const base = await C.subtle.importKey('raw', enc.encode(segredo), 'PBKDF2', false, ['deriveKey']);
    return C.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function cifrar(chave, bytes) {
    const iv = rand(12);
    return { iv: b64(iv), ct: b64(new Uint8Array(await C.subtle.encrypt({ name: 'AES-GCM', iv }, chave, bytes))) };
  }
  async function decifrar(chave, o) {
    return new Uint8Array(await C.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, chave, unb64(o.ct)));
  }
  const importarDek = raw => C.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  async function gzip(bytes, desfazer) {
    const S = desfazer ? raiz.DecompressionStream : raiz.CompressionStream;
    if (!S) { if (desfazer) throw erro('compressao', 'Este navegador é antigo demais para abrir os dados.'); return null; }
    const st = new Blob([bytes]).stream().pipeThrough(new S('gzip'));
    return new Uint8Array(await new Response(st).arrayBuffer());
  }
  // objeto -> texto do arquivo criptografado (JSON compactado com gzip e cifrado)
  async function selar(dek, obj) {
    const raw = enc.encode(JSON.stringify(obj));
    const z = await gzip(raw);
    return JSON.stringify({ v: 1, z: z ? 1 : 0, ...(await cifrar(dek, z || raw)) });
  }
  async function abrirSelado(dek, texto) {
    const o = JSON.parse(texto);
    let b;
    try { b = await decifrar(dek, o); } catch (_) { throw erro('cripto', 'Não consegui abrir os dados (chave errada ou arquivo corrompido).'); }
    if (o.z) b = await gzip(b, true);
    return JSON.parse(dec.decode(b));
  }
  async function hashTexto(s) {
    const h = new Uint8Array(await C.subtle.digest('SHA-256', enc.encode(s)));
    return Array.from(h, x => x.toString(16).padStart(2, '0')).join('');
  }
  const hashObj = o => hashTexto(JSON.stringify(o));

  /* ------------------------------------------------------------------ cofre (senha -> chave dos dados) */
  async function criarCofre(senha) {
    const dekRaw = rand(32), salt = rand(16);
    const kek = await pbkdf2(senha, salt, ITER_SENHA);
    const cofre = { v: 1, app: 'controle-de-gastos', kdf: { nome: 'PBKDF2-SHA256', iter: ITER_SENHA, salt: b64(salt) },
      chave: await cifrar(kek, dekRaw), criado: new Date().toISOString() };
    return { cofre, dekRaw, kek };
  }
  const kekDoCofre = (cofre, senha) => pbkdf2(senha, unb64(cofre.kdf.salt), cofre.kdf.iter);
  async function abrirCofre(cofre, kek) {
    try { return await decifrar(kek, cofre.chave); }
    catch (_) { throw erro('senha', 'Senha do cofre incorreta.'); }
  }

  /* ------------------------------------------------------------------ GitHub (API Contents) */
  function GH(o) {
    const base = `https://api.github.com/repos/${encodeURIComponent(o.dono)}/${encodeURIComponent(o.repo)}`;
    const f = Nuvem._fetch || ((...a) => raiz.fetch(...a));
    async function req(caminho, op = {}) {
      const h = { Authorization: 'Bearer ' + o.token, Accept: op.raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
      if (op.body) h['Content-Type'] = 'application/json';
      let r;
      try { r = await f(base + caminho, { method: op.method || 'GET', cache: 'no-store', headers: h, body: op.body ? JSON.stringify(op.body) : undefined }); }
      catch (e) { throw erro('rede', 'Sem conexão com o GitHub.'); }
      if (r.status === 401) throw erro('token', 'A chave de acesso do GitHub é inválida, venceu ou foi revogada.');
      return r;
    }
    const falha = async r => { let m = ''; try { m = (await r.json()).message || ''; } catch (_) {} return erro('http', `GitHub respondeu ${r.status}${m ? ': ' + m : ''}`); };
    return {
      dono: o.dono, repo: o.repo, token: o.token,
      async info() {
        const r = await req('');
        if (r.status === 404) throw erro('repo', 'Repositório não encontrado (confira o nome, ou a chave não tem acesso a ele).');
        if (!r.ok) throw await falha(r);
        return r.json();
      },
      async listar() {
        const r = await req('/contents/' + PASTA);
        if (r.status === 404) return [];
        if (!r.ok) throw await falha(r);
        const l = await r.json();
        return Array.isArray(l) ? l.filter(x => x.type === 'file').map(x => ({ nome: x.name, sha: x.sha })) : [];
      },
      async ler(nome) {
        const r = await req(`/contents/${PASTA}/${nome}`, { raw: true });
        if (r.status === 404) return null;
        if (!r.ok) throw await falha(r);
        return r.text();
      },
      async gravar(nome, texto, sha) {
        const r = await req(`/contents/${PASTA}/${nome}`, { method: 'PUT', body: { message: `app: ${nome}`, content: b64(enc.encode(texto)), ...(sha ? { sha } : {}) } });
        if (r.status === 409 || r.status === 422) throw erro('conflito', 'O arquivo mudou no GitHub enquanto era gravado.');
        if (!r.ok) throw await falha(r);
        return (await r.json()).content.sha;
      },
    };
  }
  async function conferirRepo(gh) {
    const info = await gh.info();
    if (!info.private) throw erro('publico', `O repositório "${gh.repo}" é PÚBLICO. Os dados só podem ir para um repositório privado.`);
    if (info.permissions && !info.permissions.push) throw erro('permissao', 'A chave de acesso não tem permissão de escrita (Contents: Read and write).');
    return info;
  }

  /* ------------------------------------------------------------------ armazenamento do aparelho (IndexedDB) */
  // IndexedDB (guarda a chave do navegador como CryptoKey não exportável). Sem IndexedDB (testes): memória.
  const kv = {
    _db: null, mem: new Map(),
    async _abrir() {
      if (this._db) return this._db;
      this._db = await new Promise((ok, no) => {
        const r = raiz.indexedDB.open('cg-nuvem', 1);
        r.onupgradeneeded = () => r.result.createObjectStore('kv');
        r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error);
      });
      return this._db;
    },
    async _op(modo, fn) {
      const db = await this._abrir();
      return new Promise((ok, no) => {
        const t = db.transaction('kv', modo), r = fn(t.objectStore('kv'));
        t.oncomplete = () => ok(r.result); t.onerror = () => no(t.error);
      });
    },
    async get(k) { return raiz.indexedDB ? this._op('readonly', st => st.get(k)) : this.mem.get(k); },
    async set(k, v) { if (raiz.indexedDB) await this._op('readwrite', st => st.put(v, k)); else this.mem.set(k, v); },
    async del(k) { if (raiz.indexedDB) await this._op('readwrite', st => st.delete(k)); else this.mem.delete(k); },
  };

  // caixa do aparelho: {token, dek} trancados pela chave do navegador (não exportável) e depois pelo PIN
  async function guardarAparelho(dados, pin) {
    let kdev = await kv.get('kdev');
    if (!kdev) { kdev = await C.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); await kv.set('kdev', kdev); }
    const dentro = await cifrar(kdev, enc.encode(JSON.stringify({ token: dados.token, dek: b64(dados.dekRaw) })));
    const salt = rand(16), kpin = await pbkdf2(pin, salt, ITER_PIN);
    const caixa = await cifrar(kpin, enc.encode(JSON.stringify(dentro)));
    await kv.set('aparelho', { v: 1, dono: dados.dono, repo: dados.repo, pin: { salt: b64(salt), iter: ITER_PIN, n: pin.length }, caixa, em: Date.now() });
    await kv.set('erros', 0);
    // pede ao navegador para não apagar estes dados quando faltar espaço (assim só o PIN é pedido nas próximas vezes)
    try { if (raiz.navigator && raiz.navigator.storage && raiz.navigator.storage.persist) await raiz.navigator.storage.persist(); } catch (_) {}
  }
  async function abrirAparelho(ap, pin) {
    const kpin = await pbkdf2(pin, unb64(ap.pin.salt), ap.pin.iter);
    let dentro;
    try { dentro = JSON.parse(dec.decode(await decifrar(kpin, ap.caixa))); }
    catch (_) {
      const n = ((await kv.get('erros')) || 0) + 1;
      if (n >= MAX_ERROS_PIN) { await esquecerAparelho(); throw erro('pin_apagado', 'PIN errado 5 vezes: por segurança este aparelho foi desconectado. Entre com a senha do cofre.'); }
      await kv.set('erros', n);
      const r = MAX_ERROS_PIN - n;
      throw erro('pin', `PIN incorreto (${r} tentativa${r > 1 ? 's' : ''} antes de pedir a senha)`);
    }
    const kdev = await kv.get('kdev');
    if (!kdev) throw erro('pin_apagado', 'A chave deste navegador sumiu: entre com a senha do cofre.');
    const p = JSON.parse(dec.decode(await decifrar(kdev, dentro)));
    await kv.set('erros', 0);
    return { dono: ap.dono, repo: ap.repo, token: p.token, dekRaw: unb64(p.dek) };
  }
  async function esquecerAparelho() { for (const k of ['aparelho', 'cache', 'erros']) await kv.del(k); }

  /* ------------------------------------------------------------------ estado em memória + sincronização */
  const S = {
    gh: null, dek: null, dekRaw: null, dono: '', repo: '',
    cfg: { mod: 0, config: null }, recs: {}, del: {}, shas: {}, up: {},
    ocupado: null, pendente: false, timer: null, cacheTimer: null,
    ultimo: 0, erro: null, aoMudar: null, aoStatus: null, galeria: null,
  };
  const particao = r => { const a = String((r && r.data) || '').slice(0, 4); return /^\d{4}$/.test(a) ? `tx-${a}.enc` : 'tx-0000.enc'; };

  function resolver() {
    let mudou = false;
    for (const id in S.del) { const r = S.recs[id]; if (r && r[0] <= S.del[id]) { delete S.recs[id]; mudou = true; } }
    return mudou;
  }
  // junta um arquivo do GitHub com o que está no aparelho. Devolve true se algo mudou aqui.
  function mesclar(nome, obj) {
    let mudou = false;
    if (nome === 'config.enc') {
      if (obj && obj.mod > S.cfg.mod) { S.cfg = { mod: obj.mod, config: obj.config }; mudou = true; }
    } else if (nome === 'apagados.enc') {
      for (const [id, ts] of Object.entries((obj && obj.del) || {})) if (!(S.del[id] >= ts)) S.del[id] = ts;
      mudou = resolver() || mudou;
    } else if (/^tx-\d{4}\.enc$/.test(nome)) {
      for (const [id, par] of Object.entries((obj && obj.recs) || {})) {
        const cur = S.recs[id];
        if ((!cur || par[0] > cur[0]) && !(S.del[id] >= par[0])) { S.recs[id] = par; mudou = true; }
      }
    }
    return mudou;
  }
  function conteudoLocal() {
    const m = new Map();
    if (S.cfg.config || S.shas['config.enc']) m.set('config.enc', { mod: S.cfg.mod, config: S.cfg.config });
    const del = {}; for (const k of Object.keys(S.del).sort()) del[k] = S.del[k];
    if (Object.keys(del).length || S.shas['apagados.enc']) m.set('apagados.enc', { del });
    for (const nome of Object.keys(S.shas)) if (/^tx-\d{4}\.enc$/.test(nome)) m.set(nome, { recs: {} });
    for (const id of Object.keys(S.recs).sort()) {
      const n = particao(S.recs[id][1]);
      if (!m.has(n)) m.set(n, { recs: {} });
      m.get(n).recs[id] = S.recs[id];
    }
    return m;
  }
  function dados() {
    return { config: S.cfg.config ? clone(S.cfg.config) : null, tx: Object.values(S.recs).map(p => clone(p[1])) };
  }

  async function salvarCache() {
    if (!S.dek || S.semCache) return;
    const txt = await selar(S.dek, { dono: S.dono, repo: S.repo, cfg: S.cfg, recs: S.recs, del: S.del, shas: S.shas, up: S.up });
    await kv.set('cache', txt);
  }
  function agendarCache() { clearTimeout(S.cacheTimer); S.cacheTimer = setTimeout(() => salvarCache().catch(e => console.error('nuvem: cache', e)), 150); }
  async function lerCache() {
    const txt = await kv.get('cache'); if (!txt) return false;
    try {
      const c = await abrirSelado(S.dek, txt);
      if (c.dono !== S.dono || c.repo !== S.repo) return false;
      Object.assign(S, { cfg: c.cfg, recs: c.recs, del: c.del, shas: c.shas, up: c.up });
      return true;
    } catch (e) { console.error('nuvem: cache ilegível', e); return false; }
  }

  const status = () => { try { S.aoStatus && S.aoStatus(estado()); } catch (_) {} };
  function estado() {
    return { conectado: !!S.gh, dono: S.dono, repo: S.repo, ultimo: S.ultimo, sincronizando: !!S.ocupado,
      pendente: !!(S.timer || S.pendente), erro: S.erro ? (S.erro.msg || String(S.erro.message || S.erro)) : null, erroCode: S.erro && S.erro.code };
  }

  function sincronizar() {
    if (!S.gh) return Promise.resolve();
    if (S.ocupado) { S.pendente = true; return S.ocupado; }
    clearTimeout(S.timer); S.timer = null;
    S.ocupado = (async () => {
      let mudouAqui = false;
      for (let volta = 0; volta < 5; volta++) {
        const lista = await S.gh.listar();
        const remoto = new Map(lista.map(x => [x.nome, x.sha]));
        for (const [nome, sha] of remoto) {
          if (!RE_DADOS.test(nome) || S.shas[nome] === sha) continue;
          const txt = await S.gh.ler(nome); if (txt == null) continue;
          const obj = await abrirSelado(S.dek, txt);
          if (mesclar(nome, obj)) mudouAqui = true;
          S.shas[nome] = sha; S.up[nome] = await hashObj(obj);
        }
        for (const nome of Object.keys(S.shas)) if (!remoto.has(nome)) { delete S.shas[nome]; delete S.up[nome]; }   // apagado no GitHub: sobe de novo
        if (resolver()) mudouAqui = true;
        let conflito = false;
        for (const [nome, obj] of conteudoLocal()) {
          const h = await hashObj(obj);
          if (S.up[nome] === h && S.shas[nome]) continue;
          try { S.shas[nome] = await S.gh.gravar(nome, await selar(S.dek, obj), S.shas[nome]); S.up[nome] = h; }
          catch (e) { if (e.code === 'conflito') { conflito = true; delete S.shas[nome]; break; } throw e; }
        }
        if (!conflito) break;
        await espera(300 + Math.random() * 700);
      }
      S.ultimo = Date.now(); S.erro = null;
      await salvarCache();
      if (mudouAqui && S.aoMudar) { try { S.aoMudar(); } catch (e) { console.error(e); } }
    })().catch(e => { S.erro = e; throw e; }).finally(() => {
      S.ocupado = null; status();
      if (S.pendente) { S.pendente = false; agendar(400); }
    });
    status();
    return S.ocupado;
  }
  function agendar(ms = 1500) {
    agendarCache();
    if (S.ocupado) { S.pendente = true; status(); return; }
    clearTimeout(S.timer);
    S.timer = setTimeout(() => { S.timer = null; sincronizar().catch(avisarErro); }, ms);
    status();
  }
  let _ultimoAviso = 0;
  function avisarErro(e) {
    console.error('nuvem: sincronização', e);
    if (e && e.code === 'rede') return;   // sem internet: fica salvo no aparelho e tenta de novo depois
    if (Date.now() - _ultimoAviso < 60000) return; _ultimoAviso = Date.now();
    if (typeof raiz.toast === 'function') raiz.toast('Nuvem: ' + (e.msg || e.message || 'falha ao sincronizar') + ' (seus dados continuam salvos neste aparelho)');
  }

  // gravações vindas do app (Store)
  function putTx(lista) {
    const agora = Date.now();
    for (const t of lista) {
      const id = String(t.id), cur = S.recs[id];
      S.recs[id] = [Math.max(agora, (cur ? cur[0] : 0) + 1, (S.del[id] || 0) + 1), clone(t)];
    }
    agendar();
  }
  function delTx(ids) {
    const agora = Date.now();
    for (const id of ids) { const cur = S.recs[id]; S.del[id] = Math.max(agora, cur ? cur[0] + 1 : 0); delete S.recs[id]; }
    agendar();
  }
  function salvarConfig(cfg) { S.cfg = { mod: Math.max(Date.now(), S.cfg.mod + 1), config: clone(cfg) }; agendar(); }

  /* ------------------------------------------------------------------ conexão (senha do cofre) */
  // conecta e abre o cofre. o: {dono, repo, token, senha, senha2?, criar?, convite?}. Devolve {gh, dekRaw, kek, novo}
  async function conectar(o) {
    let token = o.token, kek = null;
    if (o.convite) {   // link/QR de outro aparelho: a chave do GitHub vem trancada pela senha do cofre
      kek = await pbkdf2(o.senha, unb64(o.convite.s), o.convite.i);
      try { token = dec.decode(await decifrar(kek, o.convite.c)); } catch (_) { throw erro('senha', 'Senha do cofre incorreta.'); }
    }
    const gh = GH({ dono: o.dono, repo: o.repo, token });
    await conferirRepo(gh);
    const txt = await gh.ler('cofre.json');
    if (!txt) {
      if (!o.criar) throw erro('sem_cofre', 'Este repositório ainda não tem um cofre.');
      if (String(o.senha).length < MIN_SENHA) throw erro('senha_curta', `A senha do cofre precisa ter pelo menos ${MIN_SENHA} caracteres.`);
      if (o.senha !== o.senha2) throw erro('senha_dif', 'As duas senhas não são iguais.');
      const c = await criarCofre(o.senha);
      await gh.gravar('cofre.json', JSON.stringify(c.cofre, null, 1));
      return { gh, dekRaw: c.dekRaw, kek: c.kek, novo: true };
    }
    const cofre = JSON.parse(txt);
    if (!kek || o.convite.s !== cofre.kdf.salt) kek = await kekDoCofre(cofre, o.senha);
    return { gh, dekRaw: await abrirCofre(cofre, kek), kek, novo: false };
  }
  async function usar(c) {
    Object.assign(S, { gh: c.gh, dono: c.gh.dono, repo: c.gh.repo, dekRaw: c.dekRaw, dek: await importarDek(c.dekRaw),
      cfg: { mod: 0, config: null }, recs: {}, del: {}, shas: {}, up: {}, galeria: null });
  }

  /* ------------------------------------------------------------------ telas (PIN, senha, criar PIN) */
  const TECLADO = `<div class="travaTeclado">${[1, 2, 3, 4, 5, 6, 7, 8, 9].map(k => `<button type="button" data-k="${k}">${k}</button>`).join('')}
    <button type="button" data-k="ok" class="tecOk" aria-label="Confirmar">OK</button><button type="button" data-k="0">0</button>
    <button type="button" data-k="del" class="tecDel" aria-label="Apagar"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 5H9l-6 7 6 7h12z"/><path d="M17 9l-5 5M12 9l5 5"/></svg></button></div>`;
  let _tela = null;
  function tela(html) {
    if (!_tela) { _tela = raiz.document.createElement('div'); _tela.className = 'trava nvTela'; _tela.setAttribute('role', 'dialog'); raiz.document.body.appendChild(_tela); }
    _tela.innerHTML = `<div class="travaCx"><div class="travaLogo" aria-hidden="true">R$</div>${html}</div>`;
    _tela.hidden = false;
    return _tela;
  }
  function fecharTela() { if (_tela) { _tela.remove(); _tela = null; } }
  const q = sel => _tela.querySelector(sel);
  const msgErro = (m, tremer) => { const e = q('.travaErro'); if (e) e.textContent = m || ''; if (m && tremer) { const p = q('.travaPontos'); if (p) { p.classList.remove('erro'); void p.offsetWidth; p.classList.add('erro'); } } };

  // teclado numérico: resolve com o PIN digitado (n = tamanho fixo, confere sozinho no último dígito)
  function teclado({ titulo, sub, n, rodape }) {
    return new Promise(res => {
      tela(`<h2>${escH(titulo)}</h2><p class="travaSub">${escH(sub || '')}</p><div class="travaPontos" aria-hidden="true"></div>
        <div class="travaErro" role="alert"></div>${TECLADO}<div class="travaRodape">${rodape || ''}</div>`);
      let buf = '';
      const pontos = () => { const tot = n || Math.max(4, buf.length); q('.travaPontos').innerHTML = Array.from({ length: tot }, (_, i) => `<i class="${i < buf.length ? 'on' : ''}"></i>`).join(''); };
      q('.tecOk').hidden = !!n;
      const fim = () => { raiz.document.removeEventListener('keydown', tecla, true); };
      const enviar = () => { if (buf.length < 4) return msgErro('Use de 4 a 8 números', true); const p = buf; buf = ''; pontos(); fim(); res({ pin: p, tela: { recomecar: () => teclado({ titulo, sub, n, rodape }) } }); };
      const dig = k => { msgErro(''); if (k === 'del') buf = buf.slice(0, -1); else if (k === 'ok') return enviar(); else if (buf.length < 8) buf += k; pontos(); if (n && buf.length === n) enviar(); };
      function tecla(e) { if (/^\d$/.test(e.key)) { e.preventDefault(); dig(e.key); } else if (e.key === 'Backspace') { e.preventDefault(); dig('del'); } else if (e.key === 'Enter') { e.preventDefault(); dig('ok'); } }
      raiz.document.addEventListener('keydown', tecla, true);
      q('.travaTeclado').onclick = e => { const b = e.target.closest('button[data-k]'); if (b) dig(b.dataset.k); };
      _tela.querySelectorAll('[data-acao]').forEach(b => b.onclick = () => { fim(); res({ acao: b.dataset.acao }); });
      pontos();
    });
  }

  async function telaPin(ap) {
    let aviso = '';
    for (;;) {
      const r = await teclado({ titulo: 'Digite seu PIN', sub: aviso || `Cofre ${ap.dono}/${ap.repo}`, n: ap.pin.n,
        rodape: '<button type="button" class="linkish" data-acao="senha">Esqueci o PIN · entrar com a senha</button>' });
      if (r.acao === 'senha') return null;
      tela('<h2>Abrindo…</h2><p class="travaSub">Destrancando os dados neste aparelho</p><div class="travaErro" role="alert"></div>');
      try { return await abrirAparelho(ap, r.pin); }
      catch (e) { if (e.code === 'pin_apagado') { aviso = ''; await kv.del('aparelho'); return { apagado: e.msg }; } aviso = e.msg; }
    }
  }

  // último cofre usado neste aparelho; sem ele, no GitHub Pages o dono vem do endereço (usuario.github.io)
  function lerUltimo() {
    let u = {}; try { u = JSON.parse(raiz.localStorage.getItem('cg_nv_ultimo') || '{}'); } catch (_) {}
    const m = /^([a-z0-9-]+)\.github\.io$/i.exec(raiz.location.hostname || '');
    if (!u.dono && m) u = { dono: m[1], repo: 'controle-gastos-dados' };
    return u;
  }
  // formulário de entrada. o: {convite, acesso, aviso, titulo, botao, cancelar}
  // acesso = arquivo de acesso do site (acesso.json): só a senha do cofre; "outra conta" abre o formulário completo
  function telaSenha(o = {}) {
    return new Promise(res => {
      const u = o.convite ? { dono: o.convite.d, repo: o.convite.r } : lerUltimo();
      let criar = false, token = '';
      const desenhar = () => {
        tela(`<h2>${escH(o.titulo || (criar ? 'Criar o cofre' : 'Entrar'))}</h2>
          <p class="travaSub">${escH(criar ? 'Este repositório ainda não tem dados. Escolha a senha do cofre: ela tranca tudo e NÃO pode ser recuperada.'
            : o.acesso ? 'Digite a senha do cofre. Nas próximas vezes, neste aparelho, só o PIN.'
            : o.convite ? `Conectando este aparelho ao cofre ${o.convite.d}/${o.convite.r}. Digite a senha do cofre.`
            : 'Seus dados ficam num repositório privado do GitHub, criptografados com a senha do cofre.')}</p>
          <form class="travaRec nvForm" autocomplete="off">
            ${o.convite ? '' : `
            <label>Usuário do GitHub<input name="dono" autocomplete="username" autocapitalize="off" spellcheck="false" value="${escH(u.dono || '')}" placeholder="ex.: seu-usuario"></label>
            <label>Repositório de dados (privado)<input name="repo" autocapitalize="off" spellcheck="false" value="${escH(u.repo || '')}" placeholder="ex.: controle-gastos-dados"></label>
            <label>Chave de acesso (token)<input name="token" type="password" autocomplete="off" spellcheck="false" placeholder="github_pat_…" value="${escH(token)}"></label>
            <details class="nvAjuda"><summary>Como criar a chave?</summary>GitHub › Settings › Developer settings › Personal access tokens › <b>Fine-grained tokens</b> › Generate new token. Em "Repository access" escolha <b>Only select repositories</b> e marque só o repositório de dados. Em "Permissions" › Repository permissions › <b>Contents: Read and write</b>. Copie a chave e cole aqui (ela fica guardada trancada neste aparelho).</details>`}
            <label>Senha do cofre<input name="senha" type="password" autocomplete="${criar ? 'new-password' : 'current-password'}" maxlength="200"></label>
            ${criar ? '<label>Repita a senha<input name="senha2" type="password" autocomplete="new-password" maxlength="200"></label>' : ''}
            <div class="travaErro" role="alert">${escH(o.aviso || '')}</div>
            <button type="submit" class="btn primary">${escH(o.botao || (criar ? 'Criar cofre e entrar' : 'Entrar'))}</button>
          </form>
          <div class="travaRodape">${o.cancelar ? '<button type="button" class="linkish" data-acao="cancelar">Cancelar</button>' : ''}${o.acesso ? '<button type="button" class="linkish" data-acao="outra">Entrar com outra conta do GitHub</button>' : ''}</div>`);
        const f = q('form');
        const cancel = q('[data-acao="cancelar"]'); if (cancel) cancel.onclick = () => { fecharTela(); res(null); };
        const outra = q('[data-acao="outra"]'); if (outra) outra.onclick = () => res('outra');
        setTimeout(() => { try { (f.querySelector('input:not([value]),input[value=""]') || f.senha).focus(); } catch (_) {} }, 60);
        f.onsubmit = async e => {
          e.preventDefault();
          const v = n => (f[n] ? f[n].value.trim() : '');
          const d = { dono: o.convite ? o.convite.d : v('dono'), repo: o.convite ? o.convite.r : v('repo'), token: v('token'),
            senha: f.senha.value, senha2: f.senha2 ? f.senha2.value : '', criar, convite: o.convite };
          if (!d.dono || !d.repo || (!o.convite && !d.token)) return msgErro('Preencha usuário, repositório e chave de acesso.');
          if (!d.senha) return msgErro('Digite a senha do cofre.');
          const bt = f.querySelector('button[type=submit]'); bt.disabled = true; bt.textContent = criar ? 'Criando…' : 'Abrindo…';
          try {
            const c = await conectar(d);
            try { raiz.localStorage.setItem('cg_nv_ultimo', JSON.stringify({ dono: d.dono, repo: d.repo })); } catch (_) {}
            res(c);
          } catch (err) {
            if (err.code === 'sem_cofre') { criar = true; u.dono = d.dono; u.repo = d.repo; token = d.token; desenhar(); return; }
            bt.disabled = false; bt.textContent = o.botao || (criar ? 'Criar cofre e entrar' : 'Entrar');
            msgErro((err.msg || err.message || 'Não consegui conectar.') + (o.acesso && err.code === 'token'
              ? ' O arquivo de acesso do site está desatualizado: entre com outra conta (abaixo) e gere um novo em Ajustes › Nuvem.' : ''));
            if (err.code === 'senha') { f.senha.value = ''; f.senha.focus(); await espera(800); }
          }
        };
      };
      desenhar();
    });
  }

  async function telaCriarPin(sub) {
    let aviso = '';
    for (;;) {
      const a = await teclado({ titulo: 'Crie um PIN', sub: aviso || sub || 'De 4 a 8 números. Nas próximas vezes, neste aparelho, você só digita o PIN.' });
      const b = await teclado({ titulo: 'Confirme o PIN', sub: 'Digite o mesmo PIN de novo' });
      if (a.pin === b.pin) return a.pin;
      aviso = 'Os dois PINs não são iguais. Comece de novo.';
    }
  }

  // link/QR "conectar este aparelho": #conectar=<dados>
  function lerConvite() {
    const m = /^#conectar=([\w-]{20,})$/.exec(raiz.location.hash || '');
    if (!m) return null;
    try { raiz.history.replaceState(null, '', raiz.location.pathname + raiz.location.search); } catch (_) {}
    try { const c = JSON.parse(unb64url(m[1])); return c && c.d && c.r && c.s && c.c ? c : null; } catch (_) { return null; }
  }
  // convite: {d: dono, r: repo, s/i: sal e voltas do cofre, c: chave do GitHub cifrada pela senha do cofre}
  async function convite(senha) {
    const txt = await S.gh.ler('cofre.json'); const cofre = JSON.parse(txt);
    const kek = await kekDoCofre(cofre, senha);
    await abrirCofre(cofre, kek);   // confere a senha
    return { d: S.dono, r: S.repo, s: cofre.kdf.salt, i: cofre.kdf.iter, c: await cifrar(kek, enc.encode(S.gh.token)) };
  }
  async function criarConvite(senha) {
    return raiz.location.origin + raiz.location.pathname + '#conectar=' + b64url(JSON.stringify(await convite(senha)));
  }
  // arquivo de acesso publicado junto com o app (acesso.json): o mesmo convite, para entrar em aparelho novo só com a senha
  async function lerAcessoPublico() {
    try {
      const r = await raiz.fetch('acesso.json', { cache: 'no-store' });
      if (!r.ok) return null;
      const c = await r.json();
      return c && c.d && c.r && c.s && c.i && c.c && c.c.iv && c.c.ct ? c : null;
    } catch (_) { return null; }
  }

  /* ------------------------------------------------------------------ abrir o app */
  let _aberto = false;
  async function abrir() {
    registrarSW();
    const convite = lerConvite();
    let ap = await kv.get('aparelho'), aviso = '';
    if (convite && ap && (ap.dono !== convite.d || ap.repo !== convite.r)) ap = null;
    for (;;) {
      let c = null;
      if (ap && !convite) {
        const r = await telaPin(ap);
        if (r && r.apagado) { aviso = r.apagado; ap = null; continue; }
        if (!r) { ap = null; continue; }
        c = { gh: GH({ dono: r.dono, repo: r.repo, token: r.token }), dekRaw: r.dekRaw };
      } else {
        // aparelho novo: com o arquivo de acesso do site, só a senha do cofre; sem ele (ou "outra conta"), o formulário completo
        const acesso = convite ? null : await lerAcessoPublico();
        c = acesso ? await telaSenha({ convite: acesso, acesso: true, aviso }) : null;
        if (!c || c === 'outra') c = await telaSenha({ convite, aviso });
        aviso = '';
        const pin = await telaCriarPin(c.novo ? 'Cofre criado. Agora um PIN para este aparelho: nas próximas vezes você só digita o PIN.' : null);
        tela('<h2>Guardando…</h2><p class="travaSub">Trancando o acesso neste aparelho com o PIN</p>');
        await guardarAparelho({ dono: c.gh.dono, repo: c.gh.repo, token: c.gh.token, dekRaw: c.dekRaw }, pin);
        await kv.del('cache');
      }
      await usar(c);
      const temCache = await lerCache();
      tela('<h2>Sincronizando…</h2><p class="travaSub">Buscando seus dados no GitHub</p><div class="travaErro" role="alert"></div>');
      try { await Promise.race([sincronizar(), espera(temCache ? 4000 : 60000).then(() => { if (!temCache) throw erro('lento', 'O GitHub está demorando para responder.'); })]); }
      catch (e) {
        if (e.code === 'token') { await esquecerAparelho(); aviso = e.msg + ' Crie uma nova chave e entre de novo.'; ap = null; continue; }
        if (!temCache) { aviso = (e.msg || e.message) + (e.code === 'rede' ? ' Sem internet e ainda sem cópia neste aparelho.' : ''); ap = await kv.get('aparelho'); if (ap) { tela(`<h2>Não consegui abrir</h2><p class="travaSub">${escH(aviso)}</p><button class="btn primary" onclick="location.reload()">Tentar de novo</button>`); await new Promise(() => {}); } continue; }
        avisarErro(e);
      }
      fecharTela();
      _aberto = true;
      vigiar();
      return dados();
    }
  }

  // sincroniza de tempos em tempos, ao voltar para o app e ao voltar a internet. Mais de 5 min em segundo plano = pede o PIN.
  let _ocultoEm = 0;
  function vigiar() {
    const d = raiz.document;
    d.addEventListener('visibilitychange', () => {
      if (d.visibilityState === 'hidden') { _ocultoEm = Date.now(); salvarCache().catch(() => {}); if (S.timer) sincronizar().catch(() => {}); return; }
      if (_ocultoEm && Date.now() - _ocultoEm > 5 * 60000) { salvarCache().finally(() => raiz.location.reload()); return; }
      sincronizar().catch(avisarErro);
    });
    raiz.addEventListener('online', () => sincronizar().catch(avisarErro));
    raiz.addEventListener('pagehide', () => { salvarCache().catch(() => {}); });
    setInterval(() => { if (d.visibilityState === 'visible') sincronizar().catch(avisarErro); }, 60000);
  }

  function registrarSW() {
    try {
      if (raiz.navigator && raiz.navigator.serviceWorker && raiz.location.protocol === 'https:')
        raiz.navigator.serviceWorker.register('sw.js').catch(e => console.error('sw', e));
    } catch (_) {}
  }

  /* ------------------------------------------------------------------ extras usados pelo app */
  async function cdi(ini) {
    const [a, m, d] = ini.split('-'), h = new Date();
    const url = `https://api.bcb.gov.br/dados/serie/bcdata.sgs.12/dados?formato=json&dataInicial=${d}/${m}/${a}&dataFinal=${String(h.getDate()).padStart(2, '0')}/${String(h.getMonth() + 1).padStart(2, '0')}/${h.getFullYear()}`;
    const r = await raiz.fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) throw erro('cdi', 'Banco Central respondeu ' + r.status);
    const taxas = {};
    for (const it of await r.json()) { const [dd, mm, aa] = it.data.split('/'); taxas[`${aa}-${mm}-${dd}`] = parseFloat(it.valor); }
    return { taxas };
  }
  async function galeria() {
    if (S.galeria) return S.galeria;
    const txt = await S.gh.ler('galeria.enc');
    if (!txt) return (S.galeria = []);
    const g = await abrirSelado(S.dek, txt);
    S.galeria = (g.itens || []).map(x => {
      let url = '';
      try { const m = /^data:([^;]+);base64,(.*)$/.exec(x.img); url = URL.createObjectURL(new Blob([unb64(m[2])], { type: m[1] })); } catch (_) {}
      return { id: x.id, emissor: x.emissor || '', variante: x.variante || '', tipo: x.tipo || '', banco: x.banco || '', url };
    }).filter(x => x.url);
    return S.galeria;
  }

  /* ------------------------------------------------------------------ no computador (servidor): enviar / trazer */
  // envia os dados do computador para a nuvem. o: {config, tx, galeria: async () => [{id, emissor, variante, tipo, banco, img}]}
  async function enviar(o) {
    const c = await telaSenha({ titulo: 'Enviar para a nuvem', botao: 'Enviar', cancelar: true });
    if (!c) return null;
    tela('<h2>Enviando…</h2><p class="travaSub" id="nvProg">Preparando</p>');
    const prog = t => { const e = raiz.document.getElementById('nvProg'); if (e) e.textContent = t; };
    try {
      await usar(c); S.semCache = true;
      prog('Lendo o que já existe na nuvem');
      await sincronizar();   // junta com o que já estiver lá (se houver)
      const agora = Date.now();
      S.cfg = { mod: Math.max(agora, S.cfg.mod + 1), config: clone(o.config) };
      const ids = new Set(o.tx.map(t => String(t.id)));
      for (const t of o.tx) S.recs[String(t.id)] = [agora, clone(t)];
      for (const id of Object.keys(S.recs)) if (!ids.has(id)) { S.del[id] = agora; delete S.recs[id]; }   // a nuvem fica igual ao computador
      prog(`Enviando ${o.tx.length} lançamentos e a configuração`);
      await sincronizar();
      if (o.galeria) {
        prog('Enviando a galeria de cartões');
        try {
          const itens = await o.galeria(prog);
          if (itens && itens.length) {
            const l = await S.gh.listar(), g = l.find(x => x.nome === 'galeria.enc');
            await S.gh.gravar('galeria.enc', await selar(S.dek, { itens }), g && g.sha);
          }
        } catch (e) { console.error('galeria', e); }
      }
      fecharTela();
      return { lancamentos: o.tx.length, dono: S.dono, repo: S.repo };
    } catch (e) { fecharTela(); throw e; }
    finally { S.gh = null; S.dek = null; S.semCache = false; }
  }
  // baixa tudo da nuvem (para o computador guardar uma cópia). Devolve {config, tx} ou null (cancelado).
  async function trazer() {
    const c = await telaSenha({ titulo: 'Trazer da nuvem', botao: 'Baixar', cancelar: true });
    if (!c) return null;
    tela('<h2>Baixando…</h2><p class="travaSub">Lendo os dados no GitHub</p>');
    try { await usar(c); S.semCache = true; await sincronizar(); return dados(); }
    finally { fecharTela(); S.gh = null; S.dek = null; S.semCache = false; }
  }

  /* ------------------------------------------------------------------ Ajustes › Nuvem */
  function quando(ms) { if (!ms) return 'ainda não'; const d = new Date(ms); return d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }); }
  function renderAjustes(el, modo) {
    if (!el) return;
    if (modo !== 'nuvem') {
      el.innerHTML = `<p class="small">Leve seus dados para um repositório <b>privado</b> do GitHub e use o app por um link (GitHub Pages), com este computador desligado. Tudo vai <b>criptografado</b> com a senha do cofre. O passo a passo está no arquivo <b>PUBLICAR_NO_GITHUB.md</b>, na pasta do app.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" data-nv="enviar">Enviar dados deste computador</button><button class="btn" data-nv="trazer">Trazer da nuvem para este computador</button></div>`;
      el.querySelector('[data-nv="enviar"]').onclick = () => raiz.nuvemEnviar && raiz.nuvemEnviar();
      el.querySelector('[data-nv="trazer"]').onclick = () => raiz.nuvemTrazer && raiz.nuvemTrazer();
      return;
    }
    const e = estado();
    const st = e.erro ? `<span style="color:var(--bad)">● ${escH(e.erro)}</span>` : e.sincronizando ? '● Sincronizando…' : e.pendente ? '● Alterações aguardando envio' : `<span style="color:var(--good)">●</span> Sincronizado ${escH(quando(e.ultimo))}`;
    el.innerHTML = `<p class="small" id="nvStatus">${st}<br>Cofre: <b>${escH(e.dono)}/${escH(e.repo)}</b> · dados criptografados · cada alteração vira uma versão no histórico do repositório (backup).</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
        <button class="btn primary" data-nv="sync">Sincronizar agora</button>
        <button class="btn" data-nv="qr">Conectar outro aparelho</button>
        <button class="btn" data-nv="pin">Trocar PIN deste aparelho</button>
      </div>
      <div id="nvQr"></div>
      <details class="nvAjuda"><summary>Entrar em aparelho novo só com a senha (arquivo de acesso)</summary>
        Gera o <b>acesso.json</b>: a chave do GitHub trancada pela senha do cofre, publicada junto com o app. Com ele, um aparelho novo pede só a senha do cofre (depois, só o PIN). Gere de novo se trocar a senha ou a chave.
        <form class="frow" style="align-items:flex-end" id="nvAcForm"><div class="f"><label>Senha do cofre<input type="password" id="nvAcS" autocomplete="current-password"></label></div><button class="btn" type="submit">Gerar acesso.json</button></form></details>
      <details class="nvAjuda"><summary>Trocar a senha do cofre</summary>
        <div class="frow"><div class="f"><label>Senha atual<input type="password" id="nvSa" autocomplete="current-password"></label></div>
        <div class="f"><label>Nova senha (mín. ${MIN_SENHA})<input type="password" id="nvSn" autocomplete="new-password"></label></div>
        <div class="f"><label>Repita a nova<input type="password" id="nvSn2" autocomplete="new-password"></label></div></div>
        <button class="btn" data-nv="senha">Trocar senha</button> <span class="small">Os outros aparelhos continuam funcionando (eles usam o PIN deles).</span></details>
      <details class="nvAjuda"><summary>Trocar a chave de acesso do GitHub</summary>
        <div class="f"><label>Nova chave (token)<input type="password" id="nvTk" autocomplete="off"></label></div>
        <button class="btn" data-nv="token">Salvar nova chave</button></details>
      <div class="mt"><button class="btn danger" data-nv="sair">Desconectar este aparelho</button></div>`;
    const on = (k, f) => { const b = el.querySelector(`[data-nv="${k}"]`); if (b) b.onclick = () => f().catch(err => toastE(err)); };
    on('sync', async () => { await sincronizar(); renderAjustes(el, modo); toastM('Sincronizado ✔'); });
    on('qr', async () => {
      const box = el.querySelector('#nvQr');
      box.innerHTML = `<form class="frow" style="align-items:flex-end"><div class="f"><label>Senha do cofre (para gerar o QR code)<input type="password" id="nvQs" autocomplete="current-password"></label></div><button class="btn primary" type="submit">Gerar QR code</button></form>`;
      const fq = box.querySelector('form'); setTimeout(() => box.querySelector('#nvQs').focus(), 50);
      fq.onsubmit = ev => { ev.preventDefault(); gerarQr(box, box.querySelector('#nvQs').value).catch(err => toastE(err)); };
    });
    const fa = el.querySelector('#nvAcForm');
    if (fa) fa.onsubmit = ev => {
      ev.preventDefault();
      (async () => {
        const s = el.querySelector('#nvAcS').value; if (!s) return;
        const c = await convite(s);
        const a = raiz.document.createElement('a');
        a.href = URL.createObjectURL(new Blob([JSON.stringify(c)], { type: 'application/json' }));
        a.download = 'acesso.json'; raiz.document.body.appendChild(a); a.click(); a.remove();
        el.querySelector('#nvAcS').value = '';
        toastM('acesso.json gerado: coloque-o na pasta do app e publique junto com o código');
      })().catch(err => toastE(err));
    };
    async function gerarQr(box, senha) {
      if (!senha) return;
      const link = await criarConvite(senha);
      box.innerHTML = `<div class="lanItem">${typeof raiz.qrSvg === 'function' ? `<div class="qrBox">${raiz.qrSvg(link)}</div>` : ''}<div class="small">Aponte a câmera do outro aparelho para o QR code (ou abra este link nele). Lá, digite a senha do cofre e crie um PIN. <button class="linkish" data-nv="copiar">Copiar link</button></div></div>`;
      box.querySelector('[data-nv="copiar"]').onclick = () => { try { raiz.navigator.clipboard.writeText(link); toastM('Link copiado'); } catch (_) {} };
    }
    on('pin', async () => {
      const pin = await telaCriarPin('Novo PIN para este aparelho');
      await guardarAparelho({ dono: S.dono, repo: S.repo, token: S.gh.token, dekRaw: S.dekRaw }, pin); fecharTela(); toastM('PIN trocado ✔');
    });
    on('senha', async () => {
      const a = el.querySelector('#nvSa').value, n = el.querySelector('#nvSn').value, n2 = el.querySelector('#nvSn2').value;
      if (n.length < MIN_SENHA) throw erro('x', `A nova senha precisa ter pelo menos ${MIN_SENHA} caracteres.`);
      if (n !== n2) throw erro('x', 'As duas senhas novas não são iguais.');
      await trocarSenha(a, n); el.querySelector('#nvSa').value = el.querySelector('#nvSn').value = el.querySelector('#nvSn2').value = '';
      toastM('Senha do cofre trocada ✔');
    });
    on('token', async () => {
      const tk = el.querySelector('#nvTk').value.trim(); if (!tk) throw erro('x', 'Cole a nova chave.');
      const gh = GH({ dono: S.dono, repo: S.repo, token: tk }); await conferirRepo(gh);
      const pin = await telaCriarPin('Confirme criando o PIN deste aparelho (pode ser o mesmo)');
      fecharTela(); S.gh = gh;
      await guardarAparelho({ dono: S.dono, repo: S.repo, token: tk, dekRaw: S.dekRaw }, pin); el.querySelector('#nvTk').value = ''; toastM('Chave salva ✔');
    });
    on('sair', async () => {
      const ok = raiz.confirmBox ? await raiz.confirmBox('Desconectar este aparelho', 'Apaga deste aparelho a chave de acesso e a cópia local dos dados. Nada é apagado no GitHub. Para usar de novo, entre com a senha do cofre.', 'Desconectar') : true;
      if (!ok) return;
      if (S.ocupado || S.timer) { try { await sincronizar(); } catch (_) {} }
      await esquecerAparelho(); raiz.location.reload();
    });
  }
  async function trocarSenha(atual, nova) {
    const l = await S.gh.listar(), f = l.find(x => x.nome === 'cofre.json');
    const cofre = JSON.parse(await S.gh.ler('cofre.json'));
    const dekRaw = await abrirCofre(cofre, await kekDoCofre(cofre, atual));
    const salt = rand(16), kek = await pbkdf2(nova, salt, ITER_SENHA);
    const novo = { ...cofre, kdf: { nome: 'PBKDF2-SHA256', iter: ITER_SENHA, salt: b64(salt) }, chave: await cifrar(kek, dekRaw), trocada: new Date().toISOString() };
    await S.gh.gravar('cofre.json', JSON.stringify(novo, null, 1), f && f.sha);
  }
  const toastM = m => { if (typeof raiz.toast === 'function') raiz.toast(m); };
  const toastE = e => { console.error(e); toastM(e.msg || e.message || 'Não deu certo'); };

  /* ------------------------------------------------------------------ interface pública */
  function ativo() {
    try {
      const qs = raiz.location.search || '';
      if (/[?&]nuvem=1\b/.test(qs)) raiz.localStorage.setItem('cg_nuvem', '1');
      if (/[?&]nuvem=0\b/.test(qs)) raiz.localStorage.removeItem('cg_nuvem');
      return /\.github\.io$/i.test(raiz.location.hostname || '') || raiz.localStorage.getItem('cg_nuvem') === '1';
    } catch (_) { return false; }
  }
  const Nuvem = {
    ativo, abrir, dados, putTx, delTx, salvarConfig, sincronizar, estado, cdi, galeria, enviar, trazer, renderAjustes,
    aoMudar(fn) { S.aoMudar = fn; }, aoStatus(fn) { S.aoStatus = fn; },
    rotulo: () => S.dono ? `${S.dono}/${S.repo}` : 'Nuvem',
    sair: async () => { await esquecerAparelho(); raiz.location.reload(); },
    get aberto() { return _aberto; },
    _fetch: null,
    // só para os testes automáticos
    _t: { S, kv, selar, abrirSelado, mesclar, conteudoLocal, resolver, criarCofre, abrirCofre, kekDoCofre, conectar, usar, guardarAparelho, abrirAparelho, GH, b64url, unb64url, trocarSenha, criarConvite, convite, lerAcessoPublico, lerUltimo },
  };
  raiz.Nuvem = Nuvem;
  if (typeof module !== 'undefined' && module.exports) module.exports = Nuvem;
})(typeof window !== 'undefined' ? window : globalThis);
