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
  const ITER_SENHA = 600000, MIN_SENHA = 8;
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
    const P = o.pasta || PASTA;   // pasta dos dados: 'dados' (dono) ou 'usuarios/<id>' (outras contas)
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
      dono: o.dono, repo: o.repo, token: o.token, pasta: P,
      async info() {
        const r = await req('');
        if (r.status === 404) throw erro('repo', 'Repositório não encontrado (confira o nome, ou a chave não tem acesso a ele).');
        if (!r.ok) throw await falha(r);
        return r.json();
      },
      async listar() {
        const r = await req('/contents/' + P);
        if (r.status === 404) return [];
        if (!r.ok) throw await falha(r);
        const l = await r.json();
        return Array.isArray(l) ? l.filter(x => x.type === 'file').map(x => ({ nome: x.name, sha: x.sha })) : [];
      },
      async ler(nome) {
        const r = await req(`/contents/${P}/${nome}`, { raw: true });
        if (r.status === 404) return null;
        if (!r.ok) throw await falha(r);
        return r.text();
      },
      async gravar(nome, texto, sha) {
        const r = await req(`/contents/${P}/${nome}`, { method: 'PUT', body: { message: `app: ${nome}`, content: b64(enc.encode(texto)), ...(sha ? { sha } : {}) } });
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

  // cópia local (criptografada com a chave da conta), uma por conta: várias pessoas podem usar o mesmo aparelho
  const chaveCache = () => `cache:${S.dono}/${S.repo}/${S.pasta}`;
  async function salvarCache() {
    if (!S.dek || S.semCache) return;
    const txt = await selar(S.dek, { dono: S.dono, repo: S.repo, pasta: S.pasta, cfg: S.cfg, recs: S.recs, del: S.del, shas: S.shas, up: S.up });
    await kv.set(chaveCache(), txt);
  }
  function agendarCache() { clearTimeout(S.cacheTimer); S.cacheTimer = setTimeout(() => salvarCache().catch(e => console.error('nuvem: cache', e)), 150); }
  async function lerCache() {
    const txt = await kv.get(chaveCache()); if (!txt) return false;
    try {
      const c = await abrirSelado(S.dek, txt);
      if (c.dono !== S.dono || c.repo !== S.repo || c.pasta !== S.pasta) return false;
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
    Object.assign(S, { gh: c.gh, dono: c.gh.dono, repo: c.gh.repo, pasta: c.gh.pasta, dekRaw: c.dekRaw, dek: await importarDek(c.dekRaw),
      cfg: { mod: 0, config: null }, recs: {}, del: {}, shas: {}, up: {}, galeria: null });
  }

  /* ------------------------------------------------------------------ telas (login; enviar/trazer no computador) */
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

  /* ------------------------------------------------------------------ contas (usuário + senha) */
  // Cada conta é um arquivo publicado com o app: contas/<id>.json, id = sha256("cg-conta:" + usuário) (não revela o nome).
  // Dentro, trancado pela senha da conta (PBKDF2 600 mil + AES-GCM): {nome, dono, repo, pasta, token, dek}.
  // Entrar = baixar o arquivo da conta, destrancar com a senha e abrir os dados da pasta dela. Nada de GitHub na tela.
  // Contas são criadas no computador (ferramentas/conta_nuvem.js) e publicadas junto com o código.
  const ITER_CONTA = 600000;
  const idConta = async usuario => (await hashTexto('cg-conta:' + String(usuario).trim().toLowerCase())).slice(0, 32);
  async function criarConta(dados, senha) {
    const salt = rand(16), k = await pbkdf2(senha, salt, ITER_CONTA);
    return { v: 1, salt: b64(salt), iter: ITER_CONTA, caixa: await cifrar(k, enc.encode(JSON.stringify(dados))) };
  }
  async function abrirConta(conta, senha) {
    const k = await pbkdf2(senha, unb64(conta.salt), conta.iter || ITER_CONTA);
    try { return JSON.parse(dec.decode(await decifrar(k, conta.caixa))); }
    catch (_) { throw erro('login', 'Usuário ou senha incorretos.'); }
  }
  async function lerConta(usuario) {
    try {
      const r = await raiz.fetch(`contas/${await idConta(usuario)}.json`, { cache: 'no-store' });
      if (!r.ok) return null;
      const c = await r.json();
      return c && c.salt && c.caixa ? c : null;
    } catch (_) { return null; }
  }
  // usuário + senha -> acesso aos dados da conta. Usuário que não existe demora o mesmo e dá a mesma mensagem.
  async function entrar(usuario, senha) {
    const conta = await lerConta(usuario);
    if (!conta) { await pbkdf2(senha, rand(16), ITER_CONTA); throw erro('login', 'Usuário ou senha incorretos.'); }
    const p = await abrirConta(conta, senha);
    return { gh: GH({ dono: p.dono, repo: p.repo, token: p.token, pasta: p.pasta }), dekRaw: unb64(p.dek), nome: p.nome || usuario };
  }

  function telaLogin(aviso) {
    return new Promise(res => {
      let ultimo = ''; try { ultimo = raiz.localStorage.getItem('cg_nv_usuario') || ''; } catch (_) {}
      tela(`<h2>Controle de Gastos</h2><p class="travaSub">Entre com seu usuário e senha</p>
        <form class="travaRec nvForm" autocomplete="on">
          <label>Usuário<input name="usuario" autocomplete="username" autocapitalize="off" spellcheck="false" value="${escH(ultimo)}"></label>
          <label>Senha<input name="senha" type="password" autocomplete="current-password" maxlength="200"></label>
          <div class="travaErro" role="alert">${escH(aviso || '')}</div>
          <button type="submit" class="btn primary">Entrar</button>
        </form>`);
      const f = q('form');
      setTimeout(() => { try { (ultimo ? f.senha : f.usuario).focus(); } catch (_) {} }, 60);
      f.onsubmit = async e => {
        e.preventDefault();
        const u = f.usuario.value.trim(), s = f.senha.value;
        if (!u || !s) return msgErro('Digite o usuário e a senha.');
        const bt = f.querySelector('button[type=submit]'); bt.disabled = true; bt.textContent = 'Entrando…';
        try {
          const c = await entrar(u, s);
          try { raiz.localStorage.setItem('cg_nv_usuario', u); } catch (_) {}
          res(c);
        } catch (err) {
          bt.disabled = false; bt.textContent = 'Entrar';
          f.senha.value = ''; f.senha.focus();
          msgErro(err.msg || err.message || 'Não consegui entrar.', true);
          await espera(600);
        }
      };
    });
  }

  /* ------------------------------------------------------------------ abrir o app */
  let _aberto = false;
  async function abrir() {
    registrarSW();
    let aviso = '';
    for (;;) {
      const c = await telaLogin(aviso);
      aviso = '';
      await usar(c); S.nome = c.nome;
      const temCache = await lerCache();
      tela('<h2>Abrindo…</h2><p class="travaSub">Buscando seus dados</p><div class="travaErro" role="alert"></div>');
      try { await Promise.race([sincronizar(), espera(temCache ? 4000 : 60000).then(() => { if (!temCache) throw erro('lento', 'O GitHub está demorando para responder.'); })]); }
      catch (e) {
        if (e.code === 'token') { aviso = 'O acesso desta conta venceu. Avise quem administra o app.'; continue; }
        if (!temCache) { aviso = (e.msg || e.message) + (e.code === 'rede' ? ' Sem internet.' : ''); continue; }
        avisarErro(e);
      }
      fecharTela();
      _aberto = true;
      vigiar();
      return dados();
    }
  }

  // sincroniza de tempos em tempos, ao voltar para o app e ao voltar a internet. Mais de 5 min em segundo plano = pede o login de novo.
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
      const sw = raiz.navigator && raiz.navigator.serviceWorker;
      if (sw && raiz.location.protocol === 'https:') {
        // versão nova publicada: o service worker novo assume e a página recarrega uma vez (se nenhuma janela estiver aberta)
        const tinha = !!sw.controller;
        sw.addEventListener('controllerchange', () => {
          if (!tinha || raiz.__cgRecarregou) return;
          if (raiz.document.querySelector('.ov.show')) return;
          raiz.__cgRecarregou = true; raiz.location.reload();
        });
        sw.register('sw.js').then(reg => reg.update()).catch(e => console.error('sw', e));
      }
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
    const st = e.erro ? `<span style="color:var(--bad)">● ${escH(e.erro)}</span>` : e.sincronizando ? '● Sincronizando…' : e.pendente ? '● Alterações aguardando envio' : `<span style="color:var(--good)">●</span> Tudo salvo ${escH(quando(e.ultimo))}`;
    el.innerHTML = `<p class="small" id="nvStatus">${st}<br>Conta: <b>${escH(S.nome || '')}</b> · seus dados ficam criptografados num repositório privado; cada alteração vira uma versão no histórico (backup).</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn primary" data-nv="sync">Sincronizar agora</button>
        <button class="btn" data-nv="sair">Sair</button>
      </div>
      <p class="small mt">Contas novas e troca de senha são feitas no computador (ferramentas/conta_nuvem.js).</p>`;
    const on = (k, f) => { const b = el.querySelector(`[data-nv="${k}"]`); if (b) b.onclick = () => f().catch(err => toastE(err)); };
    on('sync', async () => { await sincronizar(); renderAjustes(el, modo); toastM('Sincronizado ✔'); });
    on('sair', async () => { if (S.ocupado || S.timer) { try { await sincronizar(); } catch (_) {} } raiz.location.reload(); });
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
    rotulo: () => S.nome || 'Minha conta',
    sair: () => raiz.location.reload(),
    get aberto() { return _aberto; },
    _fetch: null,
    // só para os testes automáticos
    _t: { S, kv, selar, abrirSelado, mesclar, conteudoLocal, resolver, criarCofre, abrirCofre, kekDoCofre, conectar, usar, GH, b64url, unb64url, lerUltimo, idConta, criarConta, abrirConta, lerConta, entrar },
  };
  raiz.Nuvem = Nuvem;
  if (typeof module !== 'undefined' && module.exports) module.exports = Nuvem;
})(typeof window !== 'undefined' ? window : globalThis);
