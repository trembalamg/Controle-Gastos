/* Relatório financeiro em PDF, gerado no próprio aparelho: sem servidor, sem internet e sem biblioteca externa.
 *
 *   const bytes = Relatorio.pdf(dados);   // Uint8Array com um PDF (A4)
 *
 * "dados" é montado pelo index.html (dadosRelatorio): números já calculados, textos prontos.
 * Este arquivo só desenha: capa com o resumo, gráficos de barras, tabelas que continuam na página seguinte,
 * dicas e o extrato. Usa as fontes padrão do PDF (Helvetica), com acentos do português (codificação WinAnsi). */
(function (raiz) {
  'use strict';

  // larguras das letras (1/1000 do tamanho da fonte), códigos 32 a 126: Helvetica e Helvetica-Bold
  const LR = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,
    1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,
    333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584];
  const LB = [278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,
    975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,
    333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584];
  // caracteres fora do Latin-1 que existem na fonte (WinAnsi 128-159) e trocas para os que não existem
  const WIN = { '€': [0x80, 556], '…': [0x85, 1000], '‰': [0x89, 1000], '‘': [0x91, 222], '’': [0x92, 222], '“': [0x93, 333], '”': [0x94, 333],
    '•': [0x95, 350], '–': [0x96, 556], '—': [0x97, 1000], '™': [0x99, 1000] };
  const TROCA = { '−': '-', '≈': '~', '→': '>', '←': '<', '▲': '+', '▼': '-', '✔': '', '✓': '', ' ': ' ', ' ': ' ' };

  // texto -> lista de [código, largura]; o que não existe na fonte (emoji etc.) é descartado
  function glifos(s, negrito) {
    const out = [], T = negrito ? LB : LR;
    for (let c of String(s == null ? '' : s)) {
      if (c in TROCA) { if (!TROCA[c]) continue; c = TROCA[c]; }
      const n = c.codePointAt(0);
      if (n === 9 || n === 10 || n === 13) { out.push([32, 278]); continue; }
      if (n >= 32 && n <= 126) { out.push([n, T[n - 32]]); continue; }
      if (WIN[c]) { out.push(WIN[c]); continue; }
      if (n >= 160 && n <= 255) {
        const base = c.normalize('NFD')[0].codePointAt(0);   // á -> a: a letra acentuada tem a largura da letra
        let w = base >= 32 && base <= 126 ? T[base - 32] : 556;
        if (n === 0xA0 || n === 0xB7) w = 278; else if (n === 0xAA || n === 0xBA) w = 365; else if (n === 0xB0) w = 400;
        out.push([n, w]); continue;
      }
    }
    return out;
  }
  const largura = (s, tam, negrito) => glifos(s, negrito).reduce((a, g) => a + g[1], 0) * tam / 1000;
  function cabe(s, w, tam, negrito) {   // corta com "…" o que não cabe em w
    s = String(s == null ? '' : s);
    if (largura(s, tam, negrito) <= w) return s;
    const gl = [...s]; let lo = 0, hi = gl.length;
    while (lo < hi) { const m = (lo + hi + 1) >> 1; if (largura(gl.slice(0, m).join('') + '…', tam, negrito) <= w) lo = m; else hi = m - 1; }
    return gl.slice(0, lo).join('').trimEnd() + '…';
  }
  function quebrar(s, w, tam, negrito) {  // quebra em linhas que cabem em w (respeita \n)
    const linhas = [];
    for (const par of String(s == null ? '' : s).split('\n')) {
      let cur = '';
      for (const p of par.split(/ +/)) {
        const t = cur ? cur + ' ' + p : p;
        if (!cur || largura(t, tam, negrito) <= w) { cur = t; continue; }
        linhas.push(cur); cur = p;
      }
      while (largura(cur, tam, negrito) > w && cur.length > 1) { const c = cabe(cur, w, tam, negrito).replace(/…$/, ''); linhas.push(c); cur = cur.slice(c.length).trimStart(); }
      linhas.push(cur);
    }
    return linhas;
  }
  const strPdf = (s, negrito) => '(' + glifos(s, negrito).map(([n]) =>
    n === 40 || n === 41 || n === 92 ? '\\' + String.fromCharCode(n) : n > 126 ? '\\' + n.toString(8).padStart(3, '0') : String.fromCharCode(n)).join('') + ')';
  const num = v => (Math.round(v * 100) / 100).toString();
  function rgb(h) { h = String(h || '#000').replace('#', ''); if (h.length === 3) h = [...h].map(c => c + c).join('');
    return [0, 2, 4].map(i => num(parseInt(h.slice(i, i + 2), 16) / 255)).join(' '); }

  /* ---------- documento: páginas A4, coordenadas a partir do canto de cima (y cresce para baixo) ---------- */
  const PW = 595.28, PH = 841.89;
  function Doc() { this.pags = []; this.p = null; }
  Doc.prototype.nova = function () { this.p = []; this.pags.push(this.p); };
  Doc.prototype.op = function (s) { this.p.push(s); };
  Doc.prototype.texto = function (x, y, s, o = {}) {
    const tam = o.tam || 10, b = !!o.b; let t = s;
    if (o.max) t = cabe(t, o.max, tam, b);
    const w = largura(t, tam, b), xx = o.al === 'd' ? x - w : o.al === 'c' ? x - w / 2 : x;
    this.op(`BT /${b ? 'F2' : 'F1'} ${num(tam)} Tf ${rgb(o.cor || '#0a1f44')} rg ${num(xx)} ${num(PH - y)} Td ${strPdf(t, b)} Tj ET`);
    return w;
  };
  Doc.prototype.ret = function (x, y, w, h, cor, r) {
    if (w <= 0 || h <= 0) return;
    const Y = PH - y - h; r = Math.min(r || 0, w / 2, h / 2);
    if (!r) { this.op(`${rgb(cor)} rg ${num(x)} ${num(Y)} ${num(w)} ${num(h)} re f`); return; }
    const k = r * 0.5523, x2 = x + w, y2 = Y + h;
    this.op(`${rgb(cor)} rg ${num(x + r)} ${num(Y)} m ${num(x2 - r)} ${num(Y)} l ${num(x2 - r + k)} ${num(Y)} ${num(x2)} ${num(Y + r - k)} ${num(x2)} ${num(Y + r)} c `
      + `${num(x2)} ${num(y2 - r)} l ${num(x2)} ${num(y2 - r + k)} ${num(x2 - r + k)} ${num(y2)} ${num(x2 - r)} ${num(y2)} c `
      + `${num(x + r)} ${num(y2)} l ${num(x + r - k)} ${num(y2)} ${num(x)} ${num(y2 - r + k)} ${num(x)} ${num(y2 - r)} c `
      + `${num(x)} ${num(Y + r)} l ${num(x)} ${num(Y + r - k)} ${num(x + r - k)} ${num(Y)} ${num(x + r)} ${num(Y)} c f`);
  };
  Doc.prototype.linha = function (x1, y1, x2, y2, cor, lw) {
    this.op(`${rgb(cor)} RG ${num(lw || 0.6)} w ${num(x1)} ${num(PH - y1)} m ${num(x2)} ${num(PH - y2)} l S`);
  };
  Doc.prototype.bytes = function (titulo) {
    const objs = [];   // índice 0 = objeto 1
    const add = s => { objs.push(s); return objs.length; };
    add('<< /Type /Catalog /Pages 2 0 R >>');
    add('');   // Pages (preenchido depois)
    add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
    add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
    const kids = [];
    for (const p of this.pags) {
      const conteudo = p.join('\n');
      const c = add(`<< /Length ${conteudo.length} >>\nstream\n${conteudo}\nendstream`);
      kids.push(add(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PW} ${PH}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${c} 0 R >>`));
    }
    objs[1] = `<< /Type /Pages /Kids [${kids.map(k => k + ' 0 R').join(' ')}] /Count ${kids.length} >>`;
    const d = new Date(), p2 = n => String(n).padStart(2, '0');
    const info = add(`<< /Title ${strPdf(titulo || 'Relatório')} /Producer (Controle de Gastos) /CreationDate (D:${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}${p2(d.getHours())}${p2(d.getMinutes())}${p2(d.getSeconds())}) >>`);
    let s = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'; const pos = [];
    objs.forEach((o, i) => { pos.push(s.length); s += `${i + 1} 0 obj\n${o}\nendobj\n`; });
    const xref = s.length;
    s += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + pos.map(n => String(n).padStart(10, '0') + ' 00000 n \n').join('');
    s += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R /Info ${info} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 255;
    return b;
  };

  /* ---------- relatório ---------- */
  const C = { azul: '#0033a0', azul2: '#0a4fd1', claro: '#eef3fb', claro2: '#f6f8fc', txt: '#0a1f44', txt2: '#3d5277', mudo: '#7d8fae',
    bom: '#12873a', ruim: '#d32f2f', grade: '#dfe6f2', gas: '#8fa6cf', branco: '#ffffff' };
  const M = 40, CW = PW - 2 * M, BASE = PH - 46;
  const brl = v => (v < -0.004 ? '-' : '') + 'R$ ' + Math.abs(+v || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const brlS = v => (v > 0.004 ? '+' : '') + brl(v);
  const pct = v => (v == null || !isFinite(v)) ? '—' : (Math.round(v * 10) / 10).toLocaleString('pt-BR') + '%';

  function pdf(d) {
    const doc = new Doc(); let y = 0;
    const rodapeTxt = `${d.titulo} · ${d.periodo.rotulo}`;
    function pagina(primeira) {
      doc.nova();
      if (primeira) return;
      doc.texto(M, 30, rodapeTxt, { tam: 8, cor: C.mudo, max: CW });
      doc.linha(M, 37, PW - M, 37, C.grade);
      y = 56;
    }
    const precisa = h => { if (y + h > BASE) pagina(false); };
    function secao(titulo, sub) {
      precisa(sub ? 70 : 56); y += 14;
      doc.ret(M, y - 1, 4, 16, C.azul2, 2);
      doc.texto(M + 12, y + 12, titulo, { tam: 14, b: true, cor: C.azul });
      y += 22;
      if (sub) { for (const l of quebrar(sub, CW, 8.5)) { doc.texto(M, y + 8, l, { tam: 8.5, cor: C.mudo }); y += 12; } }
      y += 6;
    }
    function paragrafo(s, o = {}) {
      const tam = o.tam || 9.5, lh = tam * 1.45, x = M + (o.rec || 0), w = CW - (o.rec || 0);
      for (const l of quebrar(s, w, tam, o.b)) { precisa(lh); doc.texto(x, y + tam, l, { tam, b: o.b, cor: o.cor || C.txt2 }); y += lh; }
      y += o.depois ?? 4;
    }
    // tabela com cabeçalho repetido a cada página. col: {t, w, al:'d'|'c'}; linha: [células] ou {cels, b, fundo}
    function tabela(cols, linhas, o = {}) {
      const tam = o.tam || 8.5, lh = o.lh || 15;
      const cab = () => {
        doc.ret(M, y, CW, lh + 1, C.claro, 3); let x = M + 6;
        for (const c of cols) { doc.texto(c.al === 'd' ? x + c.w - 12 : x, y + lh - 4.5, c.t, { tam: tam - 0.5, b: true, cor: C.txt2, al: c.al === 'd' ? 'd' : undefined, max: c.w - 8 }); x += c.w; }
        y += lh + 3;
      };
      precisa(lh * 3); cab();
      linhas.forEach((ln, i) => {
        const cels = Array.isArray(ln) ? ln : ln.cels;
        if (y + lh > BASE) { pagina(false); cab(); }
        if (ln.fundo) doc.ret(M, y, CW, lh, ln.fundo, 2); else if (i % 2) doc.ret(M, y, CW, lh, C.claro2);
        let x = M + 6;
        cols.forEach((c, j) => {
          let v = cels[j]; const ob = v && typeof v === 'object' ? v : { v };
          if (ob.v != null && ob.v !== '') doc.texto(c.al === 'd' ? x + c.w - 12 : x, y + lh - 4.5, ob.v, { tam, b: ob.b || ln.b, cor: ob.cor || C.txt, al: c.al === 'd' ? 'd' : undefined, max: c.w - 10 });
          x += c.w;
        });
        y += lh;
      });
      y += 8;
    }
    // barras horizontais: [{nome, v, extra}] (extra = texto à direita do valor)
    function barras(itens, o = {}) {
      const max = Math.max(...itens.map(x => x.v), 0.01), wN = o.wNome || 140, wV = o.wValor || 130, wB = CW - wN - wV - 10, lh = 17;
      for (const it of itens) {
        precisa(lh);
        doc.texto(M, y + 11, it.nome, { tam: 9, cor: C.txt, max: wN - 8 });
        doc.ret(M + wN, y + 3, wB, 9, C.claro, 4.5);
        doc.ret(M + wN, y + 3, Math.max(3, wB * it.v / max), 9, it.cor || C.azul2, 4.5);
        doc.texto(PW - M, y + 11, (it.extra ? it.extra + '   ' : '') + brl(it.v), { tam: 9, b: true, al: 'd', cor: C.txt });
        y += lh;
      }
      y += 6;
    }
    function subtitulo(t) { precisa(80); doc.texto(M, y + 10, t, { tam: 10.5, b: true, cor: C.txt }); y += 18; }
    function caixa(x, w, h, rotulo, valor, rodape, cor) {
      doc.ret(x, y, w, h, C.claro2, 8);
      doc.texto(x + 10, y + 15, rotulo, { tam: 7.5, b: true, cor: C.mudo, max: w - 20 });
      doc.texto(x + 10, y + 33, valor, { tam: 13, b: true, cor: cor || C.txt, max: w - 20 });
      if (rodape) quebrar(rodape, w - 20, 7.5).slice(0, 2).forEach((l, i) => doc.texto(x + 10, y + 46 + i * 9.5, l, { tam: 7.5, cor: C.txt2 }));
    }
    function caixas(lista, h = 64) {
      precisa(h + 10); const n = lista.length, g = 10, w = (CW - g * (n - 1)) / n;
      lista.forEach((c, i) => caixa(M + i * (w + g), w, h, ...c));
      y += h + 10;
    }

    /* capa */
    pagina(true);
    doc.ret(0, 0, PW, 128, C.azul);
    doc.ret(0, 122, PW, 6, C.azul2);
    doc.texto(M, 44, 'CONTROLE DE GASTOS', { tam: 9, b: true, cor: '#b9cdf5' });
    doc.texto(M, 74, d.titulo, { tam: 24, b: true, cor: C.branco });
    doc.texto(M, 96, d.periodo.rotulo, { tam: 12, cor: C.branco, max: CW });
    doc.texto(M, 113, `Gerado em ${d.geradoEm}${d.nome ? ' · ' + d.nome : ''}`, { tam: 8.5, cor: '#b9cdf5', max: CW });
    y = 150;

    const r = d.resumo;
    secao('Resumo do período', r.aviso || null);
    caixas([
      ['RECEITAS', brl(r.rec), r.recAnt != null ? `Período anterior: ${brl(r.recAnt)}` : '', C.bom],
      ['GASTOS', brl(r.gas), r.varGas != null ? `${r.varGas >= 0 ? 'Subiu' : 'Caiu'} ${pct(Math.abs(r.varGas))} vs anterior (${brl(r.gasAnt)})` : '', C.txt],
      ['RESULTADO', brl(r.res), r.res >= 0 ? 'Sobrou dinheiro' : 'Gastou mais do que recebeu', r.res >= 0 ? C.bom : C.ruim],
      ['TAXA DE POUPANÇA', r.rec > 0 ? pct(r.poupanca) : '—', 'Quanto da receita sobrou', r.poupanca >= 0 ? C.azul2 : C.ruim],
    ]);
    caixas([
      ['SALDO EM CONTA', brl(r.saldoFim), `Começou com ${brl(r.saldoIni)}`],
      ['CAIXINHAS', d.caixinhas.length ? brl(r.cxFim) : '—', d.caixinhas.length ? `Começou com ${brl(r.cxIni)}` : 'Nenhuma caixinha'],
      ['RENDIMENTOS', brl(r.rendTotal), `Conta ${brl(r.rendConta)} · caixinhas ${brl(r.rendCx)}`, C.bom],
      ['PATRIMÔNIO', brl(r.patrimonio), `Conta + caixinhas${r.din ? ' + dinheiro' : ''} · ${brlS(r.patrimonioVar)}`],
    ]);
    if (d.destaques && d.destaques.length) for (const t of d.destaques) paragrafo('• ' + t, { tam: 9.5, depois: 1 });
    y += 4;

    /* gráfico: receitas x gastos dos últimos meses */
    if (d.meses && d.meses.some(m => m.rec || m.gas)) {
      secao('Receitas x gastos', 'Últimos meses até o fim do período (pela data em que o dinheiro entra ou sai da conta; cartão = mês do vencimento da fatura).');
      const h = 130; precisa(h + 34);
      const max = Math.max(...d.meses.map(m => Math.max(m.rec, m.gas)), 1), n = d.meses.length, gw = CW / n, bw = Math.min(18, gw / 3.2), top = y, base = y + h;
      for (let i = 0; i <= 4; i++) { const yy = base - h * i / 4; doc.linha(M, yy, PW - M, yy, C.grade, 0.5); if (i) doc.texto(M + 2, yy - 2, brl(max * i / 4).replace(',00', ''), { tam: 6.5, cor: C.mudo }); }
      d.meses.forEach((m, i) => {
        const cx = M + gw * i + gw / 2, hr = h * m.rec / max, hg = h * m.gas / max;
        doc.ret(cx - bw - 1, base - hr, bw, hr, C.azul2, 2); doc.ret(cx + 1, base - hg, bw, hg, C.gas, 2);
        const vazio = !m.rec && !m.gas;
        doc.texto(cx, base + 12, m.rotulo, { tam: 8, b: true, al: 'c', cor: vazio ? C.mudo : (m.rec - m.gas) >= 0 ? C.bom : C.ruim });
        if (!vazio) doc.texto(cx, base + 22, brlS(m.rec - m.gas).replace(',00', ''), { tam: 6.5, al: 'c', cor: C.txt2 });
      });
      y = top + h + 30;
      doc.ret(M, y, 8, 8, C.azul2, 2); doc.texto(M + 12, y + 7.5, 'Receitas', { tam: 8, cor: C.txt2 });
      doc.ret(M + 70, y, 8, 8, C.gas, 2); doc.texto(M + 82, y + 7.5, 'Gastos', { tam: 8, cor: C.txt2 });
      doc.texto(M + 130, y + 7.5, 'Embaixo de cada mês: quanto sobrou (verde) ou faltou (vermelho)', { tam: 8, cor: C.mudo });
      y += 20;
    }

    /* onde mais gastei */
    secao('Onde mais gastei', `Gastos do período por categoria · total ${brl(r.gas)}`);
    if (d.categorias.length) barras(d.categorias.map(c => ({ nome: c.nome, v: c.v, extra: pct(c.pct) + (c.varAnt != null ? ` (${c.varAnt >= 0 ? '+' : '-'}${pct(Math.abs(c.varAnt))})` : '') })));
    else paragrafo('Nenhum gasto no período.');
    if (d.categorias.some(c => c.varAnt != null)) paragrafo('Entre parênteses: quanto a categoria subiu (+) ou caiu (-) em relação ao período anterior.', { tam: 8, cor: C.mudo });
    if (d.formas.length) {
      subtitulo('Como paguei');
      barras(d.formas.map(c => ({ nome: c.nome, v: c.v, extra: pct(c.pct), cor: C.azul })));
    }
    if (d.maiores.length) {
      subtitulo('Maiores compras e contas');
      tabela([{ t: 'Data', w: 52 }, { t: 'Descrição', w: 190 }, { t: 'Categoria', w: 110 }, { t: 'Forma', w: 83 }, { t: 'Valor', w: 80, al: 'd' }],
        d.maiores.map(m => [m.data, m.desc, m.cat, m.forma, { v: brl(m.v), b: true }]));
    }
    if (d.frequentes.length) {
      subtitulo('Onde comprei mais vezes');
      tabela([{ t: 'Descrição', w: 245 }, { t: 'Vezes', w: 60, al: 'd' }, { t: 'Valor médio', w: 100, al: 'd' }, { t: 'Total', w: 110, al: 'd' }],
        d.frequentes.map(f => [f.desc, String(f.n), brl(f.v / f.n), { v: brl(f.v), b: true }]));
    }

    /* economia */
    secao('Onde posso economizar', 'Análise automática do período. Os valores de economia são por mês.');
    if (d.economia.potencial > 0.004) {
      precisa(46); doc.ret(M, y, CW, 38, '#e8f6ec', 8);
      doc.texto(M + 12, y + 16, `Potencial: ${brl(d.economia.potencial)} por mês · ${brl(d.economia.potencial * 12)} por ano`, { tam: 11, b: true, cor: C.bom, max: CW - 24 });
      doc.texto(M + 12, y + 29, 'Cortando 20% nas maiores categorias que dá para ajustar (alimentação, compras, lazer, etc.).', { tam: 8, cor: C.txt2, max: CW - 24 });
      y += 48;
    }
    if (!d.economia.itens.length) paragrafo('Não há gastos suficientes no período para sugerir cortes. Lance as compras do dia a dia (não só as faturas) que as dicas aparecem aqui.');
    for (const e of d.economia.itens) {
      const linhas = quebrar(e.d, CW - (e.eco > 0 ? 130 : 18), 8.5);
      precisa(20 + linhas.length * 11.5);
      doc.ret(M, y + 3, 6, 6, e.cor || C.azul2, 3);
      doc.texto(M + 14, y + 10, e.t, { tam: 10, b: true, cor: C.txt, max: CW - (e.eco > 0 ? 130 : 18) });
      if (e.eco > 0.004) { doc.texto(PW - M, y + 10, brl(e.eco) + '/mês', { tam: 10, b: true, al: 'd', cor: C.bom }); doc.texto(PW - M, y + 21, 'economia', { tam: 7, al: 'd', cor: C.mudo }); }
      y += 15;
      for (const l of linhas) { doc.texto(M + 14, y + 8.5, l, { tam: 8.5, cor: C.txt2 }); y += 11.5; }
      y += 7;
    }

    /* investir */
    const iv = d.investir;
    secao('Como investir o que sobrar', 'Simulações com os seus números e a taxa do CDI que o app já usa. Conteúdo educativo: não é recomendação de investimento.');
    caixas([
      ['SOBRA POR MÊS', brl(iv.sobraMes), iv.sobraMes > 0 ? 'Média do período' : 'Sem sobra no período', iv.sobraMes > 0 ? C.bom : C.ruim],
      ['RESERVA DE EMERGÊNCIA', pct(iv.reservaPct), `${brl(iv.reservaAtual)} de ${brl(iv.reservaMeta)} · ` + (iv.reservaFonte === 'manual' ? 'meta definida por você' : iv.reservaFonte === 'sugerida' ? 'meta sugerida pelo app' : 'estimativa: 6 meses de gastos'), iv.reservaPct >= 100 ? C.bom : C.azul2],
      ['CDI HOJE', pct(iv.cdiAno) + ' a.a.', `${iv.pctCdi}% do CDI ≈ ${pct(iv.taxaLiq)} a.a. líquido de IR`],
    ]);
    if (iv.cenarios.length) {
      subtitulo('Quanto o dinheiro guardado todo mês pode virar');
      tabela([{ t: 'Guardando por mês', w: 160 }, ...iv.prazos.map(p => ({ t: p === 1 ? '1 ano' : p + ' anos', w: (CW - 160) / iv.prazos.length, al: 'd' }))],
        iv.cenarios.map(c => [{ v: `${c.nome}: ${brl(c.aporte)}`, b: true }, ...c.valores.map(v => brl(v))]));
      paragrafo(`Rendendo ${iv.pctCdi}% do CDI (${pct(iv.taxaLiq)} ao ano já sem o IR de 15%), com a taxa de hoje mantida. Nos valores acima, ${brl(iv.cenarios[0].juros5)} em 5 anos são só rendimento no primeiro cenário. Taxas mudam: é uma estimativa.`, { tam: 8, cor: C.mudo });
    }
    subtitulo('Uma ordem que costuma funcionar');
    iv.passos.forEach((p, i) => {
      const linhas = quebrar(p.d, CW - 26, 8.5); precisa(16 + linhas.length * 11.5);
      doc.ret(M, y, 16, 16, p.feito ? C.bom : C.azul2, 8); doc.texto(M + 8, y + 11.5, p.feito ? 'ok' : String(i + 1), { tam: p.feito ? 7 : 9, b: true, al: 'c', cor: C.branco });
      doc.texto(M + 26, y + 11.5, p.t, { tam: 10, b: true, cor: C.txt, max: CW - 26 }); y += 17;
      for (const l of linhas) { doc.texto(M + 26, y + 8.5, l, { tam: 8.5, cor: C.txt2 }); y += 11.5; }
      y += 6;
    });
    paragrafo('Antes de investir, confira o seu perfil de investidor no banco ou na corretora e prefira instituições cobertas pelo FGC (até R$ 250 mil por CPF e instituição). Em caso de dúvida, procure um profissional certificado.', { tam: 8, cor: C.mudo });

    /* outros dados */
    secao('Outros números do período');
    if (d.outros.length) {
      const linhas = []; for (let i = 0; i < d.outros.length; i += 2) linhas.push(d.outros.slice(i, i + 2));
      for (const par of linhas) caixas(par.map(o => [o.t.toUpperCase(), o.v, o.d]), 58);
    }
    if (d.faturas.length) {
      subtitulo('Faturas de cartão com vencimento no período');
      tabela([{ t: 'Cartão', w: 190 }, { t: 'Vencimento', w: 90 }, { t: 'Situação', w: 140 }, { t: 'Valor', w: 95, al: 'd' }],
        d.faturas.map(f => [f.cartao, f.venc, { v: f.status, cor: /Vencida/.test(f.status) ? C.ruim : C.txt2 }, { v: brl(f.v), b: true }]));
    }
    if (d.futuro.some(f => f.v > 0.004)) {
      subtitulo('Compromissos já lançados para os próximos meses');
      tabela([{ t: 'Mês', w: 150 }, { t: 'Parcelas de cartão', w: 130, al: 'd' }, { t: 'Demais contas e faturas', w: 130, al: 'd' }, { t: 'Total', w: 105, al: 'd' }],
        d.futuro.filter(f => f.v > 0.004).map(f => [f.rotulo, brl(f.parc), brl(r2(f.v - f.parc)), { v: brl(f.v), b: true }]));
    }
    if (d.pendentes.length) {
      subtitulo('Ainda em aberto');
      tabela([{ t: 'Data', w: 60 }, { t: 'Descrição', w: 235 }, { t: 'Tipo', w: 120 }, { t: 'Valor', w: 100, al: 'd' }],
        d.pendentes.map(p => [p.data, p.desc, { v: p.tipo, cor: p.atrasado ? C.ruim : C.txt2 }, { v: brl(p.v), b: true, cor: p.receita ? C.bom : C.txt }]));
    }
    if (d.caixinhas.length) {
      subtitulo('Caixinhas');
      tabela([{ t: 'Caixinha', w: 155 }, { t: 'Início', w: 90, al: 'd' }, { t: 'Guardei / resgatei', w: 100, al: 'd' }, { t: 'Rendeu', w: 80, al: 'd' }, { t: 'Fim', w: 90, al: 'd' }],
        [...d.caixinhas.map(c => [c.nome, brl(c.ini), brlS(c.mov), { v: brlS(c.rend), cor: C.bom }, { v: brl(c.fim), b: true }]),
          { b: true, fundo: C.claro, cels: ['Total', brl(r.cxIni), brlS(d.caixinhas.reduce((s, c) => s + c.mov, 0)), brlS(r.rendCx), brl(r.cxFim)] }]);
    }

    /* extrato */
    secao('Extrato do período', 'Tudo o que foi lançado no período, pela data da compra ou da conta. Compra parcelada aparece uma vez, pelo total; no cartão, ao lado, a data da fatura em que ela sai da conta.');
    if (!d.extrato.length) paragrafo('Nenhum lançamento no período.');
    else {
      tabela([{ t: 'Data', w: 50 }, { t: 'Descrição', w: 195 }, { t: 'Categoria', w: 100 }, { t: 'Forma', w: 85 }, { t: 'Valor', w: 85, al: 'd' }],
        [...d.extrato.map(t => [t.data, t.desc + (t.obs ? ` (${t.obs})` : ''), t.cat, { v: t.forma, cor: t.previsto ? C.mudo : C.txt2 },
          { v: brlS(t.v) + (t.previsto ? '*' : ''), b: true, cor: t.v >= 0 ? C.bom : C.txt }]),
          { b: true, fundo: C.claro, cels: ['', `Total · ${d.extrato.length} lançamentos`, '', '', { v: brlS(d.extratoTot.ent - d.extratoTot.sai), cor: d.extratoTot.ent >= d.extratoTot.sai ? C.bom : C.ruim }] }],
        { tam: 8, lh: 14 });
      paragrafo(`Entradas: ${brl(d.extratoTot.ent)} · saídas: ${brl(d.extratoTot.sai)}. Este total pode diferir do resumo, que conta as compras no cartão no mês em que a fatura vence.`, { tam: 8.5, cor: C.txt2 });
      if (d.extrato.some(t => t.previsto)) paragrafo('* previsto: com data futura ou ainda não marcado como pago/recebido.', { tam: 8, cor: C.mudo });
    }

    // rodapé com número da página (depois de saber o total)
    const n = doc.pags.length;
    doc.pags.forEach((p, i) => {
      doc.p = p;
      doc.linha(M, PH - 30, PW - M, PH - 30, C.grade, 0.5);
      doc.texto(M, PH - 18, 'Controle de Gastos · relatório gerado no seu aparelho; os dados não saem dele para fazer este PDF', { tam: 7, cor: C.mudo });
      doc.texto(PW - M, PH - 18, `Página ${i + 1} de ${n}`, { tam: 7, cor: C.mudo, al: 'd' });
    });
    return doc.bytes(`${d.titulo} - ${d.periodo.rotulo}`);
  }
  const r2 = v => Math.round(v * 100) / 100;

  const api = { pdf, _t: { largura, cabe, quebrar, glifos, Doc } };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  raiz.Relatorio = api;
})(typeof window !== 'undefined' ? window : globalThis);
