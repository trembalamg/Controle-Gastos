/* Regras de data do Controle de Gastos.
 *
 * Funções puras (sem DOM): rodam no navegador (window.Regras) e no Node
 * (require('./regras.js')), para poderem ser testadas em testes/regras.test.js.
 *
 * Datas são strings 'AAAA-MM-DD'. Meses são 1-12.
 * Os cálculos usam UTC para não sofrer com horário de verão/fuso.
 */
(function (root) {
  'use strict';

  /* ------------------------------------------------------------------
   * FERIADOS
   * Hoje só sábado e domingo contam como dias não úteis (as listas abaixo
   * estão vazias de propósito). Para passar a considerar feriados, basta
   * preencher:
   *   nacionaisFixos: datas que se repetem todo ano, formato 'MM-DD'
   *                   ex.: ['01-01','04-21','05-01','09-07','10-12','11-02','11-15','11-20','12-25']
   *   datas:          feriados de data específica (móveis como Carnaval e
   *                   Sexta-feira Santa, estaduais, municipais), 'AAAA-MM-DD'
   *                   ex.: ['2026-04-03', '2026-02-17']
   *   estaduais:      por UF, também 'MM-DD' (fixos) ou 'AAAA-MM-DD'
   *                   ex.: { MG: ['04-21'] }   uf: 'MG' escolhe qual usar
   * ------------------------------------------------------------------ */
  const FERIADOS = {
    nacionaisFixos: [],
    datas: [],
    estaduais: {},
    uf: null,
  };

  /* ------------------------------------------------------------------
   * REGRA DO SALÁRIO
   *   sabadoUtil:        sábado conta como dia útil (se não for feriado)
   *   sabadoPagaNaSexta: se o 5º dia útil cair num sábado, a empresa paga no
   *                      dia útil de segunda a sexta imediatamente anterior
   *                      (normalmente a sexta; se ela for feriado, a quinta…)
   * ------------------------------------------------------------------ */
  const REGRA_SALARIO = {
    diaUtil: 5,
    sabadoUtil: true,
    sabadoPagaNaSexta: true,
  };

  const pad = n => String(n).padStart(2, '0');
  const fmt = (y, m, d) => `${y}-${pad(m)}-${pad(d)}`;

  // normaliza (2026, 13) -> (2027, 1) e (2026, 0) -> (2025, 12)
  function normYM(year, month) {
    const t = year * 12 + (month - 1);
    return [Math.floor(t / 12), (t % 12 + 12) % 12 + 1];
  }

  function daysInMonth(year, month) {
    [year, month] = normYM(year, month);
    return new Date(Date.UTC(year, month, 0)).getUTCDate();
  }

  // 0 = domingo ... 6 = sábado
  function weekday(year, month, day) {
    return new Date(Date.UTC(year, month - 1, day)).getUTCDay();
  }

  /** Conjunto de feriados ('AAAA-MM-DD') de um ano, a partir da configuração. */
  function holidaysFor(year, cfg) {
    cfg = cfg || FERIADOS;
    const out = new Set();
    const add = item => {
      if (/^\d{2}-\d{2}$/.test(item)) out.add(`${year}-${item}`);
      else if (/^\d{4}-\d{2}-\d{2}$/.test(item) && item.startsWith(year + '-')) out.add(item);
    };
    (cfg.nacionaisFixos || []).forEach(add);
    (cfg.datas || []).forEach(add);
    if (cfg.uf && cfg.estaduais && cfg.estaduais[cfg.uf]) cfg.estaduais[cfg.uf].forEach(add);
    return out;
  }

  function toSet(holidays, year) {
    if (holidays instanceof Set) return holidays;
    if (Array.isArray(holidays)) return new Set(holidays);
    return holidaysFor(year); // não informado: usa a configuração FERIADOS
  }

  /** true se a data é dia útil. Domingo e feriado nunca são; sábado só com opts.sabadoUtil. */
  function isBusinessDay(dateStr, holidays, opts) {
    const [y, m, d] = dateStr.split('-').map(Number);
    const wd = weekday(y, m, d);
    if (wd === 0) return false;
    if (wd === 6 && !(opts && opts.sabadoUtil)) return false;
    return !toSet(holidays, y).has(dateStr);
  }

  /** N-ésimo dia útil do mês. Retorna 'AAAA-MM-DD'. */
  function getNthBusinessDay(year, month, n, holidays, opts) {
    [year, month] = normYM(year, month);
    const hs = toSet(holidays, year);
    const last = daysInMonth(year, month);
    let count = 0;
    for (let d = 1; d <= last; d++) {
      const ds = fmt(year, month, d);
      if (isBusinessDay(ds, hs, opts) && ++count === n) return ds;
    }
    throw new Error(`O mês ${pad(month)}/${year} não tem ${n} dias úteis`);
  }

  /** Quinto dia útil do mês. Padrão: segunda a sexta; com { sabadoUtil: true } o sábado também conta. */
  function getFifthBusinessDay(year, month, holidays, opts) {
    return getNthBusinessDay(year, month, 5, holidays, opts);
  }

  /** Data em que o salário cai no mês, pela REGRA_SALARIO (ou outra regra informada). */
  function getSalaryDate(year, month, holidays, regra) {
    regra = regra || REGRA_SALARIO;
    [year, month] = normYM(year, month);
    const hs = toSet(holidays, year);
    let ds = getNthBusinessDay(year, month, regra.diaUtil || 5, hs, { sabadoUtil: regra.sabadoUtil });
    if (regra.sabadoPagaNaSexta) {
      let [y, m, d] = ds.split('-').map(Number);
      if (weekday(y, m, d) === 6) {
        // volta até o dia de semana (seg-sex) não feriado mais próximo
        do { d--; ds = fmt(y, m, d); } while (d > 1 && !isBusinessDay(ds, hs));
      }
    }
    return ds;
  }

  /** Datas do salário para N meses a partir de 'AAAA-MM' (cada mês calculado individualmente). */
  function salaryDates(startYM, count, holidays, regra) {
    const [y0, m0] = startYM.split('-').map(Number);
    const out = [];
    for (let i = 0; i < count; i++) {
      const [y, m] = normYM(y0, m0 + i);
      out.push(getSalaryDate(y, m, holidays, regra));
    }
    return out;
  }

  /** Mês sugerido para um novo salário: o atual, ou o próximo se a data do salário já passou. */
  function nextSalaryMonth(todayStr, holidays, regra) {
    const [y, m] = todayStr.split('-').map(Number);
    if (getSalaryDate(y, m, holidays, regra) >= todayStr) return `${y}-${pad(m)}`;
    const [ny, nm] = normYM(y, m + 1);
    return `${ny}-${pad(nm)}`;
  }

  /* ------------------------------------------------------------------
   * CALENDÁRIO BANCÁRIO (vencimento de faturas)
   * Separado da regra do salário (acima): aqui SÁBADO e DOMINGO nunca são
   * dias úteis e entram os feriados em que os bancos não funcionam.
   *   nacional  - feriados nacionais por lei (Leis 662/1949, 6.802/1980,
   *               10.607/2002 e 14.759/2023 - Consciência Negra desde 2024)
   *   bancario  - Sexta-feira da Paixão (feriado religioso; consta no
   *               calendário bancário nacional da FEBRABAN/ANBIMA)
   *   estadual / municipal - só os informados pelo usuário (nada é presumido)
   *   pontos facultativos (Carnaval seg/ter e Corpus Christi): os bancos
   *               costumam fechar, mas por serem pontos facultativos só
   *               contam se o usuário ligar a opção (cfg.pontosFacultativos)
   * cfg = { uf, municipio, estaduais:['MM-DD'|'AAAA-MM-DD'], municipais:[...],
   *         pontosFacultativos:false }
   * ------------------------------------------------------------------ */
  function pascoa(year) { // algoritmo de Meeus/Jones/Butcher (calendário gregoriano)
    const a = year % 19, b = Math.floor(year / 100), c = year % 100, d = Math.floor(b / 4), e = b % 4;
    const f = Math.floor((b + 8) / 25), g = Math.floor((b - f + 1) / 3), h = (19 * a + b - d - g + 15) % 30;
    const i = Math.floor(c / 4), k = c % 4, l = (32 + 2 * e + 2 * i - h - k) % 7, m = Math.floor((a + 11 * h + 22 * l) / 451);
    const month = Math.floor((h + l - 7 * m + 114) / 31), day = ((h + l - 7 * m + 114) % 31) + 1;
    return fmt(year, month, day);
  }
  function somaDias(dateStr, n) {
    const [y, m, d] = dateStr.split('-').map(Number);
    const x = new Date(Date.UTC(y, m - 1, d + n));
    return fmt(x.getUTCFullYear(), x.getUTCMonth() + 1, x.getUTCDate());
  }
  const NACIONAIS_FIXOS = [['01-01', 'Confraternização Universal'], ['04-21', 'Tiradentes'], ['05-01', 'Dia do Trabalho'],
    ['09-07', 'Independência do Brasil'], ['10-12', 'Nossa Senhora Aparecida'], ['11-02', 'Finados'],
    ['11-15', 'Proclamação da República'], ['12-25', 'Natal']];
  const _cacheBanc = new Map();
  /** Map 'AAAA-MM-DD' -> {nome, tipo} com os dias sem expediente bancário do ano. */
  function feriadosBancarios(year, cfg) {
    cfg = cfg || {};
    const chave = year + '|' + JSON.stringify([cfg.estaduais || [], cfg.municipais || [], !!cfg.pontosFacultativos]);
    if (_cacheBanc.has(chave)) return _cacheBanc.get(chave);
    const out = new Map();
    const put = (d, nome, tipo) => { if (!out.has(d)) out.set(d, { nome, tipo }); };
    for (const [md, nome] of NACIONAIS_FIXOS) put(`${year}-${md}`, nome, 'nacional');
    if (year >= 2024) put(`${year}-11-20`, 'Dia Nacional de Zumbi e da Consciência Negra', 'nacional');
    const p = pascoa(year);
    put(somaDias(p, -2), 'Sexta-feira da Paixão', 'bancario');
    if (cfg.pontosFacultativos) {
      put(somaDias(p, -48), 'Carnaval (segunda)', 'ponto facultativo');
      put(somaDias(p, -47), 'Carnaval (terça)', 'ponto facultativo');
      put(somaDias(p, 60), 'Corpus Christi', 'ponto facultativo');
    }
    const locais = (lista, tipo) => (lista || []).forEach(item => {
      if (/^\d{2}-\d{2}$/.test(item)) put(`${year}-${item}`, `Feriado ${tipo}`, tipo);
      else if (/^\d{4}-\d{2}-\d{2}$/.test(item) && item.startsWith(year + '-')) put(item, `Feriado ${tipo}`, tipo);
    });
    locais(cfg.estaduais, 'estadual');
    locais(cfg.municipais, 'municipal');
    _cacheBanc.set(chave, out);
    return out;
  }
  /** Dia útil bancário: segunda a sexta e fora dos feriados bancários. */
  function isBankBusinessDay(dateStr, cfg) {
    const [y, m, d] = dateStr.split('-').map(Number);
    const wd = weekday(y, m, d);
    if (wd === 0 || wd === 6) return false;
    return !feriadosBancarios(y, cfg).has(dateStr);
  }
  /** A própria data, se for dia útil bancário; senão o próximo dia útil bancário. */
  function nextBankBusinessDay(dateStr, cfg) {
    let d = dateStr;
    for (let i = 0; i < 15 && !isBankBusinessDay(d, cfg); i++) d = somaDias(d, 1);
    return d;
  }
  /** Motivo de a data não ser dia útil bancário (para mostrar na tela), ou null. */
  function motivoNaoUtil(dateStr, cfg) {
    const [y, m, d] = dateStr.split('-').map(Number);
    const wd = weekday(y, m, d);
    if (wd === 6) return 'sábado';
    if (wd === 0) return 'domingo';
    const f = feriadosBancarios(y, cfg).get(dateStr);
    return f ? f.nome : null;
  }

  const api = { FERIADOS, REGRA_SALARIO, holidaysFor, isBusinessDay, getNthBusinessDay, getFifthBusinessDay, getSalaryDate, salaryDates, nextSalaryMonth, daysInMonth, normYM,
    pascoa, feriadosBancarios, isBankBusinessDay, nextBankBusinessDay, motivoNaoUtil };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.Regras = api;
})(typeof window !== 'undefined' ? window : this);
