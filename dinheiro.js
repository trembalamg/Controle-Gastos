/* Leitura de valores em reais digitados pelo usuário.
 *
 * Função pura (sem DOM): roda no navegador (window.Dinheiro) e no Node
 * (require('./dinheiro.js')), testada em testes/dinheiro.test.js.
 *
 * Formatos aceitos (padrão brasileiro):
 *   1.500      -> 1500      (ponto seguido de grupos de 3 dígitos = milhar)
 *   1.500,00   -> 1500
 *   1500       -> 1500
 *   1500,50    -> 1500.5
 *   25,90      -> 25.9
 *   R$ 1.234.567,89 -> 1234567.89
 *   10.5 / 10.50    -> 10.5   (ponto com 1 ou 2 casas = decimal, como antes)
 *   -120,00    -> -120      (sinal só é usado no saldo da conta)
 * Qualquer outra coisa (texto, várias vírgulas, "1.50.0", "1.5000") -> NaN.
 * Não arredonda: quem grava continua usando r2() como antes.
 */
(function (root) {
  'use strict';

  function parseMoney(s) {
    if (typeof s === 'number') return s;
    s = String(s == null ? '' : s).trim().replace(/R\$/gi, '').replace(/\s+/g, '');
    if (!s) return NaN;
    let sinal = 1;
    if (s[0] === '-') { sinal = -1; s = s.slice(1); }
    let n;
    if (s.includes(',')) {
      // vírgula = decimal; pontos (se houver) têm de ser separadores de milhar bem formados
      if (!/^\d{1,3}(\.\d{3})*,\d*$|^\d+,\d*$/.test(s)) return NaN;
      n = s.replace(/\./g, '').replace(',', '.');
    } else if (/^\d{1,3}(\.\d{3})+$/.test(s)) {
      n = s.replace(/\./g, '');                // 1.500 / 12.345.678 -> milhar
    } else if (/^\d+(\.\d{1,2})?$/.test(s)) {
      n = s;                                   // 1500 / 10.5 / 10.50 -> decimal com ponto
    } else {
      return NaN;
    }
    if (n.endsWith('.')) n = n.slice(0, -1);   // "25," -> 25
    const v = Number(n);
    return Number.isFinite(v) ? sinal * v : NaN;
  }

  const api = { parseMoney };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.Dinheiro = api;
})(typeof window !== 'undefined' ? window : this);
