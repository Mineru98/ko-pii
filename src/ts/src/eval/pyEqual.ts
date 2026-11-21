/**
 * eval 보고서 비교용 Python ``==`` 근사 (JSON 값 한정) — ``bool`` 은 ``int`` 와 같은 수로 본다.
 * ``undefined`` 는 Python ``dict.get`` 의 ``None`` 으로 취급한다.
 */
export function pyEqual(a: unknown, b: unknown): boolean {
  const x = a === undefined ? null : a;
  const y = b === undefined ? null : b;
  const numeric = (v: unknown): v is number | boolean =>
    typeof v === "number" || typeof v === "boolean";
  if (numeric(x) && numeric(y)) return Number(x) === Number(y);
  if (Array.isArray(x) || Array.isArray(y)) {
    if (!Array.isArray(x) || !Array.isArray(y) || x.length !== y.length) return false;
    return x.every((v, i) => pyEqual(v, y[i]));
  }
  if (typeof x === "object" && x !== null && typeof y === "object" && y !== null) {
    const kx = Object.keys(x);
    const ky = Object.keys(y);
    if (kx.length !== ky.length) return false;
    const rx = x as Record<string, unknown>;
    const ry = y as Record<string, unknown>;
    return kx.every((k) => Object.hasOwn(ry, k) && pyEqual(rx[k], ry[k]));
  }
  return x === y;
}
