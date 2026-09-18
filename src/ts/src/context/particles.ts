/** 한국어 조사 처리 — Python ko_pii.context.particles 대응.
 * 이름이 조사와 붙어 등장("홍길동이", "홍길동에게")할 때 조사를 분리한다.
 */

/** 길이가 긴 조사부터 시도해야 옳게 매칭됨 ("에게"가 "에"보다 먼저). */
export const PARTICLES: readonly string[] = [
  "에게서",
  "한테서",
  "께서",
  "에게",
  "한테",
  "에서",
  "으로",
  "보다",
  "이가",
  "이는",
  "이도",
  "이를",
  "은",
  "는",
  "이",
  "가",
  "을",
  "를",
  "와",
  "과",
  "의",
  "에",
  "도",
  "만",
  "야",
  "라",
  "여",
];

/** (stem, particle) 반환 — 떼낸 조사가 없으면 particle 은 null. */
export function stripTrailingParticle(token: string): [string, string | null] {
  for (const p of PARTICLES) {
    if (token.endsWith(p) && token.length > p.length) {
      return [token.slice(0, -p.length), p];
    }
  }
  return [token, null];
}

export function startsWithParticle(token: string): boolean {
  return PARTICLES.some((p) => token.startsWith(p));
}
