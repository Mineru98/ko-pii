/**
 * 직업/직책 일반화 — 구체 직책 → 범주.
 *
 * 극도로 단순한 카테고리 매핑. Phase 4 에서 부처/직급 사전과 함께 정교화.
 */

type Category = readonly [readonly string[], string];

const CATEGORIES: readonly Category[] = [
  [
    ["장관", "차관", "실장", "국장", "과장", "주무관", "서기관", "사무관", "주사", "주사보"],
    "공무원",
  ],
  [["대표이사", "이사", "임원", "사장", "부사장", "전무", "상무"], "경영진"],
  [
    ["교수", "부교수", "조교수", "강사", "박사후연구원", "선임연구원", "책임연구원", "수석연구원"],
    "연구/학계",
  ],
  [["의사", "전문의", "수련의", "간호사", "약사", "한의사"], "의료"],
  [["판사", "검사", "변호사", "법무사"], "법조"],
  [["회계사", "세무사", "감정평가사"], "회계/세무"],
  [["선생", "교사"], "교사"],
];

/**
 * Return a coarse category for ``title``.
 *
 * Unknown titles are returned unchanged (caller decides whether to surface).
 */
export function generalizeOccupation(title: string): string {
  for (const [needles, category] of CATEGORIES) {
    for (const needle of needles) {
      if (title.includes(needle)) return category;
    }
  }
  return title;
}
