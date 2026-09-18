/** 법정동 가제티어 — Python dictionaries/legal_dongs.py 대응.
 * Python 은 번들 gzip 리소스(legal_dongs.txt.gz)를 읽지만, npm 배포본(dist)은 Python
 * 패키지 트리를 볼 수 없으므로 tools/convert-dicts.py 가 같은 리소스에서 생성한
 * 상수를 쓴다 (sync:check 가 드리프트를 잡는다).
 */

import { LEGAL_DONGS } from "./generated/legal_dongs.js";

/** token 이 알려진 법정동(동/읍/면/리)인지. */
export function isLegalDong(token: string): boolean {
  return LEGAL_DONGS.has(token);
}

/** 전체 법정동 가제티어. */
export function legalDongs(): ReadonlySet<string> {
  return LEGAL_DONGS;
}
