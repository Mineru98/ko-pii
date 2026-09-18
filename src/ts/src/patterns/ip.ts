/** IP address detection (IPv4 + IPv6).
 *
 * Python 원본: src/ko_pii/patterns/ip.py — 1:1 포팅 (골드 마스터 기준).
 *
 * IPv6 유효성은 Python 이 표준 라이브러리 ipaddress.IPv6Address 로 판정하므로,
 * CPython Lib/ipaddress.py 의 _ip_int_from_string/_parse_hextet/_parse_octet
 * 알고리즘을 동일하게 재현했다 (IPv4 임베드 꼬리 leading-zero 거부 포함).
 */

import { type DetectionResult, makeDetection, RiskLevel } from "../core/types.js";

const LABEL = "IP";
const LEGAL_BASIS = "개인정보보호법 제2조";
const CATEGORY = "일반개인정보";

const IPV4 = /(?<![0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?![0-9.])/g;

// IPv6 candidate: hex digits, colons, optional embedded IPv4 tail
// (::ffff:1.2.3.4). Final validity is decided by the (reimplemented) standard
// library parser, so the regex is deliberately permissive.
const IPV6 =
  /(?<![0-9A-Fa-f:.])([0-9A-Fa-f:]*::[0-9A-Fa-f:]*(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3})?|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})(?:%[A-Za-z0-9]+)?(?![0-9A-Fa-f:.])/g;

function isValidIpv4(addr: string): boolean {
  const parts = addr.split(".");
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^[0-9]+$/.test(p) || p.length < 1 || p.length > 3) return false;
    const n = Number(p);
    if (!(n >= 0 && n <= 255)) return false;
  }
  return true;
}

/** IANA 특수목적 주소 — 개인 식별과 무관해 PII 가 아니다(loopback 127.0.0.1 등).
 * 사설망(10/172.16/192.168)은 결합 시 식별 가능성이 있어 제외하지 않는다(recall 보존). */
function isReservedIpv4(addr: string): boolean {
  const [a, b, c] = addr.split(".").map((x) => Number(x));
  return (
    a === 127 || // loopback 127/8
    a === 0 || // "this network" 0/8
    (a === 169 && b === 254) || // link-local 169.254/16
    (a === 192 && b === 0 && c === 2) || // TEST-NET-1 (문서용)
    (a === 198 && b === 51 && c === 100) || // TEST-NET-2
    (a === 203 && b === 0 && c === 113) || // TEST-NET-3
    (a ?? 0) >= 224 // multicast / reserved 224.0.0.0+
  );
}

/** Python IPv4Address 의 엄격 옥텟 파싱 — leading-zero 거부 포함. */
function parseIpv4Tail(s: string): number | null {
  const octets = s.split(".");
  if (octets.length !== 4) return null;
  let val = 0;
  for (const o of octets) {
    if (o.length < 1 || o.length > 3) return null;
    if (!/^[0-9]+$/.test(o)) return null;
    if (o.length > 1 && o.startsWith("0")) return null; // leading zeros 금지 (3.9.5+)
    const n = Number(o);
    if (n > 255) return null;
    val = val * 256 + n;
  }
  return val;
}

/** CPython _parse_hextet — [0-9A-Fa-f] 만, 최대 4자. */
function parseHextet(s: string): boolean {
  if (!/^[0-9A-Fa-f]*$/.test(s)) return false;
  if (s.length > 4) return false;
  if (s.length === 0) return false; // int("", 16) ValueError — 파싱 위치엔 빈 hextet 이 올 수 없지만 안전판
  return true;
}

/** CPython ipaddress._BaseV6._ip_int_from_string 의 유효성 판정부 재현. */
function isValidIpv6Address(raw: string): boolean {
  if (raw.length === 0) return false; // Address cannot be empty
  if (raw.length > 45) return false; // At most 45 characters

  // We want to allow more parts than the max to be 'split' — Python 은
  // split(':', maxsplit=9) 후 >9 parts 를 거부. 전체 split 으로 동일 판정.
  const parts = raw.split(":");
  // An IPv6 address needs at least 2 colons (3 parts).
  if (parts.length < 3) return false;

  // If the address has an IPv4-style suffix, convert it to hexadecimal.
  const last = parts[parts.length - 1];
  if (last !== undefined && last.includes(".")) {
    const v4 = parseIpv4Tail(last);
    if (v4 === null) return false;
    parts.pop();
    parts.push(((v4 >> 16) & 0xffff).toString(16));
    parts.push((v4 & 0xffff).toString(16));
  }

  // An IPv6 address can't have more than 8 colons (9 parts).
  if (parts.length > 9) return false;

  // Disregarding the endpoints, find '::' with nothing in between.
  let skipIndex: number | null = null;
  for (let i = 1; i < parts.length - 1; i++) {
    if (parts[i] === "") {
      if (skipIndex !== null) return false; // At most one '::'
      skipIndex = i;
    }
  }

  const first = parts[0];
  const lastPart = parts[parts.length - 1];
  let partsHi: number;
  let partsLo: number;
  let partsSkipped: number;
  if (skipIndex !== null) {
    partsHi = skipIndex;
    partsLo = parts.length - skipIndex - 1;
    if (first === "") {
      partsHi -= 1;
      if (partsHi !== 0) return false; // Leading ':' only permitted as part of '::'
    }
    if (lastPart === "") {
      partsLo -= 1;
      if (partsLo !== 0) return false; // Trailing ':' only permitted as part of '::'
    }
    partsSkipped = 8 - (partsHi + partsLo);
    if (partsSkipped < 1) return false; // Expected at most 7 other parts with '::'
  } else {
    if (parts.length !== 8) return false; // Exactly 8 parts expected without '::'
    if (first === "") return false; // Leading ':' only permitted as part of '::'
    if (lastPart === "") return false; // Trailing ':' only permitted as part of '::'
    partsHi = parts.length;
    partsLo = 0;
    partsSkipped = 0;
  }

  // hextet 파싱 (값은 불필요 — 유효성만)
  for (let i = 0; i < partsHi; i++) {
    if (!parseHextet(parts[i] ?? "")) return false;
  }
  for (let i = -partsLo; i < 0; i++) {
    if (!parseHextet(parts[parts.length + i] ?? "")) return false;
  }
  void partsSkipped;
  return true;
}

function isValidIpv6(addr: string): boolean {
  // Strip zone id (e.g. "fe80::1%eth0") — ipaddress 에 넘기기 전 제거
  const pct = addr.indexOf("%");
  const raw = pct >= 0 ? addr.slice(0, pct) : addr;
  return isValidIpv6Address(raw);
}

// 버전/빌드 문자열은 IPv4 와 형식이 같다('소프트웨어 버전 10.0.19.41'). 좌측에 버전
// 단서가 바로 붙거나(예 'v10.0.19.41') 근접하면 IP 로 채택하지 않는다(과탐 방지).
const VERSION_CTX =
  /(?:버전|버젼|펌웨어|릴리[스즈]|빌드|패치|(?<![A-Za-z])(?:[vV]\.?|ver\.?|version|firmware|release|build|patch))\s*$/;
// 문서 섹션/항목 번호('표 3.2.1.4', 'Section 4.2.1.3')도 IPv4 형식이라 좌측 단서로 제외.
const SECTION_CTX =
  /(?:표|그림|별표|도표|붙임|항목|조항|조|항|단계|절|장|버전|챕터|[Ss]ection|[Cc]hapter|[Ff]igure|[Tt]able|[Aa]ppendix|[Cc]lause|(?<![A-Za-z])(?:[Ss]ec|[Cc]h|[Ff]ig|[Aa]pp)\.?)\s*$/;
// 우측에 '버전' 단서가 바로 붙는 경우('2.10.4.5 버전입니다')도 버전 문자열로 본다.
const VERSION_RIGHT = /^\s*(?:버전|버젼|version|빌드|build|릴리[스즈])/;

export function detect(text: string): DetectionResult[] {
  const out: DetectionResult[] = [];
  const seen: Array<readonly [number, number]> = [];

  for (const m of text.matchAll(IPV4)) {
    if (m.index === undefined) continue;
    const addr = m[1];
    if (addr === undefined) continue;
    if (!isValidIpv4(addr) || isReservedIpv4(addr)) continue;
    const left = text.slice(Math.max(0, m.index - 12), m.index);
    if (VERSION_CTX.test(left) || SECTION_CTX.test(left)) continue;
    if (VERSION_RIGHT.test(text.slice(m.index + m[0].length, m.index + m[0].length + 8))) continue;
    seen.push([m.index, m.index + m[0].length]);
    out.push(
      makeDetection({
        label: LABEL,
        text: addr,
        start: m.index,
        end: m.index + m[0].length,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 1.0,
        evidence: ["pattern:ipv4"],
        legal_basis: LEGAL_BASIS,
        extra: { version: 4, value: addr, category: CATEGORY },
      }),
    );
  }

  for (const m of text.matchAll(IPV6)) {
    if (m.index === undefined) continue;
    const start = m.index;
    const end = start + m[0].length;
    if (seen.some(([s, e]) => s === start && e === end)) continue;
    const addr = m[0];
    // Filter trivial cases that the loose regex may match.
    if (!addr.includes(":")) continue;
    // 단독 "::" 만 매칭은 거부 — 텍스트에서 *주석 ::* 같은 패턴
    // (한국어 자유 텍스트의 ":" 강조 표기)
    if (addr.trim() === "::" || addr.trim() === "") continue;
    if (!isValidIpv6(addr)) continue;
    seen.push([start, end]);
    out.push(
      makeDetection({
        label: LABEL,
        text: addr,
        start,
        end,
        riskLevel: RiskLevel.MEDIUM,
        confidence: 1.0,
        evidence: ["pattern:ipv6"],
        legal_basis: LEGAL_BASIS,
        extra: { version: 6, value: addr, category: CATEGORY },
      }),
    );
  }

  return out;
}
