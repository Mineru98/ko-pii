/** Pseudonymization / redaction modes — apply detections to text. */

export type { AppliedSpan, Replacer } from "./apply.js";
export { applySubstitutions, prepareDetections } from "./apply.js";
export { FPE_BY_LABEL, fpe, fpeDefault, pseudonymizeValue } from "./fpe.js";
export { hashed } from "./hashed.js";
export { MASK, maskValue, partial } from "./partial.js";
export { labelToHangul, redact } from "./redact.js";
export { tokenize } from "./tokenize.js";
export type { ModesVault } from "./vault.js";
