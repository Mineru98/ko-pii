/** 일반어 사전 게이트 — Python dictionaries/common_words.py 함수층 대응. */
import { COMMON_WORDS, MFDS_DOMAIN_WORDS } from "./generated/common_words.js";

export const isCommonWord = (token: string): boolean =>
  COMMON_WORDS.has(token) || MFDS_DOMAIN_WORDS.has(token);
