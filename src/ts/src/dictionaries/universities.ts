/** 대학 사전 게이트 — Python dictionaries/universities.py 함수층 대응. */
import { ALL_UNIVERSITIES, UNIVERSITY_ABBREV } from "./generated/universities.js";

/** 학교명이 사전에 있거나 약칭으로 매핑되는지. */
export const isUniversity = (token: string): boolean =>
  ALL_UNIVERSITIES.has(token) || UNIVERSITY_ABBREV[token] !== undefined;

/** 약칭을 정식명으로. 매핑 없으면 원본 반환. */
export const normalizeUniversity = (token: string): string => UNIVERSITY_ABBREV[token] ?? token;
