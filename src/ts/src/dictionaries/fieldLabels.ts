/** 필드 라벨 사전 게이트 — Python dictionaries/field_labels.py 함수층 대응. */
import { FIELD_LABELS, FIELD_LABELS_NAME } from "./generated/field_labels.js";

export const isFieldLabel = (token: string): boolean => FIELD_LABELS.has(token);
export const isNameFieldLabel = (token: string): boolean => FIELD_LABELS_NAME.has(token);
