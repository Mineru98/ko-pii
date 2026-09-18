import { expect, it } from "vitest";
import * as dict from "../../src/dictionaries/index.js";

/** 사전 게이트 함수 스모크 — Python 함수층과의 대표 케이스 정합 (Python docstring 예제 포함). */
it("dictionary gates behave like the Python layer", () => {
  expect(dict.isProvince("서울특별시")).toBe(true);
  expect(dict.isProvince("서울")).toBe(true);
  expect(dict.isValidProvinceDistrict("경기도", "성남시")).toBe(true);
  expect(dict.isValidProvinceDistrict("경기도", "강남구")).toBe(false); // 강남구는 서울
  expect(dict.isValidProvinceDistrict("서울특별시", "강남구")).toBe(true);
  expect(dict.normalizeProvince("서울")).toBe("서울특별시");
  expect(dict.isCountry("대한민국")).toBe(true);

  expect(dict.isSurname("홍")).toBe(true);
  expect(dict.isSurname("선우")).toBe(true);
  expect(dict.surnamePrefixLen("선우길동")).toBe(2);
  expect(dict.surnamePrefixLen("홍길동")).toBe(1);
  // "길" 도 실제 한국 성씨라 선행 성씨로 인정된다 (Python 동작 확인).
  expect(dict.surnamePrefixLen("길동")).toBe(1);
  expect(dict.surnamePrefixLen("ㅎ길동")).toBe(0);

  expect(dict.isTitle("과장")).toBe(true);
  expect(dict.titleDomain("치안총감")).toBe("police");
  expect(dict.titleDomain("과장")).toBe("gov");

  // agency_titles docstring 예제
  expect(dict.isValidAgencyTitle("기획재정부", "사무관")).toBe(true);
  expect(dict.isValidAgencyTitle("환경부", "치안총감")).toBe(false);
  expect(dict.isValidAgencyTitle("행정안전부", "경찰청장")).toBe(true); // 산하 외청
  expect(dict.specializedAgenciesFor("치안총감")).toEqual(["경찰청"]);

  expect(dict.normalizeMajor("컴퓨터공학과")).toBe("컴퓨터공학");
  // Python 실측: "경영" 이 ALL_MAJORS 에 있어 stem 이 그대로 반환된다 (docstring 과 무관).
  expect(dict.normalizeMajor("경영학부")).toBe("경영");
  expect(dict.isUniversity("서울대")).toBe(true);
  expect(dict.normalizeUniversity("서울대")).toBe("서울대학교");
  expect(dict.isCommonWord("오늘")).toBe(true);
  expect(typeof dict.isLegalDong("역삼동")).toBe("boolean");

  expect(dict.isAgency("기획재정부")).toBe(true);
  expect(dict.normalizeAgency("기재부")).not.toBeNull();
  expect(dict.isFieldLabel("성명")).toBe(true);
  expect(dict.isNameFieldLabel("성명")).toBe(true);
  expect(dict.isFieldLabel("주소")).toBe(true);
});
