import { expect, it } from "vitest";
import { VERSION } from "../src/index.js";

it("package version is in sync with package.json", async () => {
  const pkg = (await import("../package.json", { with: { type: "json" } })) as {
    default: { version: string };
  };
  expect(VERSION).toBe(pkg.default.version);
});
