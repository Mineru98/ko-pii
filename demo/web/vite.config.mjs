// vite 는 src/ts/node_modules 의 것을 쓴다 (demo/web 에는 node_modules 가 없다) —
// 그래서 여기서는 "vite" 를 import 하지 않고 설정 객체만 내보낸다.
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

export default {
  root: here("."),
  base: "./",
  resolve: {
    alias: {
      "node:crypto": here("./src/shims/node-crypto.ts"),
      "node:fs": here("./src/shims/node-fs.ts"),
    },
  },
  // ReversibleVault 생성자가 읽는 process.env.KPII_FINGERPRINT_KEY — 브라우저에는 process 가 없다.
  define: { "process.env.KPII_FINGERPRINT_KEY": "undefined" },
  server: { port: 5173, strictPort: true, fs: { allow: [here("../..")] } },
  build: { target: "es2022" },
};
