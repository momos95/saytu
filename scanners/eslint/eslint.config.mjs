// SAYTU ESLint configuration (Apache-2.0). Loaded with --config: the audited repository's own
// eslint.config.* (JavaScript, i.e. code) is never executed. Inline "eslint-disable" comments are
// ignored (--no-inline-config). Rules: ESLint recommended, typescript-eslint recommended (no type
// information, so no tsconfig of the repository is loaded), eslint-plugin-security recommended.
import js from "@eslint/js";
import security from "eslint-plugin-security";
import globals from "globals";
import tseslint from "typescript-eslint";

const JS = ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs"];
const TS = ["**/*.ts", "**/*.tsx", "**/*.mts", "**/*.cts"];

export default [
  {
    ignores: [
      "**/node_modules/", "**/bower_components/", "**/vendor/", "**/third_party/", "**/dist/", "**/build/",
      "**/target/", "**/out/", "**/coverage/", "**/.next/", "**/.nuxt/", "**/.angular/", "**/.svelte-kit/",
      "**/*.min.js", "**/*.bundle.js", "**/*.chunk.js", "**/*.d.ts",
    ],
  },
  {
    files: [...JS, ...TS],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: { ...globals.browser, ...globals.node, ...globals.es2021 },
    },
    linterOptions: { reportUnusedDisableDirectives: "off" },
  },
  { files: [...JS, ...TS], ...js.configs.recommended },
  ...tseslint.configs.recommended.map((config) => ({ ...config, files: config.files ?? TS })),
  { files: [...JS, ...TS], ...security.configs.recommended },
];
