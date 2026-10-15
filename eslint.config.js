// ESLint flat config: the recommended rules plus a few strict ones. Run: npm run lint
import js from "@eslint/js";
import globals from "globals";

export default [
  { ignores: ["node_modules/", "data/"] },
  js.configs.recommended,
  {
    languageOptions: { ecmaVersion: 2024, sourceType: "module", globals: globals.node },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      eqeqeq: ["error", "always"],
      "prefer-const": "error",
    },
  },
];
