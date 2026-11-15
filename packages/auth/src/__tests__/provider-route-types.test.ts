import { describe, it, expect } from "vitest"
import { fileURLToPath } from "node:url"
import ts from "typescript"

// Vitest strips types without checking them, and the package's tsconfig
// excludes tests, so type-level rules are checked by compiling a fixture.
const COMPILE_TIMEOUT_MS = 60_000

describe("ProviderRoute", () => {
  it(
    "accepts rateLimitByIp only on action routes",
    () => {
      const fixture = fileURLToPath(
        new URL("./fixtures/provider-route-types.ts", import.meta.url),
      )
      const program = ts.createProgram([fixture], {
        strict: true,
        noEmit: true,
        skipLibCheck: true,
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.NodeNext,
        moduleResolution: ts.ModuleResolutionKind.NodeNext,
      })

      const diagnostics = ts
        .getPreEmitDiagnostics(program)
        .map((diagnostic) =>
          ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
        )

      expect(diagnostics).toEqual([])
    },
    COMPILE_TIMEOUT_MS,
  )
})
