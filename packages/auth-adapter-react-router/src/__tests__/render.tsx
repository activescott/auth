import { act } from "react"
import type { ReactElement } from "react"
import { createRoot } from "react-dom/client"

// Tells React this is a test environment that wraps updates in act()
;(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true

/** Mount an element into a fresh container in the document */
export function render(element: ReactElement): {
  container: HTMLElement
  unmount: () => void
} {
  const container = document.createElement("div")
  document.body.append(container)
  const root = createRoot(container)
  act(() => root.render(element))
  return {
    container,
    unmount: () => {
      act(() => root.unmount())
      container.remove()
    },
  }
}

/**
 * Run a hook inside a component and expose its latest return value.
 * `children` renders alongside, for hooks that need elements (refs).
 */
export function renderHook<T>(
  hook: () => T,
  children?: (value: T) => ReactElement | null,
): { result: { current: T }; unmount: () => void } {
  const result = { current: undefined as T }
  function Probe(): ReactElement | null {
    result.current = hook()
    return children ? children(result.current) : null
  }
  const { unmount } = render(<Probe />)
  return { result, unmount }
}
