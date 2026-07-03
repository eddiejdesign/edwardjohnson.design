# Tools

Small self-contained utilities hosted at `edwardjohnson.design/tools/`.

## Convention

- One folder per tool: `tools/<tool-name>/index.html`.
- Each tool is a single static page — vanilla HTML/CSS/JS, no build step, no dependencies. GitHub Pages serves the repo as-is.
- Shared styling lives in `tools/shared.css` (dark theme, accent color, base components). Link to it with `../shared.css`.
- Persist tool state with `localStorage` under a `tools.<tool-name>` key — no backend.
- Add a card for the new tool to `tools/index.html`.
