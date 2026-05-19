# Magistrala Agent UI

This is the embedded Preact/Vite UI for Magistrala Agent.

## Development

```bash
npm ci
npm run dev
```

The development server serves the UI with Vite. The production agent serves the
compiled UI from `/ui/`.

## Production Build

```bash
npm run build
```

The build writes static assets to `dist/`. The Go agent embeds this directory
through `ui/embed.go`, so build the UI before compiling or testing the Go
binary.

From the repository root:

```bash
make ui_prod
make all
```
