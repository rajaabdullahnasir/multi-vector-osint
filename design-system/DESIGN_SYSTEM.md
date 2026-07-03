# OSINT Vector Design System

**Multi-Vector OSINT Analyzer** — visual language inspired by [TryHackMe](https://tryhackme.com): dark navy canvas, lime-green primary actions, card-based module dashboard, and monospace output for forensic data.

Prepared for **iSeeWaves Pvt Ltd** · aligns with FYP spec in `OSINT Vector.pdf`.

---

## Quick start

```html
<link rel="stylesheet" href="/static/design-system/theme.css" />
<body class="ov-body ov-app">…</body>
```

**Live preview:** open `design-system/preview.html` in a browser.

| File | Purpose |
|------|---------|
| `tokens.css` | CSS custom properties (source of truth for apps) |
| `tokens.json` | Machine-readable tokens (Figma, Style Dictionary) |
| `typography.css` | Type scale + Google Fonts |
| `components.css` | Layout, cards, forms, tables, badges |
| `theme.css` | Single bundle import |

---

## Design principles (TryHackMe mapping)

| TryHackMe pattern | OSINT Vector implementation |
|-------------------|----------------------------|
| Dark-first UI | `--ov-bg-canvas` → `--ov-bg-surface` elevation ladder |
| Signature lime CTA | `--ov-color-primary` `#9fef00` |
| Navy brand surfaces | `--ov-color-navy` `#212c42` (THM header color) |
| “Room” cards | `.ov-module-card` with top accent bar |
| Difficulty / status chips | `.ov-badge--easy \| medium \| hard` |
| Learning path sidebar | `.ov-sidebar` + `.ov-nav` |
| Terminal / challenge output | `.ov-mono-block`, `.ov-table__mono` |
| Progress on tasks | `.ov-progress` (subdomain scan, etc.) |

---

## Color system

### Brand

| Token | Hex | Usage |
|-------|-----|--------|
| `primary` | `#9fef00` | Primary buttons, links, focus, logo accent |
| `primary-hover` | `#b8ff33` | Hover states |
| `navy` | `#212c42` | Cards, THM-aligned surfaces |
| `accent-red` | `#c11111` | Critical brand accent (THM logo variant) |

### Background elevation

```
canvas (#0f1419) → base (#151c28) → elevated (#1c2538) → surface (#212c42)
```

Use **higher** tokens for cards and panels, **lower** for page background.

### Semantic (investigation outcomes)

| Token | Use case |
|-------|----------|
| `success` / `safe` | No breach, URL safe, subdomain active |
| `warning` / `suspicious` | Rate limits, suspicious URL (SRS-38) |
| `danger` / `dangerous` | Breach found, phishing URL, account lockout |
| `info` | Pending verification, inactive host |

### OSINT module accents

Each module tile uses `data-module` for the top border color:

| `data-module` | Color | Module |
|---------------|-------|--------|
| `image` | Purple `#a78bfa` | Image OSINT / EXIF |
| `whois` | Blue `#5b9fff` | WHOIS & domain |
| `subdomain` | Cyan `#38bdf8` | Subdomain finder |
| `email-breach` | Pink `#f472b6` | Email breach |
| `password-breach` | Orange `#fb923c` | Password breach (k-anon) |
| `username` | Green `#34d399` | Username OSINT |
| `url-risk` | Red `#f87171` | URL risk |
| `hasher` | Lime `#9fef00` | Password hasher |

---

## Typography

- **UI:** Plus Jakarta Sans (weights 400–800) — modern, approachable, similar to THM’s product feel.
- **Data / CLI output:** JetBrains Mono — WHOIS rows, hashes, logs.

| Class | Size | Weight | Use |
|-------|------|--------|-----|
| `.ov-display-1` | 2.25rem | 800 | Marketing / login hero |
| `.ov-display-2` | 1.875rem | 700 | Page titles |
| `.ov-heading-1` | 1.5rem | 700 | Section headers |
| `.ov-heading-2` | 1.25rem | 600 | Card titles |
| `.ov-label` | 0.875rem | 500 | Form labels |
| `.ov-caption` | 0.75rem | 400 | Hints, timestamps |
| `.ov-overline` | 0.75rem | 600 caps | Eyebrow (“Security Analyst”) |
| `.ov-mono-block` | 0.875rem | mono | Tool output |

---

## Spacing & layout

- **Grid unit:** 4px base (`--ov-space-*`).
- **Sidebar:** 260px (`--ov-sidebar-width`).
- **Header:** 64px sticky.
- **Content max width:** 1280px.
- **Module grid:** `repeat(auto-fill, minmax(280px, 1fr))`.

---

## Components

### Shell

```html
<div class="ov-shell">
  <aside class="ov-sidebar">…</aside>
  <div class="ov-main">
    <header class="ov-header">…</header>
    <main class="ov-content">…</main>
  </div>
</div>
```

### Module card

```html
<article class="ov-card ov-module-card ov-card--interactive" data-module="whois">
  <div class="ov-module-card__icon">🌐</div>
  <h2 class="ov-card__title">WHOIS Lookup</h2>
  <p class="ov-card__desc">…</p>
  <span class="ov-badge ov-badge--easy">Ready</span>
</article>
```

### Buttons

| Class | When |
|-------|------|
| `.ov-btn--primary` | Main action (Run lookup, Check breach) |
| `.ov-btn--secondary` | Export, Cancel |
| `.ov-btn--ghost` | Tertiary / nav actions |
| `.ov-btn--danger` | Delete user, destructive |

### Badges (SRS status mapping)

| SRS concept | Badge class |
|-------------|-------------|
| URL Safe | `ov-badge--safe` |
| URL Suspicious | `ov-badge--suspicious` |
| URL Dangerous | `ov-badge--dangerous` |
| Subdomain active | `ov-badge--active` |
| Subdomain inactive | `ov-badge--inactive` |
| User pending | `ov-badge--pending` |
| User suspended | `ov-badge--suspended` |
| THM-style difficulty | `easy` / `medium` / `hard` |

### Forms

- Always pair `.ov-field__label` + `.ov-input`.
- Use `.ov-input--mono` for domains, emails, hashes.
- Focus ring uses lime border + outer glow (`--ov-input-focus-ring`).

### Alerts

Map API errors and SRS extension messages:

- Success: “No breaches found” → `.ov-alert--success`
- Warning: rate limit → `.ov-alert--warning`
- Danger: compromised password → `.ov-alert--danger`

---

## Page templates (recommended)

| Route | Layout | Key components |
|-------|--------|----------------|
| `/login`, `/register` | Centered card on canvas | `.ov-card`, `.ov-btn--primary` |
| `/dashboard` | Shell + module grid | `.ov-module-grid`, `.ov-stats` |
| `/modules/:id` | Shell + form + results | `.ov-field`, `.ov-progress`, `.ov-table` |
| `/reports` | Shell + table | `.ov-table`, export buttons |
| `/admin/users` | Shell + table + badges | `.ov-badge--pending`, actions |
| `/admin/logs` | Shell + filters + mono | `.ov-mono-block` |

---

## Accessibility

- Minimum contrast: primary lime on dark passes for **large text / UI chrome**; use white (`--ov-text-primary`) for body copy.
- `:focus-visible` outline on all interactive elements (defined in `theme.css`).
- Do not rely on color alone — pair badges with text (“Dangerous”, “Active”).
- Masked inputs for password breach module (styled via `.ov-input[type=password]`).

---

## Framework integration

### Django templates

```django
{% load static %}
<link rel="stylesheet" href="{% static 'design-system/theme.css' %}">
```

Copy `design-system/` into `static/design-system/`.

### React / Vite

```ts
import '../design-system/theme.css';
// Or map tokens.json via style-dictionary
```

Prefix `ov-` avoids collisions with Bootstrap if both are used; prefer **tokens only** if Bootstrap is required for grid.

### Tailwind (optional)

Extend `theme.extend.colors` from `tokens.json` values, or use CSS variables:

```js
colors: {
  brand: 'var(--ov-color-primary)',
  surface: 'var(--ov-bg-surface)',
}
```

---

## Light theme

Set `data-theme="light"` on `<html>` for optional light mode overrides (tokens in `tokens.css`). Default is **dark** to match TryHackMe.

---

## Legal / brand note

This system **evokes** TryHackMe’s public aesthetic (dark + lime cybersecurity UI) for an educational FYP project. It is **not** an official TryHackMe product. Use original logo/wordmark for OSINT Vector (“OV” mark in preview only).

---

## Changelog

| Version | Date | Notes |
|---------|------|-------|
| 1.0.0 | 2026-05-23 | Initial tokens, components, preview |
