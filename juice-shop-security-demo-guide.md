# Web App Security Demo: SQLi, CSRF, XSS & CORS/CSP on OWASP Juice Shop

**Lecturer's guide — IF3110 Web-based Application Development**
_As of 2026-11-17_

A step-by-step guide for running four live web-security demos against a local copy of
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop), a shop that is insecure on purpose.
Each demo follows the same five steps: **find the code → attack → why it works → fix → how to avoid it.**
Code excerpts come from the Juice Shop `master` branch as of 17 Nov 2026; line numbers may shift.

> **Ethics / scope:** only ever run these against your own local instance. The same payloads against a
> real site are illegal. Juice Shop exists precisely so you can practise safely.

---

## 0. Setup

**Run Juice Shop from source** (needed for Demo 4, which is switched off inside Docker):

```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start            # open http://localhost:3000
```

**Or with Docker** (fine for Demos 1–3; the `NODE_CONFIG` flag turns the Demo 4 challenge back on):

```bash
docker run --rm -p 127.0.0.1:3000:3000 \
  -e 'NODE_CONFIG={"challenges":{"safetyMode":"disabled"}}' \
  bkimminich/juice-shop
```

**Tools:** a browser with DevTools (Network and Console tabs), `curl`, and Python for a tiny
"attacker" web server. Burp Suite is optional.

**The attacker site.** Demos 2 and 4 need a page on a *different origin*. Make a folder `evil/` and
serve it on another host and port:

```bash
mkdir evil && cd evil
python3 -m http.server 8000 --bind 127.0.0.1   # open via http://127.0.0.1:8000
```

`http://127.0.0.1:8000` and `http://localhost:3000` differ in host and port, so the browser treats
them as different origins (slide: *The Same-Origin Policy*).

**Where the code lives in the repo:**

| Demo | File | What to look at |
| --- | --- | --- |
| 1 SQL injection | `routes/login.ts`, `routes/search.ts` | `sequelize.query` with a template string |
| 2 CSRF | `routes/updateUserProfile.ts`, `server.ts` | `POST /profile` trusts the cookie alone |
| 3 XSS | `frontend/src/app/search-result/search-result.component.ts` | `bypassSecurityTrustHtml(queryParam)` |
| 4 CORS and CSP | `server.ts`, `routes/userProfile.ts` | `app.use(cors())`, CSP built from user input |

Juice Shop also ships the official fixes in `data/static/codefixes/` (files ending in `_correct.ts`).
Open the Score Board at `http://localhost:3000/#/score-board` to see each challenge tick green as you solve it.

---

## Demo 1 — SQL injection (OWASP A05 Injection)

**Teaching goal:** recognise why string-built SQL lets an attacker log in as admin or read every user row,
and rewrite it so input can never become code. Juice Shop challenges: *Login Admin*, *User Credentials*.

### The vulnerable code

`routes/login.ts` pastes the email field straight into the SQL text:

```typescript
// routes/login.ts  — VULNERABLE
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}'
   AND password = '${security.hash(req.body.password || '')}'
   AND deletedAt IS NULL`,
  { model: UserModel, plain: true })
```

`routes/search.ts` repeats it with the search box (`?q=`):

```typescript
// routes/search.ts  — VULNERABLE
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'
   OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**What is wrong:** the input is concatenated into the query, so it is parsed as part of the SQL *code*,
not treated as data. A single quote in the input ends the string literal and anything after it is
executed as SQL. This is exactly the slide pattern *Fixing SQL injection → ✗ input pasted into the query*.

### Why it works (the mechanism)

The classic teaching payload `' OR 1=1--` turns the `WHERE email = '...'` test into a condition that is
always true, and the `--` comments out the password check — so the query returns the first user (the
admin) and the server logs you in. In the search route, a `UNION SELECT` appended to the criteria lets
the single result set carry rows from *another* table (the users table), which is how the credential-dump
challenge works. In both cases the database did nothing wrong: it faithfully ran the code it was handed.
The flaw is that the application let user text *become* that code.

### Confirming it safely

You don't need a full exploit to prove the bug in a lab. Submit a lone `'` in the login email field and
watch the `login` request in DevTools → Network: the response contains a raw `SQLITE_ERROR` with the
whole query. A syntax error caused by one quote is proof the input reaches the SQL engine unescaped.
(The leaked query text is a second defect — verbose DB errors should never reach the client.)

### The fix — parameterised / bound queries

Send the query and the data **separately** so the driver binds input as a value. Juice Shop's own
corrected version (`data/static/codefixes/loginAdminChallenge_4_correct.ts`):

```typescript
// routes/login.ts  — FIXED (bind parameters)
models.sequelize.query(
  `SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
  { bind: [req.body.email, security.hash(req.body.password)], model: UserModel, plain: true })
```

And the search route (`unionSqlInjectionChallenge_2_correct.ts`) uses named replacements:

```typescript
// routes/search.ts  — FIXED (named replacement)
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%:criteria%'
   OR description LIKE '%:criteria%') AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { criteria } })
```

Now `' OR 1=1--` is searched for as a literal string; it can't change the query. The slide shows the
same idea in PHP PDO (`prepare`/`execute`) and Node `pg` (`$1`).

### How to avoid it in general

| Practice | Why |
| --- | --- |
| Always parameterise / use prepared statements | Query and data travel on separate channels — input can never become SQL |
| Prefer ORM query builders; avoid raw helpers | `sequelize.query`, `whereRaw`, `$queryRawUnsafe` reintroduce the risk |
| Allowlist identifiers | Table/column names can't be bound — pick them from a fixed list |
| Least privilege DB account | App user has no `DROP`/admin rights, so a slip does less damage |
| Don't leak DB errors | Return a generic message; log details server-side |

---

## Demo 2 — CSRF (OWASP A06 Insecure Design)

**Teaching goal:** show that a state-changing endpoint which trusts the session cookie alone can be
driven from another origin, and add a token + `SameSite` so it can't. Juice Shop challenge: *CSRF*
(change a user's name from another origin).

### The vulnerable code

`POST /profile` updates the username using only the `token` cookie to identify the user — there is no
anti-CSRF token and no `Origin` check that would *reject* the request:

```typescript
// routes/updateUserProfile.ts  — VULNERABLE
return async (req, res, next) => {
  const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
  if (!loggedInUser) { next(new Error('Blocked illegal activity')); return }

  const user = await UserModel.findByPk(loggedInUser.data.id)
  // ...note: the Origin is only READ to score the challenge, not to block:
  const savedUser = await user.update({ username: req.body.username })
  // ...issues a new token and redirects to /profile
}
```

The cookie is also set without an explicit `SameSite` attribute (frontend `login.component.ts` calls
`cookieService.put('token', ...)`), so the browser will attach it to cross-site requests.

**What is wrong:** the server cannot tell a real form submit from one triggered by another site. As the
slide *Cross-Site Request Forgery* puts it: the Same-Origin Policy allows cross-site form submits, and
the browser adds the cookie by itself.

### Why it works (the mechanism)

A page on the attacker origin (`http://127.0.0.1:8000`) contains a hidden form whose `action` is
`http://localhost:3000/profile` and which auto-submits. Because the victim is logged in, the browser
attaches the Juice Shop `token` cookie to that cross-site POST, and the server — seeing a valid cookie —
performs the username change. The attacker never reads the response (CORS blocks that); they only need
the *write* to happen. This is the slide's four-step chain: victim logged in → victim opens evil page →
hidden form auto-submits → browser attaches the cookie.

Note the slide caveat and the code's own `FIXME`: modern Chrome/Firefox default cookies to
`SameSite=Lax`, which already blocks this particular cross-site POST — which is *why* setting `SameSite`
explicitly is a real defence, and why relying on defaults is fragile.

### The fix — token + SameSite + Origin check

Three layers, matching the slide *Fixing CSRF*:

**1. Explicit SameSite on the session cookie** (server-side, where the token is set):

```typescript
res.cookie('token', updatedToken, { sameSite: 'lax', httpOnly: true, secure: true })
```

**2. Anti-CSRF token** — issue a random per-session token, embed it in the real form, and require it on
every state change:

```typescript
// pseudo-Express with csrf middleware
import csrf from 'csurf'
const csrfProtection = csrf({ cookie: false })
app.post('/profile', csrfProtection, updateUserProfile())
// the real profile form sends <input type="hidden" name="_csrf" value="...">
// a forged form on evil.com cannot read or guess this value -> 403
```

**3. Reject cross-origin state changes** — turn Juice Shop's read-only `Origin` check into an actual guard:

```typescript
const allowed = 'http://localhost:3000'
if (req.headers.origin && req.headers.origin !== allowed) {
  return res.status(403).send('Cross-origin request rejected')
}
```

### How to avoid it in general

| Practice | Why |
| --- | --- |
| `SameSite=Lax` or `Strict`, set explicitly | Browser won't attach the cookie to cross-site POSTs; don't rely on defaults |
| Random anti-CSRF token on every state change | Attacker's forged form can't read or guess it |
| Check the `Origin`/`Referer` header and reject mismatches | Stops forged POST/PUT/DELETE at the server |
| No state changes on `GET` | GET only reads; changes use POST/PUT/DELETE |
| Re-authenticate for sensitive actions | Password/email change, payments |
| Remember: **CORS is not a CSRF defence** | The forged request is still *sent* with the cookie; CORS only blocks *reading* the reply |

---

## Demo 3 — XSS (OWASP A05 Injection, browser side)

**Teaching goal:** show how a developer disabling the framework's built-in sanitiser turns a search box
into a script-execution sink, and that the fix is simply to *not* disable it. Juice Shop challenges:
*DOM XSS* and *Client-side XSS Protection*.

### The vulnerable code

Angular escapes interpolated values by default. Juice Shop deliberately opts out with
`bypassSecurityTrustHtml`, in `search-result.component.ts`:

```typescript
// frontend/src/app/search-result/search-result.component.ts  — VULNERABLE
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam) // from ?q=
// ...
tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
```

The template then renders it with `[innerHTML]`, which parses HTML:

```html
<!-- search-result.component.html -->
<span id="searchValue" [innerHTML]="searchValue"></span>
```

**What is wrong:** `bypassSecurityTrustHtml` tells Angular "trust this string, don't sanitise it", and
`[innerHTML]` then injects it as live markup. The search term came from the URL (`?q=`), so
attacker-controlled text is rendered as HTML. This is the DOM branch of the slide *Fixing XSS*
(`el.innerHTML = ...` ✗).

### Why it works (the mechanism)

Because the value is injected as HTML rather than text, markup in the search term becomes real DOM. The
*DOM XSS* challenge uses an `<iframe src="javascript:...">` payload precisely because a bare `<script>`
inserted via `innerHTML` doesn't execute, but an iframe's `javascript:` URL does. The injected code
runs **inside Juice Shop's own origin**, so — as the slide *Cross-site scripting* notes — the
Same-Origin Policy doesn't stop it: it can read the DOM, call the API as you, and read non-`HttpOnly`
cookies or the `token` in `localStorage`. That is the bridge to the session-hijacking slide
(`XSS: injected script sends document.cookie to the attacker`).

**Three XSS variants in Juice Shop, matching the slide's taxonomy:**

| Variant | Where | Source |
| --- | --- | --- |
| DOM XSS | search field `?q=` rendered via `bypassSecurityTrustHtml` | never leaves the browser |
| Reflected XSS | search results echo the term back from the server | request → response |
| Stored XSS | product/user fields sanitised with the weak `sanitizeLegacy` regex | saved in DB, served to others |

### The fix — don't bypass the sanitiser

Juice Shop's official fix (`localXssChallenge_2_correct.ts`) just assigns the plain string and lets
Angular escape it:

```typescript
// FIXED — no bypass; Angular treats it as text
this.searchValue = queryParam
```

The repo's own explanation: *"Removing the bypass of sanitization entirely is the best way to fix this —
a text search is not expected to contain HTML."* For the DOM sink itself, the slide's rule is
`el.textContent` instead of `el.innerHTML`. When you genuinely must render user HTML (rich comments),
sanitise it with a vetted library like DOMPurify — never a homegrown regex (see Demo 4 for why Juice
Shop's `sanitizeLegacy = input.replace(/<(?:\w+)\W+?[\w]/gi, '')` is trivially bypassed).

### How to avoid it in general

| Practice | Why |
| --- | --- |
| Let the framework escape (Angular, React, Vue, Blade, EJS `<%= %>`) | They encode by default; the bug only appears when you opt out |
| Avoid `innerHTML`, `bypassSecurityTrust*`, `dangerouslySetInnerHTML`, `v-html` | These are the sinks that turn text into markup |
| Encode for the context | HTML body, attributes, JS and URLs each need their own escaping |
| Sanitise rich HTML with DOMPurify, not regex | One missed case defeats a homegrown filter |
| `HttpOnly` cookies + don't keep tokens in `localStorage` | Injected script can't read an `HttpOnly` cookie |
| Add a strict CSP as a second layer | CSP blocks injected script even if encoding misses one spot |

---

## Demo 4 — CORS misconfiguration and the CSP header (OWASP A02 Security Misconfiguration)

**Teaching goal:** two header bugs on the server. First, a wildcard CORS policy that opts every origin
in. Second, a Content-Security-Policy built from user input, which both *weakens* XSS defence and lets
an attacker inject their own script source. Juice Shop challenge: *CSP Bypass* (needs `safetyMode` off,
i.e. run from source or with the Docker env flag from Setup).

### Bug A — wildcard CORS

`server.ts` relaxes the Same-Origin Policy for everyone:

```typescript
// server.ts  — VULNERABLE
/* Bludgeon solution for possible CORS problems: Allow everything! */
app.options('*', cors())
app.use(cors())        // default = Access-Control-Allow-Origin: *
```

**What is wrong:** `cors()` with no options reflects a wildcard, so any website's JavaScript may read
responses from endpoints that aren't origin-checked. The slide *CORS* calls out the dangerous
combination: reflecting any `Origin` together with `Access-Control-Allow-Credentials: true`. Remember
the slide's key point — CORS is enforced by the browser on *reads*; it never stops the request being
sent and never protects the server, so it is not a substitute for auth.

**The fix — allowlist specific origins:**

```typescript
// server.ts  — FIXED
const allowedOrigins = ['http://localhost:3000']
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || allowedOrigins.includes(origin)),
  credentials: true   // only safe BECAUSE origin is an allowlist, never with '*'
}))
```

### Bug B — CSP built from user input

`routes/userProfile.ts` constructs the CSP header by interpolating the user's profile-image URL, and
allows `unsafe-eval`:

```typescript
// routes/userProfile.ts  — VULNERABLE
const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`
res.set({ 'Content-Security-Policy': CSP })
res.send(fn(user))   // fn() is a compiled Pug template with the username injected
```

**What is wrong — two problems compounding, which is the whole point of this challenge:**

1. **CSP injection.** `profileImage` is attacker-controlled (set via *profile image URL upload*). By
   storing a URL that contains `; script-src ... 'unsafe-inline'`, the attacker appends their own
   directive to the policy, re-enabling inline script.
2. **Weak homegrown sanitiser.** The legacy profile page builds HTML by string-replacing `_username_`,
   and the username passes through `sanitizeLegacy`:

```typescript
// lib/insecurity.ts
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
```

That regex strips *some* tags but is easily bypassed, so a crafted `<script>` survives into the page.
Together: the weak sanitiser lets the script tag through, and the injected CSP directive lets it run. A
strict CSP would have stopped step 2 even though step 1 slipped — exactly the slide's *defence in depth*
argument.

**The fix — a static, strict CSP that never contains user input:**

```typescript
// FIXED — fixed policy, no interpolation, no unsafe-*
res.set({
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'"
})
```

Better still, set it once for the whole app with Helmet rather than per-route strings:

```typescript
// server.ts
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],   // add a per-response nonce for inline scripts
    objectSrc: ["'none'"],
    baseUri: ["'none'"],
    frameAncestors: ["'none'"]
  }
}))
```

### CSP: what it does and doesn't do (from the slides)

- CSP **doesn't fix the bug** — it stops injected code from *running*. It is layer 2; output encoding
  (Demo 3) is layer 1.
- Prefer a **strict CSP** (`'nonce-{random}' 'strict-dynamic'`) over an allowlist CSP, which attackers
  bypass via an allowed-but-abusable host.
- Never use `'unsafe-inline'` or `'unsafe-eval'` — they let injected inline script run.
- Roll out safely: `Content-Security-Policy-Report-Only` → collect violations → fix inline handlers → enforce.
- CSP **doesn't stop injected HTML** such as a fake login form — keep encoding output; consider Trusted
  Types (`require-trusted-types-for 'script'`) against DOM XSS sinks.

### Security headers cheat sheet (from the slide)

| Header | Example value | Protects against |
| --- | --- | --- |
| `Content-Security-Policy` | `script-src 'nonce-…' 'strict-dynamic'; object-src 'none'` | XSS, injected scripts |
| `Access-Control-Allow-Origin` | `https://app.example.com` (narrow) | Unwanted cross-origin reads |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HTTP downgrade, cookie sniffing |
| `X-Content-Type-Options` | `nosniff` | Files run as the wrong type |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Leaking full URLs |
| `frame-ancestors` | `'none'` | Clickjacking |

---

## Summary cheat sheet

One row per demo: the defect in the code, the root cause, the fix, and the slide/OWASP mapping.

| Vulnerability | Root cause (what's wrong) | The fix | Prevent it | OWASP |
| --- | --- | --- | --- | --- |
| **SQL injection** | User input concatenated into the SQL string — data becomes code | Bind/parameterise: `$1` bind params, named `:replacements` | Always parameterise; avoid raw query helpers; least-privilege DB user; don't leak DB errors | A05 Injection |
| **CSRF** | `POST /profile` trusts the session cookie alone; no token, no explicit `SameSite` | Anti-CSRF token + `SameSite=Lax` + reject cross-origin `Origin` | Token on every state change; explicit `SameSite`; no writes on `GET`; CORS is *not* a defence | A06 Insecure Design |
| **XSS** | `bypassSecurityTrustHtml(queryParam)` + `[innerHTML]` — escaping disabled | Remove the bypass; let the framework escape; `textContent` not `innerHTML` | Framework escaping; avoid HTML sinks; DOMPurify for rich HTML; `HttpOnly`; strict CSP | A05 Injection |
| **CORS misconfig** | `app.use(cors())` — wildcard `Access-Control-Allow-Origin: *` | Allowlist specific origins; `credentials:true` only with an allowlist | Narrow CORS; never `*` with credentials; CORS doesn't replace authorization | A02 Security Misconfig |
| **CSP weakness** | CSP string built from user input + `unsafe-eval`; weak regex sanitiser | Static strict CSP via Helmet; no user input in the header; no `unsafe-*` | Strict CSP (`nonce` + `strict-dynamic`); Report-Only rollout; CSP is layer 2 | A02 Security Misconfig |

### The two ideas behind all five

1. **Never let data become code.** SQLi (data becomes SQL) and XSS (data becomes HTML/JS) are the same
   bug in two languages. The fix is always *separation*: bind parameters, or let the template engine encode.
2. **The browser will send credentials for you.** CSRF and the CORS/CSP bugs are about trusting the
   wrong signal. A cookie proves the browser sent the request, not that the user intended it; a wildcard
   header trusts every origin. Defences add an intention check (token, `SameSite`, `Origin` allowlist)
   and a second layer (strict CSP) for when layer 1 misses.

### Verify as you go

Open the Score Board (`http://localhost:3000/#/score-board`) — each challenge flips green when solved,
and the *coding challenge* button on each shows the vulnerable snippet beside the official fix, so you
can diff your reasoning against the maintainers'.
