# SpotiVibe 1 - Writeup (Web Misc)

## Challenge Info
- Category: Web Misc
- Title: SpotiVibe 1
- Target: `http://chall.k1nd4sus.it:30502`

## Summary
The app has an admin review bot that visits reported songs and sets a `flag` cookie before opening the song page.

The bug is in Spotify URL validation:
- It checks `hostname == open.spotify.com`
- It checks `path.startswith("/embed/")`
- It does **not** check URL scheme (`http/https` only)

Because of this, a `javascript:` URL can pass validation if crafted as:
- `javascript://open.spotify.com/embed/...`

Then the song page places it directly into:
```html
<iframe src="{{ song.spotify_url }}">
```

So when admin bot loads the page, JavaScript executes and can read `document.cookie`, including:
- `flag=KSUS{...}`

## Root Cause
In `is_valid_spotify_url(url)`:
- `parsed.hostname` is trusted
- `parsed.path` is trusted
- no scheme allowlist is enforced

This allows script URLs disguised with a fake authority/path structure.

## Exploit Strategy
Direct exfiltration to external webhook is not necessary.

Instead, payload does this inside bot browser:
1. `fetch('/logout')`
2. Login as attacker account
3. `POST /add_song` with:
   - `title = document.cookie`
   - valid spotify URL in `spotify_url`

Now the stolen cookie string (containing `flag=...`) is stored as a song title in our own account.

After reporting the malicious song, bot visits it and runs payload.  
We then poll `/dashboard` and read the new song title to extract the flag.

## Flag
`KSUS{4b4eba6646f7903fd437d6fbf1b5783d}`

## Solver
File: `solver.py`

### Run
```bash
source /home/nata/ctf_env/bin/activate
python3 solver.py
```

Expected output:
```text
<FLAG>KSUS{...}</FLAG>
```

## Notes
- The exploit is reliable because bot explicitly sets cookie:
  - name: `flag`
  - path: `/`
  - `httpOnly: False`
- If network timing is slow, run solver again (it already includes polling/retry logic).
