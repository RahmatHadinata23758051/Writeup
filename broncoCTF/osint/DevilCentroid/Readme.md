# Devil's Centroid — Writeup

## Challenge Recap
Three "possessed" contacts each dropped one cryptic clue pointing to a location. The task: identify each city, pull its coordinates from Wikipedia, average them (find the centroid of the triangle), and format as a flag.

```
1. "I'm at a place called Devil's Isle"
2. "I found myself near a haunted sentry box"
3. "Nunca podrán dominarla La buena música no engaña"
```

---

## Solving Clue 1 — "Devil's Isle"

Searched for real-world places historically called "Devil's Isle." Turns out this is a well-documented nickname for **Bermuda**:

> Spanish explorer Juan de Bermúdez sighted the islands in 1505. Sailors, spooked by the eerie shrieks of the native cahow bird and the treacherous surrounding reefs, dubbed it the *"Isle of Devils"* — a name that stuck for over a century before English settlement in 1609.

**→ Location: Bermuda**

Wikipedia infobox (capital, Hamilton):
```
32°17′46″N 64°46′58″W  →  32.29611, -64.78278
```

---

## Solving Clue 2 — "haunted sentry box"

A direct hit on search: **La Garita del Diablo** ("The Devil's Sentry Box") — a real, famous haunted watchtower built in 1634 at **Castillo San Cristóbal, Old San Juan, Puerto Rico**.

The legend: a soldier named Sánchez vanished from this isolated post one night, leaving only his rifle and uniform behind. Locals blamed the devil (the more romantic version says he eloped with his lover Diana). It's one of the most famous ghost stories in the Caribbean.

**→ Location: San Juan, Puerto Rico**

Wikipedia infobox:
```
18°24′23″N 66°3′50″W  →  18.40639, -66.06389
```

---

## Solving Clue 3 — the Spanish lyrics

This was the trickiest one — a direct search for the phrase in quotes returned nothing useful at first (mostly hitting the unrelated *Spirit* soundtrack song "Nadie Me Va A Dominar"). Widening the search without accents cracked it:

```
"Nunca podran dominarla / La buena musica no engana"
```

This is a lyric from the song **"Miami 666"** by **Señor Loop**. The song title itself gave away the location directly.

**→ Location: Miami, Florida**

Wikipedia infobox:
```
25°46′27″N 80°11′37″W  →  25.77417, -80.19361
```

---

## Computing the Centroid

Averaging the three coordinate sets:

**Latitude:**
```
(32.29611 + 18.40639 + 25.77417) / 3 = 76.47667 / 3 = 25.49222
```

**Longitude:**
```
(-64.78278 + -66.06389 + -80.19361) / 3 = -211.04028 / 3 = -70.34676
```

**Centroid ≈ 25.49222°N, 70.34676°W**

---

## Formatting the Flag

Per the challenge instructions: *"Rounded down to the nearest whole number after all of the calculations."*

Truncating the decimals:
- Latitude: `25.49` → `25N`
- Longitude: `70.35` → `70W`

## 🚩 Flag

```
bronco{25N,70W}
```

---

### TL;DR of the "Devil's ___" theme

| Clue | Real-world reference | City |
|---|---|---|
| Devil's Isle | Historic nickname for Bermuda | Hamilton, Bermuda |
| Haunted sentry box | La Garita del Diablo | San Juan, Puerto Rico |
| Song lyric | "Miami 666" – Señor Loop | Miami, FL |

All three locations tie neatly into the "devil" motif of the puzzle title, which was a nice confirmation signal while solving.
