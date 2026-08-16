#!/usr/bin/env python3
# Rune Decryptor helper/solver - solvernat9 balanced accuracy build
# Dependency-free: stdlib only. It connects to the given SSL service, solves
# monoalphabetic-substitution paragraphs with character n-gram hillclimbing,
# submits up to 5 candidates per round, and stops when the flag appears.

import argparse
import gc
import base64
import hashlib
import itertools
import math
import random
import re
import socket
import ssl
import string
import subprocess
import shlex
import sys
import time
from collections import Counter

HOST_DEFAULT = "rune-decryptor.chal.uiuc.tf"
PORT_DEFAULT = 1337
FLAG_RE = re.compile(r"uiuctf\{[^}\n]+\}")
RUNE_RE = re.compile(r"[\u16a0-\u16ff]")

# Small built-in language material. This is not a challenge writeup/source lookup;
# it is only a local language model for classical-substitution cryptanalysis.
CORPORA = {
"en": """
the of and to in a is that was he for it with as his on be at by i this had not are but from or have an they which one you were her all she there would their we him been has when who will no more if out so said what up its about into than them can only other new some could time these two may then do first any my now such like our over man me even most made after also did many before must through back years where much your way well down should because each just those people mr how too little state good very make world still own see men work long get here between both life being under never day same another know while last might us great old year come since against go came right used take three woman every himself looked place thought house found hand eyes going asked answer tell told felt words children father mother nothing night left seemed stood turned yes young again mind enough almost seen far let once head few room door heart voice morning moment
alice beatrice chapter friend monsieur madame sir miss london england carriage cab street house room door window garden letter
""",
"nl": """
de een en van het in is dat te die zijn niet op aan met als voor er maar om hij zij wij u ik was naar hebben worden deze door over ook uit bij nog kan dan zal heeft geen meer moet veel waar zo haar hem hun ons mijn jouw zich tot onder boven achter tegen tussen omdat terwijl wanneer hoe wat wie daar hier alles niets goed groot klein nieuwe oude eerste laatste mensen man vrouw kind dag nacht tijd jaar huis stad land water wereld leven werk woord plaats naam weg hoofd hand oog stem hart vader moeder vriend kwam ging zag hoorde vroeg antwoordde zei dacht stond bleef maakte nam gaf liet vond hield wilde kon zou binnen buiten samen alleen opnieuw misschien reeds altijd plotseling eindelijk juist toen nu later vroeger zeer geheel lange korte donkere lichte witte zwarte roode blauwe groene sterke zwakke hooge lage groote kleine den der des eenen zijne hare mijne oude spelling mensch menschen oogen waren kwamen gingen hadden deden beatrice politiedienaar lagerhuis cab voerman shilling straten verlichte donkere ingang zitting bijwonen glimlachte stapte dwarrelde kwartier betaalde bedankte trad verlegen midden beelden marmeren vloeren gewelfde zolderingen gedrang waarvoor
""",
"de": """
der die und in den von zu das mit sich des auf für ist im dem nicht ein eine als auch es an werden aus er hat dass sie nach wird bei einer um am sind noch wie einem über einen so zum war haben nur oder aber vor zur bis mehr durch man sein wurde sei immer alle diese dieser ihr ihre ihrer wieder wir hatte seine wenn können kann gegen vom schon da unter sehr dann jetzt doch ihm mich uns viel herr frau kind haus hand augen kopf herz leben welt tag nacht zeit jahr stadt land wasser weg wort stimme vater mutter freund sagte fragte antwortete ging kam stand blieb sah hörte dachte machte nahm gab wollte konnte sollte musste kein guter alter neuer erste letzte lange kurze kleine grosse mensch menschen
""",
"fr": """
le de un et à être en avoir que pour dans ce il qui ne sur se pas plus pouvoir par je avec tout faire son mettre autre on mais nous comme ou si leur y dire elle devoir avant deux même prendre aussi celui donner bien où fois vous encore nouveau aller cela entre premier vouloir déjà grand mon me moins aucun lui temps très savoir falloir voir quelque sans raison notre dont non an monde jour monsieur madame homme femme enfant maison main yeux coeur vie nuit voix porte chambre rue ville pays père mère ami avait était sont furent dit demanda répondit alla vint resta regarda pensa trouvait voulait pouvait
""",
"es": """
el de que y a en un ser se no haber por con su para como estar tener le lo todo pero más hacer o poder decir este ir otro ese si me ya ver porque dar cuando él muy sin vez mucho saber qué sobre mi alguno mismo yo también hasta año dos querer entre así primero desde grande eso ni nos llegar pasar tiempo ella sí día uno bien poco deber entonces poner cosa tanto hombre mujer niño casa mano ojos corazón vida noche voz puerta cuarto calle ciudad país padre madre amigo dijo preguntó respondió fue vino estaba pensó quería podía
""",
"it": """
di e il la che in a un per non una essere si con da come più avere questo io ma fare lui dire potere se andare vedere dare sapere mio tutto suo anche altro dovere molto quando volere bene solo uomo donna bambino casa mano occhi cuore vita notte voce porta camera strada città paese padre madre amico tempo giorno anno mondo grande piccolo vecchio nuovo primo ultimo disse domandò rispose venne andò stava pensò voleva poteva aveva era sono erano
""",
"la": """
et in est non ad cum quod qui quae quo de ut per se sed esse ex suus hic ille ego tu nos vos ab aut etiam enim autem si iam neque atque nam omnis res homo deus dies nox manus oculus cor vita mors domus urbs terra mare pater mater filius amicus rex populus verbum tempus magnus parvus bonus malus primus alter multus venit vidit dixit fecit habuit erat sunt fuit esse potest debet voluit
""",
"sv": """
och det att i en jag hon som han på den med var sig för så till är men ett om hade de av icke mig du henne då sin nu har inte hans honom skulle hennes där min man ej vid kunde något från ut när efter upp vi dem vara vad över mer här genom kan än sedan mycket även bara komma se få säga under eller allt alla blev bli finns ha göra går kom gick stod såg hörde frågade svarade tänkte ville kunde huset hand ögon hjärta liv natt röst dörr rum gata stad land far mor vän barn kvinna människa gamla nya första sista
""",
"ru": """
и в не на я быть что он с а по это она этот к но они мы как из у который то за свой что весь год от так о для ты же все тот мочь вы человек такой его сказать только или еще бы себе один как уже до время если сам когда другой вот говорить наш мой знать стать при чтобы дело жизнь кто первый очень два день ее новый рука даже во со раз где там под можно ну какой после их работа без самый потом надо хотеть ли слово идти большой должен место иметь ничто видеть теперь тоже стоять думать спросить ответить дом ночь глаз сердце отец мать друг женщина ребенок
""",
"grc": """
και ο η το των τον την τα εις εν ουκ ου μη δε γαρ μεν του της τοις ως επι προς απο εκ δια κατα μετα περι υπερ υπο αν ει εστι ην είναι λεγει λογος ανθρωπος θεος πολεμος ψυχη σωμα γη θαλασσα ημερα νυξ πατηρ μητηρ φιλος πολις βασιλευς πολλος μεγας μικρος αγαθος κακος πρωτος αλλος ουτος εκεινος παντα χρονου χειρ οφθαλμος καρδια βιος θανατος ελεγε ειπεν ηλθεν ειδεν εποιησεν ελαβεν εδωκεν
""",
}

ALPHABETS = {
    "en": "abcdefghijklmnopqrstuvwxyz",
    "nl": "abcdefghijklmnopqrstuvwxyz",
    "de": "abcdefghijklmnopqrstuvwxyzäöüß",
    "fr": "abcdefghijklmnopqrstuvwxyzàâæçéèêëîïôœùûüÿ",
    "es": "abcdefghijklmnopqrstuvwxyzáéíñóúü",
    "it": "abcdefghijklmnopqrstuvwxyzàèéìíîòóùú",
    "la": "abcdefghijklmnopqrstuvwxyz",
    "sv": "abcdefghijklmnopqrstuvwxyzåäö",
    "ru": "абвгдежзийклмнопрстуфхцчшщъыьэюяё",
    "grc": "αβγδεζηθικλμνξοπρστυφχψως",
}

FREQ_ORDER = {
    "en": "etaoinshrdlucmfwypvbgkqjxz",
    "nl": "enatirodslgvhkmupbjcwzfxyq",
    "de": "enisratdhulgocmwbkfzüpäöjvyxqß",
    "fr": "esaitnrulodcmpvqfbghjxyzêèàçéùâîôûëïüœæÿ",
    "es": "eaosrnidlctumpbgvyqhfzjñxkáéíóúü",
    "it": "eaionlrtscdupmvgfhbqzàèéìòùxykwj",
    "la": "ietaonsrumlcqdpbgfhvxyzkj",
    "sv": "enartisldomkgvfhupäcbåöyjxqzw",
    "ru": "оеаинтсрвлкмдпуяызьгзбчйхжюшцщэфъё",
    "grc": "αιονεστρλκυηπμδγθχβφωξζψς",
}


def repeat_corpus(lang, corpus):
    # Put common material into a pseudo-corpus with lots of boundaries.
    words = re.findall(r"\w+", corpus.lower(), flags=re.UNICODE)
    common = " ".join(words)
    return (" " + common + " ") * 300

class NGramModel:
    def __init__(self, lang):
        self.lang = lang
        self.alpha = ALPHABETS[lang]
        self.letters = self.alpha + " "
        self.space = len(self.alpha)
        self.L = len(self.letters)
        text = repeat_corpus(lang, CORPORA[lang])
        # normalize to model alphabet
        allowed = set(self.alpha)
        norm = []
        last_space = True
        for ch in text.lower():
            if ch in allowed:
                norm.append(ch); last_space = False
            else:
                if not last_space:
                    norm.append(" "); last_space = True
        s = "".join(norm)
        self.logs = {}
        self.floor = {}
        for n in (3, 4):
            counts = Counter()
            for i in range(max(0, len(s) - n + 1)):
                code = 0
                ok = True
                for ch in s[i:i+n]:
                    try:
                        v = self.letters.index(ch)
                    except ValueError:
                        ok = False; break
                    code = code * self.L + v
                if ok:
                    counts[code] += 1
            total = sum(counts.values()) or 1
            denom = total + 0.01 * (self.L ** n)
            self.logs[n] = {k: math.log((v + 0.01) / denom) for k, v in counts.items()}
            self.floor[n] = math.log(0.01 / denom)

    def normalize_stream(self, ciphertext, syms):
        sym_index = {s: i for i, s in enumerate(syms)}
        stream = []
        for ch in ciphertext:
            if ch in sym_index:
                stream.append(sym_index[ch])
            else:
                stream.append(-1)
        return stream

    def score(self, stream, key):
        # key maps cipher-symbol index -> plaintext alphabet index. Extra dummy entries are ignored.
        L = self.L
        space = self.space
        logs4 = self.logs[4]; floor4 = self.floor[4]
        logs3 = self.logs[3]; floor3 = self.floor[3]
        a0 = a1 = a2 = None
        sc = 0.0
        for x in stream:
            val = space if x < 0 else key[x]
            if a0 is not None and a1 is not None:
                code3 = (a0 * L + a1) * L + val
                sc += 2.0 * logs3.get(code3, floor3)
            if a0 is not None and a1 is not None and a2 is not None:
                code4 = ((a2 * L + a0) * L + a1) * L + val
                sc += 10.0 * logs4.get(code4, floor4)
            a2, a0, a1 = a0, a1, val
        return sc

    def decrypt(self, ciphertext, syms, key):
        sym_index = {s: i for i, s in enumerate(syms)}
        out = []
        for ch in ciphertext:
            if ch in sym_index:
                out.append(self.alpha[key[sym_index[ch]]])
            else:
                out.append(ch)
        return "".join(out)


def extract_ciphertext(text):
    """Return the encrypted paragraph from the latest round screen.

    The remote sometimes colors the rune paragraph with ANSI escape sequences.
    If those bytes are kept, the submitted plaintext accidentally contains
    extra alphabetic chars such as the final `m` from `\x1b[38;5;179m`,
    and the service rejects it with `Submission has N letters, expected M`.
    """
    # Strip terminal color/control sequences before extracting/submitting text.
    text = _clean_ansi(text)
    # Work only after the last round marker, if present.
    m = list(re.finditer(r"Round\s+\d+/\d+", text))
    tail = text[m[-1].start():] if m else text
    lines = []
    for raw in tail.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "█" in line:
            continue
        if RUNE_RE.search(line):
            lines.append(line)
    # Service text is paragraph-like; line wrapping should be spaces.
    return " ".join(lines).strip()




def letter_count_for_service(s):
    """Count letters the same way the service appears to validate length.

    This is only for local sanity checks before sending candidates. It catches
    leaked ANSI escape sequences and other accidental alphabetic junk.
    """
    return sum(ch.isalpha() for ch in _clean_ansi(s))


def clean_candidate_for_submit(s):
    """Final cleanup before sending a plaintext candidate to the service."""
    return _clean_ansi(s).strip()

def make_initial_key(model, syms, ciphertext, mode):
    N = len(syms)
    A = len(model.alpha)
    freq = Counter(ch for ch in ciphertext if ch in syms)
    sym_order = [syms.index(s) for s, _ in freq.most_common()]
    freq_chars = [c for c in FREQ_ORDER[model.lang] if c in model.alpha]
    freq_idx = []
    for c in freq_chars:
        i = model.alpha.index(c)
        if i not in freq_idx:
            freq_idx.append(i)
    freq_idx += [i for i in range(A) if i not in freq_idx]

    key = [None] * A
    if mode == "random":
        perm = list(range(A)); random.shuffle(perm)
        return perm
    # Frequency-seeded with randomized depth.
    k = min(N, random.randint(6, min(max(7, N), max(7, min(18, A)))))
    used = set()
    for j, si in enumerate(sym_order[:k]):
        key[si] = freq_idx[j]
        used.add(freq_idx[j])
    rest = [i for i in range(A) if i not in used]
    random.shuffle(rest)
    for i in range(A):
        if key[i] is None:
            key[i] = rest.pop()
    return key


def solve_language(model, ciphertext, restarts=18, steps=9000, keep=12, seed=None, verbose=False):
    if seed is not None:
        random.seed(seed)
    syms = sorted(set(RUNE_RE.findall(ciphertext)))
    N = len(syms)
    A = len(model.alpha)
    if N > A:
        return []
    stream = model.normalize_stream(ciphertext, syms)
    best = []
    seen = set()
    positions = list(range(A))
    for r in range(restarts):
        key = make_initial_key(model, syms, ciphertext, "random" if r % 5 == 0 else "freq")
        cur = model.score(stream, key)
        T = 85.0
        local_best = (cur, key[:])
        for st in range(steps):
            a, b = random.sample(positions, 2)
            key[a], key[b] = key[b], key[a]
            sc = model.score(stream, key)
            if sc > cur or random.random() < math.exp(min(0.0, (sc - cur) / T)):
                cur = sc
                if sc > local_best[0]:
                    local_best = (sc, key[:])
            else:
                key[a], key[b] = key[b], key[a]
            T *= 0.99955
            if T < 0.25:
                T = 0.25
        txt = model.decrypt(ciphertext, syms, local_best[1])
        if txt not in seen:
            seen.add(txt)
            # length-normalized score for cross-language candidate sorting.
            best.append((local_best[0] / max(1, len(ciphertext)), model.lang, txt))
            best.sort(reverse=True, key=lambda x: x[0])
            best = best[:keep]
            if verbose:
                print(f"[{model.lang}] restart {r:02d} score={best[0][0]:.2f} {best[0][2][:100]!r}", file=sys.stderr)
    return best


def candidate_pool(ciphertext, args, models):
    # Quick pass over every viable language, then deeper pass over top languages.
    # Progress is printed because this stage can look like a hang: all work here is local CPU work.
    all_cands = []
    print(f"[+] local solve mulai: quick={args.quick_restarts}x{args.quick_steps}, deep={args.deep_restarts}x{args.deep_steps}", flush=True)
    for idx, (lang, model) in enumerate(models.items(), 1):
        print(f"[+] quick scan {idx}/{len(models)} lang={lang}", flush=True)
        cands = solve_language(model, ciphertext, restarts=args.quick_restarts, steps=args.quick_steps,
                               keep=4, verbose=args.verbose)
        all_cands.extend(cands)
        if cands:
            best = max(cands, key=lambda x: x[0])
            print(f"    best {lang}: score={best[0]:.2f} sample={best[2][:80]!r}", flush=True)
    all_cands.sort(reverse=True, key=lambda x: x[0])
    top_langs = []
    for _, lang, _ in all_cands:
        if lang not in top_langs:
            top_langs.append(lang)
        if len(top_langs) >= args.deep_langs:
            break
    print(f"[+] deep scan langs={','.join(top_langs) if top_langs else '-'}", flush=True)
    for idx, lang in enumerate(top_langs, 1):
        print(f"[+] deep scan {idx}/{len(top_langs)} lang={lang}", flush=True)
        cands = solve_language(models[lang], ciphertext, restarts=args.deep_restarts,
                               steps=args.deep_steps, keep=10, verbose=args.verbose)
        all_cands.extend(cands)
        if cands:
            best = max(cands, key=lambda x: x[0])
            print(f"    deep best {lang}: score={best[0]:.2f} sample={best[2][:120]!r}", flush=True)
    # Unique plaintext candidates. Keep top-ranked, but also keep per-language winners.
    uniq = {}
    for sc, lang, txt in all_cands:
        old = uniq.get(txt)
        if old is None or sc > old[0]:
            uniq[txt] = (sc, lang, txt)
    ranked = sorted(uniq.values(), reverse=True, key=lambda x: x[0])
    print(f"[+] kandidat siap: {len(ranked)}", flush=True)
    ranked = polish_candidate_pool(ciphertext, ranked, args, models)
    return ranked




ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _clean_ansi(text):
    return ANSI_RE.sub("", text or "")


# ---------------------------------------------------------------------------
# Optional stronger word model
# ---------------------------------------------------------------------------
# The char n-gram solver alone can land near the answer, e.g. 15/20 or 17/24
# correct symbol mappings.  The service needs an exact mapping, so solvernat6
# optionally installs/uses `wordfreq` as a generic multilingual word-frequency
# model and then polishes the best keys locally before spending remote attempts.
WF_ZIPF = None
WF_LANG_MAP = {
    "en": "en", "nl": "nl", "de": "de", "fr": "fr", "es": "es",
    "it": "it", "sv": "sv", "ru": "ru", "la": "la", "grc": "el",
}


def ensure_wordfreq(auto_install=True):
    global WF_ZIPF
    if WF_ZIPF is not None:
        return True
    try:
        from wordfreq import zipf_frequency
        WF_ZIPF = zipf_frequency
        print("[+] wordfreq aktif: rerank/polish pakai model kata multilingual", flush=True)
        return True
    except Exception:
        pass
    if not auto_install:
        print("[!] wordfreq belum ada; lanjut fallback n-gram saja", flush=True)
        return False
    print("[+] wordfreq belum ada, mencoba install otomatis: python3 -m pip install wordfreq", flush=True)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "wordfreq"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=240,
            check=False,
        )
        if proc.returncode != 0:
            print("[!] install wordfreq gagal; fallback n-gram saja", flush=True)
            if proc.stderr:
                print(proc.stderr[-800:], flush=True)
            return False
        from wordfreq import zipf_frequency
        WF_ZIPF = zipf_frequency
        print("[+] wordfreq berhasil diinstall dan aktif", flush=True)
        return True
    except Exception as e:
        print(f"[!] install/import wordfreq gagal: {e}; fallback n-gram saja", flush=True)
        return False


WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_WORD_SCORE_CACHE = {}


def wordfreq_text_bonus(lang, txt):
    """Normalized word-frequency bonus for a candidate plaintext.

    Positive for real words, heavy penalty for 4+ char gibberish.  This is not
    a challenge-specific corpus lookup; it only uses generic word frequency.
    """
    if WF_ZIPF is None:
        return 0.0
    wf_lang = WF_LANG_MAP.get(lang, lang)
    words = WORD_RE.findall(txt.lower())
    if not words:
        return -100.0
    total = 0.0
    denom = 0
    for w in words:
        # one-letter words are noisy across languages; give them tiny weight
        weight = min(8, max(1, len(w)))
        denom += weight
        key = (wf_lang, w)
        z = _WORD_SCORE_CACHE.get(key)
        if z is None:
            try:
                z = float(WF_ZIPF(w, wf_lang))
            except Exception:
                z = 0.0
            _WORD_SCORE_CACHE[key] = z
        if len(w) == 1:
            total += min(z, 4.0) * 0.2
        elif z <= 0.05:
            total -= 6.0 * weight
        elif z < 2.0:
            total += (z - 2.0) * 2.2 * weight
        else:
            total += z * weight
    return total / max(1, denom)


def key_from_plaintext(model, ciphertext, plaintext):
    """Reconstruct cipher-symbol -> plaintext-index key from a candidate text."""
    syms = sorted(set(RUNE_RE.findall(ciphertext)))
    sym_index = {s: i for i, s in enumerate(syms)}
    A = len(model.alpha)
    key = [-1] * A
    used = set()
    for c, p in zip(ciphertext, plaintext):
        if c in sym_index:
            pi = model.alpha.find(p.lower())
            if pi >= 0:
                key[sym_index[c]] = pi
                used.add(pi)
    rest = [i for i in range(A) if i not in used]
    random.shuffle(rest)
    for i in range(A):
        if key[i] < 0:
            key[i] = rest.pop() if rest else 0
    return key


def mapping_for_text(model, ciphertext, plaintext):
    """Tuple of active plaintext indices, one per rune symbol."""
    syms = sorted(set(RUNE_RE.findall(ciphertext)))
    sym_index = {s: i for i, s in enumerate(syms)}
    out = [-999] * len(syms)
    for c, p in zip(ciphertext, plaintext):
        if c in sym_index:
            pi = model.alpha.find(p.lower())
            if pi >= 0:
                out[sym_index[c]] = pi
    return tuple(out)


def mapping_overlap(a, b):
    n = min(len(a), len(b))
    return sum(1 for i in range(n) if a[i] == b[i] and a[i] >= 0)


def parse_feedback_count(screen):
    m = re.search(r"Incorrect\.\s+(\d+)\s*/\s*(\d+)\s+symbols mapped correctly", _clean_ansi(screen), re.I)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def hybrid_score_key(model, ciphertext, syms, stream, key, word_weight=18.0):
    txt = model.decrypt(ciphertext, syms, key)
    # char score is already normalized per char in candidate tuples; normalize here too
    char_part = model.score(stream, key) / max(1, len(ciphertext))
    return char_part + word_weight * wordfreq_text_bonus(model.lang, txt), txt


def polish_one_candidate(model, ciphertext, txt, steps=4500, restarts=3, word_weight=18.0):
    """Local hillclimb from a near-solution using char ngram + wordfreq score."""
    if WF_ZIPF is None:
        return []
    syms = sorted(set(RUNE_RE.findall(ciphertext)))
    stream = model.normalize_stream(ciphertext, syms)
    A = len(model.alpha)
    if len(syms) > A:
        return []
    out = []
    base = key_from_plaintext(model, ciphertext, txt)
    positions = list(range(A))
    for r in range(restarts):
        key = base[:]
        # tiny randomization on later restarts, but stay close to current candidate
        if r:
            for _ in range(min(3, max(1, len(syms)//8))):
                a, b = random.sample(positions, 2)
                key[a], key[b] = key[b], key[a]
        cur, cur_txt = hybrid_score_key(model, ciphertext, syms, stream, key, word_weight)
        best = (cur, key[:], cur_txt)
        T = 9.0
        for _ in range(steps):
            a, b = random.sample(positions, 2)
            key[a], key[b] = key[b], key[a]
            sc, cand_txt = hybrid_score_key(model, ciphertext, syms, stream, key, word_weight)
            if sc > cur or random.random() < math.exp(min(0.0, (sc - cur) / T)):
                cur = sc
                if sc > best[0]:
                    best = (sc, key[:], cand_txt)
            else:
                key[a], key[b] = key[b], key[a]
            T *= 0.9992
            if T < 0.15:
                T = 0.15
        out.append((best[0], model.lang, best[2]))
    return out


def polish_candidate_pool(ciphertext, ranked, args, models):
    if WF_ZIPF is None or not ranked:
        return ranked
    print(f"[+] polish wordfreq top={args.polish_top}, restarts={args.polish_restarts}, steps={args.polish_steps}", flush=True)
    extra = []
    seen_seed = set()
    for i, (sc, lang, txt) in enumerate(ranked[:args.polish_top], 1):
        if (lang, txt) in seen_seed or lang not in models:
            continue
        seen_seed.add((lang, txt))
        if i == 1 or args.verbose:
            print(f"    polish seed {i}/{min(args.polish_top, len(ranked))}: lang={lang} base={sc:.2f} sample={txt[:75]!r}", flush=True)
        extra.extend(polish_one_candidate(models[lang], ciphertext, txt,
                                          steps=args.polish_steps,
                                          restarts=args.polish_restarts,
                                          word_weight=args.word_weight))
    merged = {}
    for item in ranked + extra:
        sc, lang, txt = item
        # Re-rank all candidates with the same hybrid objective where possible.
        if WF_ZIPF is not None and lang in models:
            model = models[lang]
            syms = sorted(set(RUNE_RE.findall(ciphertext)))
            stream = model.normalize_stream(ciphertext, syms)
            key = key_from_plaintext(model, ciphertext, txt)
            sc2, txt2 = hybrid_score_key(model, ciphertext, syms, stream, key, args.word_weight)
            item = (sc2, lang, txt2)
        old = merged.get(item[2])
        if old is None or item[0] > old[0]:
            merged[item[2]] = item
    reranked = sorted(merged.values(), reverse=True, key=lambda x: x[0])
    print(f"[+] kandidat setelah polish: {len(reranked)}", flush=True)
    if reranked:
        print(f"    top polish: lang={reranked[0][1]} score={reranked[0][0]:.2f} sample={reranked[0][2][:120]!r}", flush=True)
    return reranked


def feedback_near_candidates(ciphertext, submitted_txt, lang, correct, total, args, models):
    """Generate candidates constrained by feedback overlap with a high-scoring miss.

    If the service says 17/24 symbols are correct, the real key differs in only
    7 active rune mappings.  This samples keys with exactly that overlap and
    scores them locally before the next remote attempt.
    """
    if lang not in models:
        return []
    model = models[lang]
    syms = sorted(set(RUNE_RE.findall(ciphertext)))
    N = len(syms)
    d = N - correct
    if d <= 0 or d > args.feedback_max_distance:
        return []
    print(f"[+] feedback expand: {correct}/{N} benar, cari neighbor distance={d}", flush=True)
    base = key_from_plaintext(model, ciphertext, submitted_txt)
    stream = model.normalize_stream(ciphertext, syms)
    active = list(range(N))
    A = len(model.alpha)
    extras = []

    # Deterministic repair for very-close misses.
    # 21/22 or 23/24 is common.  Random feedback search can waste attempts by
    # circling around the same typo (w/y, v/b, etc).  For distance 1 and 2,
    # enumerate the small neighborhood first, rank by char score, then apply
    # wordfreq only to the best few so memory stays controlled.
    if d == 1:
        for pos in active:
            oldv = base[pos]
            for val in range(A):
                if val == oldv:
                    continue
                key = base[:]
                key[pos] = val
                sc, txt = hybrid_score_key(model, ciphertext, syms, stream, key, args.word_weight)
                extras.append((sc, lang, txt))
    elif d == 2:
        rough = []
        for i, pos1 in enumerate(active):
            old1 = base[pos1]
            for pos2 in active[i+1:]:
                old2 = base[pos2]
                # common case: two active mappings are swapped
                key = base[:]
                key[pos1], key[pos2] = key[pos2], key[pos1]
                rough.append((model.score(stream, key) / max(1, len(ciphertext)), key[:]))
                # broader case: one/both letters should be another alphabet char
                for val1 in range(A):
                    if val1 == old1:
                        continue
                    for val2 in range(A):
                        if val2 == old2:
                            continue
                        key = base[:]
                        key[pos1] = val1
                        key[pos2] = val2
                        rough.append((model.score(stream, key) / max(1, len(ciphertext)), key[:]))
        rough.sort(reverse=True, key=lambda x: x[0])
        for _, key in rough[:max(400, args.feedback_keep * 30)]:
            sc, txt = hybrid_score_key(model, ciphertext, syms, stream, key, args.word_weight)
            extras.append((sc, lang, txt))
    else:
        # Random exact-overlap mutations. Good when miss is close but too large
        # to enumerate.  It also works when active mappings borrow inactive letters.
        tries = args.feedback_tries
        for t in range(tries):
            key = base[:]
            S = random.sample(active, d)
            vals = [key[i] for i in S]
            if random.random() < 0.35 and A > N:
                inactive_vals = [i for i in range(A) if i not in set(base[:N])]
                random.shuffle(inactive_vals)
                for j in range(min(len(inactive_vals), max(1, d // 2))):
                    vals[j % d] = inactive_vals[j]
            ok = False
            for _ in range(20):
                random.shuffle(vals)
                if all(key[pos] != val for pos, val in zip(S, vals)):
                    ok = True
                    break
            if not ok:
                continue
            for pos, val in zip(S, vals):
                key[pos] = val
            sc, txt = hybrid_score_key(model, ciphertext, syms, stream, key, args.word_weight)
            extras.append((sc, lang, txt))
    extras.sort(reverse=True, key=lambda x: x[0])
    # Unique text and exact overlap sanity.
    base_map = mapping_for_text(model, ciphertext, submitted_txt)
    uniq = []
    seen = set()
    for sc, lang, txt in extras:
        if txt in seen:
            continue
        cand_map = mapping_for_text(model, ciphertext, txt)
        if mapping_overlap(base_map, cand_map) != correct:
            continue
        seen.add(txt)
        uniq.append((sc, lang, txt))
        if len(uniq) >= args.feedback_keep:
            break
    if uniq:
        print(f"    feedback top: score={uniq[0][0]:.2f} sample={uniq[0][2][:120]!r}", flush=True)
    return uniq


def merge_candidates(a, b):
    merged = {}
    for item in a + b:
        sc, lang, txt = item
        old = merged.get(txt)
        if old is None or sc > old[0]:
            merged[txt] = item
    return sorted(merged.values(), reverse=True, key=lambda x: x[0])


def cleanup_round_memory():
    # wordfreq and the local cache can grow across many rounds.  On WSL/Kali this
    # can end with the shell message `killed`.  Clear our cache every round and
    # force a collection; wordfreq itself stays imported.
    try:
        _WORD_SCORE_CACHE.clear()
    except Exception:
        pass
    gc.collect()


def extract_kctf_token(screen):
    """Extract Google/kCTF Sloth PoW challenge token from the service screen.

    Challenge token shape is usually: s.<difficulty_b64>.<x_b64>
    Example: s.ABod.AAAj1gvictTr9Tw8xykfas74
    """
    text = _clean_ansi(screen)
    patterns = [
        r"\b(s\.[A-Za-z0-9+/=]{2,}\.[A-Za-z0-9+/=]{6,})\b",
        r"solve\s+(s\.[^\s\)\]\r\n]+\.[^\s\)\]\r\n]+)",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1).strip().strip("`'\"")
    return None


def _extract_solution_token(out, challenge_token=None):
    """Pick solution token from kCTF solver output.

    The official solver normally prints only `s.<base64>`. This parser is
    tolerant to notices printed to stderr.
    """
    text = _clean_ansi(out)
    toks = re.findall(r"\bs\.[A-Za-z0-9+/=]+(?:\.[A-Za-z0-9+/=]+)?\b", text)
    # Prefer one-dot solution tokens. The challenge token has two dots.
    for tok in reversed(toks):
        if tok != challenge_token and tok.count(".") == 1:
            return tok
    for line in reversed([ln.strip() for ln in text.splitlines() if ln.strip()]):
        if line.startswith("s.") and line != challenge_token:
            return line.split()[0]
    return None


def _run_kctf_pow_official(token, timeout=360):
    """Run the exact official helper from the prompt via curl/process-substitution."""
    cmd = f"python3 <(curl -fsSL https://goo.gle/kctf-pow) solve {shlex.quote(token)}"
    print(f"[+] kCTF PoW token detected: {token}")
    print("[+] solving PoW with official helper...")
    proc = subprocess.run(
        ["bash", "-lc", cmd],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    sol = _extract_solution_token(combined, token)
    if proc.returncode == 0 and sol:
        return sol
    raise RuntimeError(
        "official kCTF PoW helper failed\n"
        f"returncode={proc.returncode}\n"
        f"stdout={proc.stdout[-1200:]}\n"
        f"stderr={proc.stderr[-1200:]}"
    )


def _kctf_b64_decode(enc):
    return int.from_bytes(base64.b64decode(enc.encode()), "big")


def _kctf_b64_encode(num):
    size = (num.bit_length() // 24) * 3 + 3
    return base64.b64encode(num.to_bytes(size, "big")).decode()


def _solve_kctf_pow_embedded_gmpy(token):
    """Embedded kCTF Sloth solver. Fast only when gmpy2 is installed."""
    try:
        import gmpy2
    except Exception as e:
        raise RuntimeError("gmpy2 not installed for embedded kCTF solver") from e

    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "s":
        raise ValueError(f"bad kCTF token: {token}")
    diff = _kctf_b64_decode(parts[1])
    x = gmpy2.mpz(_kctf_b64_decode(parts[2]))
    p = gmpy2.mpz(2) ** 1279 - 1
    exp = (p + 1) // 4
    print(f"[+] solving PoW with embedded gmpy2 solver, difficulty={diff}...")
    for _ in range(diff):
        x = gmpy2.powmod(x, exp, p).bit_flip(0)
    return "s." + _kctf_b64_encode(int(x))


def solve_kctf_pow(token):
    """Solve Google/kCTF PoW robustly.

    Order:
    1. Official helper from https://goo.gle/kctf-pow, exactly as service suggests.
    2. Embedded gmpy2 Sloth implementation if curl/network fails.
    """
    errors = []
    try:
        return _run_kctf_pow_official(token)
    except Exception as e:
        errors.append(str(e))
        print("[!] official helper failed, trying embedded gmpy2 fallback...")
    try:
        return _solve_kctf_pow_embedded_gmpy(token)
    except Exception as e:
        errors.append(str(e))
    raise RuntimeError(
        "Gagal solve kCTF PoW. Install curl + internet access atau gmpy2.\n"
        + "\n---\n".join(errors)
    )


def _pow_charset():
    return string.ascii_letters + string.digits


def _bruteforce_sha256(prefix="", suffix="", target_prefix="00000", max_len=8):
    """Small local PoW solver: find nonce where sha256(prefix+nonce+suffix) starts with target_prefix."""
    chars = _pow_charset()
    for i in itertools.count():
        for nonce in (str(i), format(i, "x")):
            h = hashlib.sha256((prefix + nonce + suffix).encode()).hexdigest()
            if h.startswith(target_prefix):
                return nonce
        if i > 20_000_000:
            break
    for n in range(1, max_len + 1):
        for tup in itertools.product(chars, repeat=n):
            nonce = "".join(tup)
            h = hashlib.sha256((prefix + nonce + suffix).encode()).hexdigest()
            if h.startswith(target_prefix):
                return nonce
    raise RuntimeError("PoW brute force limit reached")


def solve_pow_from_screen(screen):
    """Detect and solve PoW prompts.

    Supports:
      - Google/kCTF Sloth PoW token: s.<difficulty>.<challenge>
      - Simple sha256 prefix/suffix nonce prompts.

    Returns nonce/solution string, or None when no supported PoW prompt is detected.
    """
    token = extract_kctf_token(screen)
    if token:
        return solve_kctf_pow(token)

    low = screen.lower()
    if "sha256" not in low or not any(w in low for w in ("proof", "pow", "nonce", "suffix", "prefix", "starts")):
        return None

    target = None
    pats = [
        r"startswith\s*\(\s*['\"]([0-9a-fA-F]{3,})['\"]\s*\)",
        r"starts?\s+with\s+['\"]?([0-9a-fA-F]{3,})['\"]?",
        r"(?:hash|digest).*?(?:prefix|beginning).*?['\"]([0-9a-fA-F]{3,})['\"]",
        r"leading\s+(\d+)\s+zero",
    ]
    for pat in pats:
        m = re.search(pat, screen, re.I | re.S)
        if m:
            if pat.startswith("leading"):
                target = "0" * int(m.group(1))
            else:
                target = m.group(1).lower()
            break
    if target is None:
        target = "00000"

    strlit = r"(?:b)?['\"]([^'\"]*)['\"]"
    var = r"(?:x|s|nonce|answer|solution|input|proof|unknown|\?)"
    prefix = ""
    suffix = ""

    m = re.search(r"sha256\s*\([^\n)]*?" + strlit + r"\s*\+\s*" + var + r"(?:\s*\+\s*" + strlit + r")?", screen, re.I | re.S)
    if m:
        prefix = m.group(1)
        if m.lastindex and m.lastindex >= 2 and m.group(2) is not None:
            suffix = m.group(2)
    else:
        m = re.search(r"sha256\s*\([^\n)]*?" + var + r"\s*\+\s*" + strlit, screen, re.I | re.S)
        if m:
            suffix = m.group(1)
        else:
            mp = re.search(r"prefix\s*[:=]\s*['\"]?([A-Za-z0-9+/_.=-]{4,})['\"]?", screen, re.I)
            ms = re.search(r"suffix\s*[:=]\s*['\"]?([A-Za-z0-9+/_.=-]{4,})['\"]?", screen, re.I)
            if mp:
                prefix = mp.group(1)
            if ms:
                suffix = ms.group(1)
            if not (prefix or suffix):
                return None

    return _bruteforce_sha256(prefix=prefix, suffix=suffix, target_prefix=target)

class Remote:
    def __init__(self, host, port, timeout=25):
        self.raw = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(self.raw, server_hostname=host)
        self.sock.settimeout(timeout)
        self.buf = b""

    def read_until_prompt(self, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            try:
                data = self.sock.recv(8192)
            except socket.timeout:
                continue
            if not data:
                # Remote closed the socket. Return any buffered text; if none,
                # make it visible to the main loop instead of silently printing blanks.
                if not self.buf:
                    return "[CONNECTION_CLOSED]"
                break
            self.buf += data
            txt = self.buf.decode("utf-8", errors="replace")
            # Do not stop only because the banner contains the word "flag".
            # The service prints `> 70% of 20 rounds = flag` before sending Round 1,
            # so the old reader returned too early and ciphertext extraction failed.
            if (re.search(r"\[\d+\s+attempt\(s\) left\]\s*>", txt)
                    or "Solution?" in txt
                    or "solution?" in txt.lower()
                    or FLAG_RE.search(txt)):
                out = txt
                self.buf = b""
                return out
        out = self.buf.decode("utf-8", errors="replace")
        self.buf = b""
        return out

    def send_line(self, s):
        self.sock.sendall(s.encode("utf-8") + b"\n")

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def write_readme(flag=None):
    flag_text = flag or "<isi flag akan muncul setelah solver berhasil>"
    md = f"""# Rune Decryptor

## Ringkasan

Service mengirim paragraf yang sudah diubah dengan substitusi monoalfabetik ke simbol rune. Bahasa asli dipilih dari beberapa bahasa: `de`, `en`, `es`, `fr`, `grc`, `it`, `la`, `nl`, `ru`, dan `sv`.

Solver memakai serangan klasik substitution-cipher:

1. Ambil paragraf rune dari prompt ronde.
2. Jalankan hillclimbing/simulated annealing untuk beberapa model bahasa kecil.
3. Model bahasa memberi skor berdasarkan trigram dan quadgram karakter.
4. Candidate plaintext terbaik dikirim ke service.
5. Feedback jumlah simbol benar dipakai sebagai validasi; solver mencoba candidate berikutnya jika belum exact.

## File Challenge

Tidak ada file lokal dari soal. Target hanya service:

```text
ncat --ssl rune-decryptor.chal.uiuc.tf 1337
```

## Analisis

Karena spasi dan tanda baca tetap terlihat, struktur kata masih bocor. Ini membuat substitution cipher bisa diserang dengan model bahasa. Contoh pola dari ciphertext:

```text
ᛇᚹ, ᛤᛇ, ᚫᚠᚹ, ᛇᛇᚹ
```

Pada salah satu ronde pola ini cocok dengan bahasa Belanda lama:

```text
en, de, van, een
```

Begitu beberapa kata pendek benar, mapping huruf lain ikut terkunci dari kata panjang.

## Solve Script

`solve.py` melakukan koneksi SSL langsung dengan Python `socket` + `ssl`, jadi tidak perlu `ncat`.

Untuk tiap ronde, script:

- mengekstrak baris yang berisi rune,
- menjalankan solver substitution cipher,
- mengirim maksimal 5 kandidat plaintext,
- lanjut otomatis sampai flag muncul.

## Cara Menjalankan

```bash
python3 solve.py
```

Parameter target bisa diganti:

```bash
python3 solve.py --host rune-decryptor.chal.uiuc.tf --port 1337
```

Kalau koneksi lambat, naikkan iterasi:

```bash
python3 solve.py --quick-restarts 8 --deep-restarts 30 --deep-steps 14000
```

## Flag

```text
{flag_text}
```

## Catatan

Tidak ada brute force agresif ke server. Semua kerja berat dilakukan lokal; service hanya menerima maksimal 5 submission per ronde sesuai aturan challenge.
"""
    with open("Readme.md", "w", encoding="utf-8") as f:
        f.write(md)



def make_dummy_plaintext(ciphertext, lang_hint="en"):
    """Create a wrong-but-length-valid answer to burn attempts quickly.

    Used only for languages that are intentionally skipped (default: ru/grc).
    The service mainly needs the number of letters to match; spaces/punctuation
    are not important for consuming an attempt, but preserving them keeps output
    readable and avoids weird length validation edge-cases.
    """
    fill = "a"
    if lang_hint == "ru":
        fill = "а"
    elif lang_hint == "grc":
        fill = "α"
    out = []
    for ch in ciphertext:
        if RUNE_RE.match(ch):
            out.append(fill)
        else:
            out.append(ch)
    return "".join(out)


def burn_round_fast(io, screen, ciphertext, expected_letters, lang_hint):
    """Skip a hard round with 5 quick wrong submissions.

    Optional skip mode: the service only requires >70% of 20 rounds. Russian and
    Ancient Greek rounds cost the most time in the local solver. Skipping can help
    timeout-prone sessions, but solvernat9 keeps it OFF by default for accuracy.
    """
    dummy = clean_candidate_for_submit(make_dummy_plaintext(ciphertext, lang_hint))
    lc = letter_count_for_service(dummy)
    if lc != expected_letters:
        dummy = ("а" if lang_hint == "ru" else "α" if lang_hint == "grc" else "a") * expected_letters
    print(f"[!] skip cepat lang={lang_hint}: kirim dummy 5x supaya lanjut ronde berikutnya", flush=True)
    last = screen
    for i in range(5):
        print(f"[>] skip attempt {i+1}/5 letters={letter_count_for_service(dummy)}/{expected_letters}", flush=True)
        io.send_line(dummy)
        last = io.read_until_prompt(timeout=20)
        if last:
            print(last)
        else:
            print("[!] tidak ada response setelah skip attempt; kemungkinan koneksi ditutup/timeout", flush=True)
            return last
        if FLAG_RE.search(last):
            return last
        new_ct = extract_ciphertext(last)
        if new_ct and new_ct != ciphertext:
            return last
    return last

def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST_DEFAULT)
    ap.add_argument("--port", type=int, default=PORT_DEFAULT)
    ap.add_argument("--quick-restarts", type=int, default=5)
    ap.add_argument("--quick-steps", type=int, default=2600)
    ap.add_argument("--deep-langs", type=int, default=4)
    ap.add_argument("--deep-restarts", type=int, default=22)
    ap.add_argument("--deep-steps", type=int, default=9500)
    ap.add_argument("--fast", action="store_true", help="pakai parameter lebih cepat, akurasi sedikit turun")
    ap.add_argument("--strong", action="store_true", help="pakai parameter berat seperti solvernat6; jangan pakai kalau WSL sering killed")
    ap.add_argument("--attempts", type=int, default=5)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--no-auto-wordfreq", action="store_true", help="jangan auto install/use wordfreq")
    ap.add_argument("--no-skip-hard", action="store_true", help="jangan skip otomatis ronde ru/grc yang biasanya makan waktu dan sering gagal")
    ap.add_argument("--hard-langs", default="", help="bahasa yang di-skip cepat supaya koneksi tidak timeout; contoh: ru,grc. Default kosong = tidak skip.")
    ap.add_argument("--polish-top", type=int, default=14)
    ap.add_argument("--polish-restarts", type=int, default=4)
    ap.add_argument("--polish-steps", type=int, default=3600)
    ap.add_argument("--word-weight", type=float, default=18.0)
    ap.add_argument("--feedback-max-distance", type=int, default=9)
    ap.add_argument("--feedback-tries", type=int, default=2500)
    ap.add_argument("--feedback-keep", type=int, default=40)
    ap.add_argument("--offline", help="solve a ciphertext text file instead of connecting")
    args = ap.parse_args()
    if args.fast:
        args.quick_restarts = min(args.quick_restarts, 4)
        args.quick_steps = min(args.quick_steps, 2200)
        args.deep_restarts = min(args.deep_restarts, 16)
        args.deep_steps = min(args.deep_steps, 7000)
        args.polish_top = min(args.polish_top, 9)
        args.polish_restarts = min(args.polish_restarts, 3)
        args.polish_steps = min(args.polish_steps, 2800)
        args.feedback_tries = min(args.feedback_tries, 1400)
    if args.strong:
        args.quick_restarts = max(args.quick_restarts, 5)
        args.quick_steps = max(args.quick_steps, 2600)
        args.deep_restarts = max(args.deep_restarts, 22)
        args.deep_steps = max(args.deep_steps, 9500)
        args.polish_top = max(args.polish_top, 18)
        args.polish_restarts = max(args.polish_restarts, 4)
        args.polish_steps = max(args.polish_steps, 4500)
        args.feedback_tries = max(args.feedback_tries, 2600)
    if args.seed is not None:
        random.seed(args.seed)

    ensure_wordfreq(auto_install=not args.no_auto_wordfreq)
    models = {lang: NGramModel(lang) for lang in CORPORA}

    if args.offline:
        ct = open(args.offline, encoding="utf-8").read().strip()
        cands = candidate_pool(ct, args, models)
        for i, (sc, lang, txt) in enumerate(cands[:args.attempts], 1):
            print(f"===== candidate {i} lang={lang} score={sc:.2f} =====")
            print(txt)
        return

    print(f"[+] target: {args.host}:{args.port}")
    io = Remote(args.host, args.port)
    try:
        screen = io.read_until_prompt()
        print(screen)
        # Optional PoW gate. The current Rune Decryptor prompt usually jumps straight to Round 1,
        # but this keeps the solver working if the infra enables a common sha256 proof-of-work.
        while True:
            ans = solve_pow_from_screen(screen)
            if ans is None:
                break
            print(f"[+] PoW solved: {ans}")
            io.send_line(ans)
            screen = io.read_until_prompt()
            print(screen)
        while True:
            mflag = FLAG_RE.search(screen)
            if mflag:
                flag = mflag.group(0)
                print(flag)
                write_readme(flag)
                return
            ct = extract_ciphertext(screen)
            if not ct:
                # Sometimes the remote sends the banner first and the round slightly later.
                # Read once more before giving up.
                more = io.read_until_prompt(timeout=20)
                if more:
                    screen += more
                    print(more)
                    ct = extract_ciphertext(screen)
            if not ct:
                print("[-] ciphertext tidak ketemu di screen terakhir")
                print("[debug] screen tail:")
                print(screen[-1500:])
                return
            expected_letters = len(RUNE_RE.findall(ct))
            print(f"[+] ciphertext chars={len(ct)} runes={len(set(RUNE_RE.findall(ct)))} letters_expected={expected_letters}", flush=True)
            print("[+] kalau berhenti di sini, bukan hang: script sedang nebak substitution cipher secara lokal", flush=True)
            cands = candidate_pool(ct, args, models)
            if not cands:
                print("[-] tidak ada kandidat")
                return
            hard_langs = {x.strip() for x in args.hard_langs.split(",") if x.strip()}
            top_lang = cands[0][1] if cands else ""
            if (not args.no_skip_hard) and top_lang in hard_langs:
                screen = burn_round_fast(io, screen, ct, expected_letters, top_lang)
                cleanup_round_memory()
                continue
            used = set()
            attempts_made = 0
            constraints = []  # (lang, submitted_txt, correct, total)
            while attempts_made < args.attempts:
                chosen = None
                # Prefer candidates consistent with prior exact-overlap feedback.
                for cand in cands:
                    sc, lang, txt0 = cand
                    txt_key = (lang, txt0)
                    if txt0 in used:
                        continue
                    ok = True
                    for clang, prev_txt, corr, total in constraints:
                        if lang != clang or lang not in models:
                            # Feedback is still useful, but do not over-filter across alphabets.
                            continue
                        prev_map = mapping_for_text(models[lang], ct, prev_txt)
                        cand_map = mapping_for_text(models[lang], ct, txt0)
                        if len(cand_map) == len(prev_map) and mapping_overlap(prev_map, cand_map) != corr:
                            ok = False
                            break
                    if ok:
                        chosen = cand
                        break
                if chosen is None:
                    for cand in cands:
                        if cand[2] not in used:
                            chosen = cand
                            break
                if chosen is None:
                    print("[-] kandidat habis")
                    break

                sc, lang, txt = chosen
                used.add(txt)
                txt = clean_candidate_for_submit(txt)
                lc = letter_count_for_service(txt)
                attempts_made += 1
                print(f"[>] attempt {attempts_made}: lang={lang} score={sc:.2f} letters={lc}/{expected_letters}")
                if lc != expected_letters:
                    print("[!] kandidat diskip: jumlah huruf tidak cocok, kemungkinan masih ada junk/ANSI")
                    continue
                if args.verbose:
                    print(txt[:500])
                io.send_line(txt)
                screen = io.read_until_prompt()
                print(screen)
                if "[CONNECTION_CLOSED]" in screen:
                    print("[-] koneksi ditutup server. Jalankan ulang solvernat9.py; default balanced accuracy + memory cleanup.")
                    return
                mflag = FLAG_RE.search(screen)
                if mflag:
                    flag = mflag.group(0)
                    print(flag)
                    write_readme(flag)
                    return
                # If a new round appears, stop trying this ciphertext.
                new_ct = extract_ciphertext(screen)
                if new_ct and new_ct != ct:
                    break
                fb = parse_feedback_count(screen)
                if fb is not None:
                    corr, total = fb
                    constraints.append((lang, txt, corr, total))
                    # If close, generate exact-overlap neighbors before spending next attempts.
                    if total == len(set(RUNE_RE.findall(ct))):
                        extra = feedback_near_candidates(ct, txt, lang, corr, total, args, models)
                        if extra:
                            cands = merge_candidates(cands, extra)
            # Ran out of attempts but service may already show next round / fail.
            cleanup_round_memory()
            continue
    finally:
        io.close()

if __name__ == "__main__":
    main()
