#!/usr/bin/env python3
"""
Собирает CSV (text,label,source) для hard-negative примеров
(кириллица + безобидная HTML-разметка) из локального txt-файла.

python scrape_wp.py --input war_and_peace.txt --limit 100
python scrape_wp.py --input war_and_peace.txt
"""
import argparse
import csv
import html
import random
import re
from pathlib import Path

# ---------- аугментация безобидной разметкой ----------
INLINE = [
    ("<i>", "</i>"), ("<em>", "</em>"), ("<b>", "</b>"), ("<strong>", "</strong>"),
    ("<u>", "</u>"), ("<sup>", "</sup>"), ("<mark>", "</mark>"), ("<span>", "</span>"),
    ('<span class="note">', "</span>"),
    ('<span style="color:#555">', "</span>"),
    ('<span lang="fr">', "</span>"),
    ('<span id="ref-1">', "</span>"),
    ('<a href="/chapter/1">', "</a>"),
    ('<abbr title="text">', "</abbr>"),
]

BLOCK = [
    ("<p>", "</p>"), ('<div class="paragraph">', "</div>"),
    ("<blockquote>", "</blockquote>"), ("<li>", "</li>"), ("<td>", "</td>"),
]

SENT_SPLIT = re.compile(r'(?<=[.!?…»])\s+(?=[—«"A-ZА-ЯЁ])')

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('{cy}')</script>",
    "<img src=x onerror=alert(1)>",
    '<img src="x" onerror="alert(\'{cy}\')">',
    "<svg onload=alert(1)>",
    "<svg><script>alert&#40;1&#41;</script></svg>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>{cy}</details>",
    '<a href="javascript:alert(1)">{cy}</a>',
    '<a href="&#106;avascript:alert(1)">{cy}</a>',
    '<div onmouseover="alert(\'{cy}\')">{cy}</div>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<img src=x onerror=alert(String.fromCharCode(1056,1091,1089))>',
    "<script>alert(document.domain)</script>",
    '<span style="background:url(javascript:alert(1))">{cy}</span>',
    "<img/src=x/onerror=alert(1)>",
    "<img src=x onerror=confirm(1)>",
    "<img src=x onerror=prompt(1)>",
    "<svg onload=eval(atob('YWxlcnQoMSk='))>",
    "<body onpageshow=print()>",
    "<a href=\"jav&#x61;script:confirm(1)\">{cy}</a>",
    "<img src=x onerror=alert`1`>",
    '<a href="javascript:alert`1`">{cy}</a>',
    "<svg><path id=x onmouseover=alert(1)>{cy}</path></svg>",
    "<svg><title><img src=x onerror=alert(1)></title></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<details open><summary onclick=alert(1)>{cy}</summary></details>",
    "<code onmouseover=alert(1)>{cy}</code>",
    "<button onclick=alert(1)>{cy}</button>",
    "<form><button formaction=javascript:alert(1)>{cy}</button></form>",
    "<img src=x onerror=top['al'+'ert'](1)>",
    "<img src=x onerror=window['alert'](1)>",
    "<img src=x onerror=Function('alert(1)')()>",
]

TAGLESS_XSS = [
    '" onfocus="alert(1)" autofocus="',
    "' onmouseover='alert(1)' x='",
    "javascript:alert(1)",
    "javascript:confirm({cy_num})",
    "';alert(1);//",
    '";alert(1);//',
    '"-alert(1)-"',
    "{{constructor.constructor('alert(1)')()}}",
]

BREAKOUT = ['">', "'>", "</p>", "</span>", "</i>", "-->", "</textarea>"]

BENIGN_LOOKALIKES = [
    '<img src="cover.png" alt="{cy}">',
    '<input autofocus placeholder="{cy}">',
    '<svg width="16" height="16" viewBox="0 0 16 16"></svg>',
    "<details open>{cy}</details>",
    '<a href="https://example.com/page">{cy}</a>',
    '<div class="card" title="{cy}">{cy}</div>',
    '<body class="page">',
    '<span style="font-weight:bold">{cy}</span>',
]

BENIGN_CODE_MENTIONS = [
    "u can write alert(1) in console for testing",
    "attribute onerror on img is called when image fails to load, don't forget to escape output",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "use textContent instead of innerHTML to <b>avoid</b> XSS",
    "eval('2 + 2')",
    "console.log('{cy}')",
    "for testing you can call alert('{cy}') in the browser console",
    "in tests we mock window.alert to avoid blocking execution",
    "instead of alert(1) it's better to use console.log",
    "the confirm('Delete?') function shows a confirmation dialog",
    "prompt('Enter your name') returns a string or null",
    "`alert(1)` — a classic example for testing XSS, but this is not recommended in production",
    "setTimeout(() => alert('{cy}'), 1000);",
    "if (confirm('Are you sure?')) { deleteItem(id); }",
    "const name = prompt('What is your name?');",
    "window.print() opens the print dialog",
    "in Python for output use print('{cy}')",
    "print('{cy}') will print the string to the console",
    "confirm and prompt block the thread, it's better to use modal windows",
    "<button onclick=\"if(confirm('{cy}')) save()\">Save</button>",
]

TWINS = {
    "script": [
        '`<script src="/static/app.js"></script>`',
        "```html\n<script>console.log('{cy}');</script>\n```",
        "<code>&lt;script&gt;console.log('{cy}')&lt;/script&gt;</code>",
        '`<script type="module">import "./main.js"</script>`',
    ],
    "img": [
        '<img src="cover.png" alt="{cy}">',
        '<img src="/img/photo.jpg" width="120" height="80">',
        "<img src=cover.png alt=pic>",
        '<IMG SRC="logo.png">',
    ],
    "svg": [
        '<svg width="16" height="16" viewBox="0 0 16 16"><path d="M2 2h12v12H2z"/></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg" class="icon"></svg>',
        "<svg><title>{cy}</title></svg>",
    ],
    "iframe": [
        '<iframe title="{cy}" width="560" height="315"></iframe>',
        '<iframe src="/embed/video1" loading="lazy"></iframe>',
        '<iframe src="about:blank"></iframe>',
    ],
    "body":    ['<body class="page">', '<body style="margin:0">', "<body id=main>"],
    "input":   ['<input type="text" placeholder="{cy}">', "<input type=text name=q value=test>"],
    "details": ["<details><summary>{cy}</summary>текст</details>", "<details open>{cy}</details>"],
    "animate": [
        '<svg><animate attributeName="opacity" from="0" to="1" dur="1s"/></svg>',
        '<animate attributeName="x" from="0" to="10" dur="2s" repeatCount="indefinite"/>',
    ],
    "textarea": ['<textarea rows="3" placeholder="{cy}"></textarea>', "<textarea name=msg>{cy}</textarea>"],
    "a": ['<a href="/docs/intro">{cy}</a>', '<a href="#top">{cy}</a>', '<a href="mailto:team@example.com">{cy}</a>'],
    "summary": ["<details><summary>{cy}</summary>{cy}</details>"],
    "handlers": [
        '<button onclick="toggleMenu()">{cy}</button>',
        '<a href="#" onclick="return false;">{cy}</a>',
        '<input onchange="save()" value="{cy}">',
        '<a href="javascript:void(0)">{cy}</a>',
        '<img src="a.png" onerror="this.src=\'fallback.png\'">',
    ],
    "form": [
        '<form action="/search" method="get"><input name="q"></form>',
        '<form method="post" action="/login">{cy}</form>',
        '<form><button formaction="/submit">{cy}</button></form>',
        "<form><label>{cy}</label></form>",
    ],
    "button": [
        '<button type="submit">{cy}</button>',
        '<button class="btn" disabled>{cy}</button>',
        "<button type=button>OK</button>",
    ],
}

TWIN_WEIGHTS = {
    "script": 4, "img": 5, "svg": 3, "iframe": 1, "body": 1, "input": 1,
    "details": 1, "animate": 1, "textarea": 1, "a": 2, "summary": 1,
    "handlers": 3, "form": 2, "button": 2,
}

DIALOGS = ["alert", "confirm", "prompt", "print"]

DIALOG_MENTIONS = [
    "{f}('{cy}')",
    "`{f}('{cy}')`",
    "you can call {f}('{cy}') in the console to check the result",
    "window.{f}('{cy}');",
    "setTimeout(() => {f}('{cy}'), 1000);",
    "in tests we mock window.{f} to avoid blocking execution",
    "instead of {f}(...) it's better to use a modal window",
    "<code>{f}('{cy}')</code>",
    "if (ok) { {f}('{cy}'); }",
]


def inject_twin(text, rng):
    tag = rng.choices(list(TWINS), weights=[TWIN_WEIGHTS[t] for t in TWINS])[0]
    twin = rng.choice(TWINS[tag]).replace("{cy}", cyr_fragment(text, rng))
    return f"{text} {twin}" if rng.random() < 0.5 else f"{twin} {text}"


def inject_code_mention(text, rng):
    if rng.random() < 0.8:
        m = rng.choice(DIALOG_MENTIONS).replace("{f}", rng.choice(DIALOGS))
    else:
        m = rng.choice(BENIGN_CODE_MENTIONS)
    m = m.replace("{cy}", cyr_fragment(text, rng))
    return f"{text} {m}" if rng.random() < 0.5 else f"{m} {text}"


def quote_attrs(s):
    return re.sub(r'(\s[a-zA-Z\-]+)=([^\s"\'>]+)', r'\1="\2"', s)


def inject_lookalike(text, rng):
    tag = rng.choice(BENIGN_LOOKALIKES).replace("{cy}", cyr_fragment(text, rng))
    return f"{text} {tag}" if rng.random() < 0.5 else f"{tag} {text}"


def random_case_tags(s, rng):
    """<script> -> <ScRiPt> (регистровая обфускация имён тегов)."""
    def repl(m):
        name = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in m.group(2))
        return f"<{m.group(1)}{name}"
    return re.sub(r"<(/?)([a-zA-Z]+)", repl, s)


def cyr_fragment(text, rng):
    words = re.findall(r"[А-Яа-яЁё]{3,}", text)
    if not words:
        return "text"
    k = rng.randint(1, min(3, len(words)))
    i = rng.randrange(len(words) - k + 1)
    return " ".join(words[i:i + k])


def decorate_payload(payload, rng, p=0.25):
    if rng.random() < p:
        o, c = rng.choice(INLINE + BLOCK)
        payload = f"{o}{payload}{c}"
    return payload


def inject_xss(text, rng):
    if rng.random() < 0.10:
        text = f"`{cyr_fragment(text, rng)}` {text}"
    pool = TAGLESS_XSS if rng.random() < 0.12 else XSS_PAYLOADS
    payload = rng.choice(pool).replace("{cy}", cyr_fragment(text, rng)).replace("{cy_num}", "1")
    payload = re.sub(r"alert\(",
                     lambda m: rng.choice(["alert(", "confirm(", "prompt(", "print("]),
                     payload)
    if rng.random() < 0.40:
        payload = quote_attrs(payload)
    if rng.random() < 0.25:
        payload = random_case_tags(payload, rng)
        payload = decorate_payload(payload, rng)
    if rng.random() < 0.25:
        payload = rng.choice(BREAKOUT) + payload
    pos = rng.choice(["start", "end", "middle"])
    if pos == "start":
        return f"{payload} {text}"
    if pos == "end":
        return f"{text} {payload}"
    words = text.split(" ")
    i = rng.randint(1, max(1, len(words) - 1))
    return " ".join(words[:i] + [payload] + words[i:])


def wrap_random_words(text, rng, n_spans):
    words = text.split(" ")
    if len(words) < 4:
        return text
    used = set()
    for _ in range(n_spans):
        i = rng.randrange(len(words))
        j = min(len(words), i + rng.randint(1, 4))
        if any(k in used for k in range(i, j)):
            continue
        used.update(range(i, j))
        o, c = rng.choice(INLINE)
        words[i] = o + words[i]
        words[j - 1] = words[j - 1] + c
    return " ".join(words)


def augment(text, rng):
    if rng.random() < 0.15:
        return inject_lookalike(text, rng)
    r = rng.random()
    if r < 0.20:
        return text
    out = text
    if r < 0.65:
        out = wrap_random_words(out, rng, rng.randint(1, 3))
    elif r < 0.85:
        out = wrap_random_words(out, rng, rng.randint(0, 2))
        o, c = rng.choice(BLOCK)
        out = f"{o}{out}{c}"
    else:
        out = html.escape(wrap_random_words(out, rng, rng.randint(1, 2)))
    if rng.random() < 0.15:
        out = out.replace("—", "&mdash;").replace("«", "&laquo;").replace("»", "&raquo;")
    if rng.random() < 0.10:
        out = out.replace(" ", "&nbsp;", rng.randint(1, 3))
    if rng.random() < 0.10:
        out = "<!-- chapter -->" + out
    if rng.random() < 0.10:
        out = out.replace(". ", ".<br>", 1)
    return out


# ---------- чтение txt и нарезка ----------
def read_lines(path, encoding):
    """Построчный генератор: чистит пробелы и пропускает пустые строки."""
    with open(path, "r", encoding=encoding, errors="replace") as f:
        for line_no, raw in enumerate(f, 1):
            line = re.sub(r"\s+", " ", raw).strip()
            if line:
                yield line_no, line


def chunk(paragraph, min_len, max_len):
    """Режем длинные строки по предложениям до max_len символов."""
    sents, cur, out = SENT_SPLIT.split(paragraph), "", []
    for s in sents:
        if cur and len(cur) + len(s) + 1 > max_len:
            out.append(cur)
            cur = s
        else:
            cur = f"{cur} {s}".strip()
    if cur:
        out.append(cur)
    final = []
    for c in out:
        while len(c) > max_len * 1.5:
            cut = c.rfind(" ", 0, max_len)
            cut = cut if cut > 0 else max_len
            final.append(c[:cut])
            c = c[cut:].strip()
        final.append(c)
    return [c.lstrip(" .,;") for c in final if len(c) >= min_len]


def benign_surface_noise(text, rng):
    if rng.random() < 0.15:
        text = random_case_tags(text, rng)
    if rng.random() < 0.10:
        text = re.sub(r'=\"([^\" ]+)\"', r'=\1', text)
    if rng.random() < 0.08:
        text = rng.choice(BREAKOUT) + " " + text
    return text


def drop_random_close_tag(text, rng, p=0.12):
    if rng.random() < p:
        closes = list(re.finditer(r"</[a-zA-Z]+>", text))
        if closes:
            m = rng.choice(closes)
            return text[:m.start()] + text[m.end():]
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="путь к txt-файлу с текстом")
    ap.add_argument("--encoding", default="utf-8", help="кодировка входного файла")
    ap.add_argument("--out", default="war_and_peace_hard_benign.csv")
    ap.add_argument("--label", default="0")
    ap.add_argument("--source", default="hard_benign")
    ap.add_argument("--min-len", type=int, default=30)
    ap.add_argument("--max-len", type=int, default=400)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--xss-ratio", type=float, default=0.3,
                    help="доля строк с XSS-payload (label=malicious)")
    ap.add_argument("--xss-label", default="1")
    ap.add_argument("--xss-source", default="synthetic-xss")
    ap.add_argument("--mention-ratio", type=float, default=0.22)
    ap.add_argument("--p-aug-attack", type=float, default=0.40)
    ap.add_argument("--p-aug-benign", type=float, default=0.80)
    ap.add_argument("--twin-ratio", type=float, default=0.40)
    ap.add_argument("--limit", type=int, default=None,
                    help="обработать только первые N непустых строк")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    seen = set()
    rows = []                # (text, label, source, line_no)
    processed = 0

    for line_no, line in read_lines(args.input, args.encoding):
        processed += 1
        if args.limit and processed > args.limit:
            break

        added = 0
        for piece in chunk(line, args.min_len, args.max_len):
            # NB: исходный код тратил один rng.random() впустую — оставил как есть,
            # чтобы сохранить распределение.
            base = augment(piece, rng) if rng.random() < 0.5 else piece

            if rng.random() < args.xss_ratio:
                base = augment(piece, rng) if rng.random() < args.p_aug_attack else piece
                text = inject_xss(base, rng)
                label, source = args.xss_label, args.xss_source
            else:
                base = augment(piece, rng) if rng.random() < args.p_aug_benign else piece
                r = rng.random()
                if r < args.twin_ratio:
                    text = inject_twin(base, rng)
                elif r < args.twin_ratio + args.mention_ratio:
                    text = inject_code_mention(base, rng)
                else:
                    text = base
                text = benign_surface_noise(text, rng)
                label, source = args.label, args.source

            text = drop_random_close_tag(text, rng)
            if text in seen:
                continue
            seen.add(text)
            rows.append((text, label, source, line_no))
            added += 1
        print(f"line {line_no}: +{added} (всего {len(rows)})")

    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["text", "label", "source"])
        w.writerows((r[0], r[1], r[2]) for r in rows)

    lines_out = args.out.replace(".csv", "_lines.csv")
    with open(lines_out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["line"])
        w.writerows((r[3],) for r in rows)

    print(f"Готово: {len(rows)} строк -> {args.out} (источники: {lines_out})")


if __name__ == "__main__":
    main()