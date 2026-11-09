"""
Парсит «Войну и мир» с ilibrary.ru и собирает CSV (text,label,source)
для hard-negative примеров: кириллица + безобидная HTML-разметка.
"""
import argparse
import csv
import html
import random
import re
import time
from pathlib import Path

import requests
from bs4 import BeautifulSoup

URL = "https://ilibrary.ru/text/11/p.{n}/index.html"
HEADERS = {"User-Agent": "Mozilla/5.0 (dataset-building; contact: you@example.com)"}

# ---------- аугментация безобидной разметкой ----------
INLINE = [
    ("<i>", "</i>"), ("<em>", "</em>"), ("<b>", "</b>"), ("<strong>", "</strong>"),
    ("<u>", "</u>"), ("<sup>", "</sup>"), ("<mark>", "</mark>"), ("<span>", "</span>"),
    ('<span class="note">', "</span>"),
    ('<span style="color:#555">', "</span>"),
    ('<span lang="fr">', "</span>"),
    ('<span id="ref-1">', "</span>"),
    ('<a href="/chapter/1">', "</a>"),
    ('<abbr title="князь">', "</abbr>"),
]

BLOCK = [
    ("<p>", "</p>"), ('<div class="paragraph">', "</div>"),
    ("<blockquote>", "</blockquote>"), ("<li>", "</li>"), ("<td>", "</td>"),
]

SENT_SPLIT = re.compile(r'(?<=[.!?…»])\s+(?=[—«"A-ZА-ЯЁ])')
# ---------- синтетические XSS-примеры с кириллицей (label=malicious) ----------
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
    "в консоли можно написать alert(1), чтобы проверить, что скрипт выполняется",
    "атрибут onerror у img вызывается при ошибке загрузки, не забудьте экранировать вывод",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "используйте textContent вместо innerHTML, чтобы <b>избежать</b> XSS",
    "eval('2 + 2')",
    "console.log('{cy}')",
    "для проверки можно вызвать alert('{cy}') в консоли браузера",
    "в тестах мы мокаем window.alert, чтобы не блокировать выполнение",
    "вместо alert(1) лучше использовать console.log",
    "функция confirm('Удалить?') показывает диалог подтверждения",
    "prompt('Введите имя') возвращает строку или null",
    "`alert(1)` — классический пример для проверки XSS, но в продакшене так делать нельзя",
    "setTimeout(() => alert('{cy}'), 1000);",
    "if (confirm('Вы уверены?')) { deleteItem(id); }",
    "const name = prompt('Как вас зовут?');",
    "window.print() открывает диалог печати",
    "в Python для вывода используйте print('{cy}')",
    "print('{cy}') выведет строку в консоль",
    "confirm и prompt блокируют поток, лучше использовать модальные окна",
    "<button onclick=\"if(confirm('{cy}')) save()\">Сохранить</button>",
]

# Политика меток: <script>/<iframe> в benign — только как ЦИТИРУЕМЫЙ код (бэктики, fence, <code>).
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
    "script": 4,
    "img": 5,
    "svg": 3,
    "iframe": 1,
    "body": 1,
    "input": 1,
    "details": 1,
    "animate": 1,
    "textarea": 1,
    "a": 2,
    "summary": 1,
    "handlers": 3,
    "form": 2,
    "button": 2,
}

DIALOGS = ["alert", "confirm", "prompt", "print"]

DIALOG_MENTIONS = [
    "{f}('{cy}')",
    "`{f}('{cy}')`",
    "в консоли можно вызвать {f}('{cy}'), чтобы проверить результат",
    "window.{f}('{cy}');",
    "setTimeout(() => {f}('{cy}'), 1000);",
    "в тестах мы мокаем window.{f}, чтобы не блокировать выполнение",
    "вместо {f}(...) лучше использовать модальное окно",
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
        return "текст"
    k = rng.randint(1, min(3, len(words)))
    i = rng.randrange(len(words) - k + 1)
    return " ".join(words[i:i + k])

def decorate_payload(payload, rng, p=0.25):
    if rng.random() < p:
        o, c = rng.choice(INLINE + BLOCK)
        payload = f"{o}{payload}{c}"
    return payload

def inject_xss(text, rng):
    if rng.random() < 0.10:          # бэктики есть, но payload снаружи кода
        text = f"`{cyr_fragment(text, rng)}` {text}"
    pool = TAGLESS_XSS if rng.random() < 0.12 else XSS_PAYLOADS
    payload = rng.choice(pool).replace("{cy}", cyr_fragment(text, rng)).replace("{cy_num}", "1")
    # не привязываемся к слову alert
    payload = re.sub(r"alert\(",
                     lambda m: rng.choice(["alert(", "confirm(", "prompt(", "print("]),
                     payload)
    if rng.random() < 0.40:
        payload = quote_attrs(payload)          # выравниваем долю атрибутов без кавычек
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
    if r < 0.20:                       # чистый текст
        return text
    out = text
    if r < 0.65:                       # inline-теги
        out = wrap_random_words(out, rng, rng.randint(1, 3))
    elif r < 0.85:                     # блок + inline
        out = wrap_random_words(out, rng, rng.randint(0, 2))
        o, c = rng.choice(BLOCK)
        out = f"{o}{out}{c}"
    else:                              # экранированная разметка
        out = html.escape(wrap_random_words(out, rng, rng.randint(1, 2)))
    # дополнительные безобидные «шумы»
    if rng.random() < 0.15:
        out = out.replace("—", "&mdash;").replace("«", "&laquo;").replace("»", "&raquo;")
    if rng.random() < 0.10:
        out = out.replace(" ", "&nbsp;", rng.randint(1, 3))
    if rng.random() < 0.10:
        out = "<!-- глава -->" + out
    if rng.random() < 0.10:
        out = out.replace(". ", ".<br>", 1)
    return out

# ---------- загрузка и парсинг ----------
def fetch(n, cache_dir):
    cache = cache_dir / f"p{n}.html"
    if cache.exists():
        return cache.read_text(encoding="utf-8")
    for attempt in range(4):
        try:
            r = requests.get(URL.format(n=n), headers=HEADERS, timeout=30)
            r.raise_for_status()
            text = r.content.decode("cp1251", errors="replace")  # сайт в windows-1251
            cache.write_text(text, encoding="utf-8")
            return text
        except requests.RequestException as e:
            print(f"  p.{n}: попытка {attempt + 1} не удалась: {e}")
            time.sleep(2 * (attempt + 1))
    return None

def extract_paragraphs(page_html):
    soup = BeautifulSoup(page_html, "html.parser")
    for t in soup(["script", "style", "noscript", "nav", "header", "footer"]):
        t.decompose()
    for a in soup.select('a[href^="#fn"]'):      # ссылки на сноски
        a.decompose()
    root = soup.find(id="text") or soup.body or soup
    nodes = root.select("span.p") or root.find_all("p")
    if nodes:
        paras = [n.get_text() for n in nodes]          # без разделителя
    else:
        paras = [s.strip() for s in root.get_text("\n").split("\n")]
    paras = [re.sub(r"\s+([.,;:!?»)])", r"\1", re.sub(r"\s+", " ", p)).strip() for p in paras]
    return [p for p in paras if p]

def chunk(paragraph, min_len, max_len):
    """Режем длинные абзацы по предложениям до max_len символов."""
    sents, cur, out = SENT_SPLIT.split(paragraph), "", []
    for s in sents:
        if cur and len(cur) + len(s) + 1 > max_len:
            out.append(cur)
            cur = s
        else:
            cur = f"{cur} {s}".strip()
    if cur:
        out.append(cur)
    # очень длинное предложение без точек — режем жёстко
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
    if rng.random() < 0.15:                      # <B>, <DIV>, <Span>
        text = random_case_tags(text, rng)
    if rng.random() < 0.10:                      # class=note вместо class="note"
        text = re.sub(r'=\"([^\" ]+)\"', r'=\1', text)
    if rng.random() < 0.08:                      # осиротевший закрывающий тег
        text = rng.choice(BREAKOUT) + " " + text
    return text

def drop_random_close_tag(text, rng, p=0.12):
    """Ломаем парность: убираем один закрывающий тег."""
    if rng.random() < p:
        closes = list(re.finditer(r"</[a-zA-Z]+>", text))
        if closes:
            m = rng.choice(closes)
            return text[:m.start()] + text[m.end():]
    return text

def main():
    # Определяем базовые пути относительно расположения скрипта
    base_dir = Path(__file__).resolve().parent.parent
    interim_dir = base_dir / "interim"
    interim_dir.mkdir(parents=True, exist_ok=True)

    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=361)
    ap.add_argument("--limit", type=int, default=None, help="только первые N страниц")
    # По умолчанию пишем в interim
    ap.add_argument("--out", default=str(interim_dir / "war_and_peace_hard_benign.csv"))
    ap.add_argument("--label", default="0")
    ap.add_argument("--source", default="hard_benign")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--min-len", type=int, default=30)
    ap.add_argument("--max-len", type=int, default=400)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--xss-ratio", type=float, default=0.3)
    ap.add_argument("--xss-label", default="1")
    ap.add_argument("--xss-source", default="synthetic-xss-cyrillic")
    ap.add_argument("--mention-ratio", type=float, default=0.22)
    ap.add_argument("--p-aug-attack", type=float, default=0.40)
    ap.add_argument("--p-aug-benign", type=float, default=0.80)
    ap.add_argument("--twin-ratio", type=float, default=0.40)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    # Кэш тоже прячем в interim, чтобы не мусорить
    cache_dir = interim_dir / "cache_wp"
    cache_dir.mkdir(exist_ok=True)
    
    total = args.limit or args.pages

    seen, rows = set(), []
    for n in range(1, total + 1):
        was_cached = (cache_dir / f"p{n}.html").exists()
        page = fetch(n, cache_dir)
        if page is None:
            print(f"p.{n}: пропущена")
            continue
        added = 0
        for para in extract_paragraphs(page):
            for piece in chunk(para, args.min_len, args.max_len):
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
                rows.append((text, label, source))
                added += 1
        print(f"p.{n}/{total}: +{added} (всего {len(rows)})")
        if not was_cached:
            time.sleep(args.delay)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["text", "label", "source"])
        w.writerows(rows)
    
    print(f"Готово: {len(rows)} строк -> {out_path}")

if __name__ == "__main__":
    main()