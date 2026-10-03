"""
Рекурсивное декодирование входных строк для обнаружения XSS.

Применяет цепочку декодирований (URL, HTML-entity, unicode, hex)
до тех пор, пока строка перестаёт меняться. Это закрывает обходы
через многослойное кодирование: %253Cscript%253E → %3Cscript%3E → <script>

Референс: DeepXSS (Fang et al., 2018) — рекурсивное декодирование.
"""

import re
import html
import urllib.parse


_MAX_DEPTH = 10  # защита от зацикливания


def _decode_url_encoding(text: str) -> str:
    """Декодирование URL-encoding (%XX → символ)."""
    try:
        decoded = urllib.parse.unquote_plus(text)
        return decoded
    except Exception:
        return text


def _decode_html_entities(text: str) -> str:
    """Декодирование HTML-entities (< → <, < → <, &#x3C; → <)."""
    return html.unescape(text)


def _decode_unicode_escapes(text: str) -> str:
    """Декодирование Unicode-escape последовательностей (\\u003C → <)."""
    try:
        # Обработка \\uXXXX и \\UXXXXXXXX
        decoded = text.encode('utf-8').decode('unicode_escape')
        return decoded
    except (UnicodeDecodeError, UnicodeEncodeError):
        return text


def _decode_hex_escapes(text: str) -> str:
    """Декодирование hex-escape последовательностей (\\x3C → <)."""
    try:
        decoded = text.encode('raw_unicode_escape').decode('unicode_escape')
        return decoded
    except (UnicodeDecodeError, UnicodeEncodeError):
        return text


def _decode_js_charcode(text: str) -> str:
    """Декодирование String.fromCharCode(...)."""
    pattern = r'String\.fromCharCode\(([^)]+)\)'
    
    def replace_charcode(match):
        try:
            codes = match.group(1).split(',')
            chars = ''.join(chr(int(c.strip())) for c in codes)
            return chars
        except (ValueError, TypeError):
            return match.group(0)
    
    return re.sub(pattern, replace_charcode, text, flags=re.IGNORECASE)


def _normalize_whitespace(text: str) -> str:
    """Нормализация пробельных символов (tabs, newlines → пробел)."""
    return re.sub(r'[\t\n\r]+', ' ', text)


def _normalize_case(text: str) -> str:
    """
    Нижний регистр для HTML-тегов и атрибутов (кроме содержимого строк).
    <SCRIPT> → <script>, OnError → onerror
    """
    # Нормализуем HTML-теги
    def lower_tag(match):
        return match.group(0).lower()
    
    return re.sub(r'</?[a-zA-Z][a-zA-Z0-9]*|on[a-zA-Z]+=', lower_tag, text)


def decode_recursive(text: str) -> str:
    """
    Рекурсивно декодирует строку, пока она продолжает меняться.
    
    Порядок декодирования на каждой итерации:
    1. URL-encoding (%XX)
    2. HTML-entities (<, <, &#x3C;)
    3. Unicode-escape (\\uXXXX)
    4. Hex-escape (\\xXX)
    5. JS String.fromCharCode
    
    После декодирования: нормализация пробелов и регистра.
    """
    if not text:
        return text
    
    for _ in range(_MAX_DEPTH):
        original = text
        
        text = _decode_url_encoding(text)
        text = _decode_html_entities(text)
        text = _decode_unicode_escapes(text)
        text = _decode_hex_escapes(text)
        text = _decode_js_charcode(text)
        
        if text == original:
            break
    
    # Финальная нормализация
    text = _normalize_whitespace(text)
    text = _normalize_case(text)
    
    return text


def preprocess_input(text: str) -> dict:
    """
    Полный препроцессинг входа.
    
    Returns:
        dict с ключами:
        - 'original': исходный текст
        - 'decoded': декодированный текст
        - 'was_decoded': изменился ли текст после декодирования
    """
    decoded = decode_recursive(text)
    return {
        'original': text,
        'decoded': decoded,
        'was_decoded': text != decoded,
    }
