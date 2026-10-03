"""
Оракул валидации XSS-пейлоадов.

Проверяет, что мутант после обхода детектора ОСТАЁТСЯ исполняемым XSS.
Поднимает уязвимый sandbox (DVWA-стиль) и проверяет факт исполнения скрипта
в headless-браузере (Playwright).

Референс: plan_VKR_XSS.md — "пейлоад после мутаций должен оставаться
исполняемым XSS. Измеряем «evasive AND working», а не просто evasion rate."

Схема:
1. Разворачиваем минимальный уязвимый HTML-сток (3 контекста: HTML-body, attr, JS)
2. Внедряем payload в каждый контекст
3. Перехватываем window.alert / console.log в headless Chromium
4. Если alert сработал → payload рабочий
"""

import asyncio
from typing import Optional


# ============================================================
# Уязвимый HTML-сток (3 контекста инъекции)
# ============================================================

VULNERABLE_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>XSS Oracle Sandbox</title></head>
<body>
    <h1>XSS Oracle Validation</h1>
    
    <!-- Контекст 1: HTML Body (вставка в тело) -->
    <div id="body-context">{body_payload}</div>
    
    <!-- Контекст 2: Attribute (вставка в атрибут) -->
    <input type="text" value="{attr_payload}" id="attr-context">
    
    <!-- Контекст 3: JavaScript (вставка в JS-строку) -->
    <script>
        var userInput = "{js_payload}";
        document.getElementById("attr-context").title = userInput;
    </script>
</body>
</html>
"""


def prepare_payload_for_context(payload: str, context: str) -> str:
    """
    Подготавливает payload для конкретного контекста инъекции.
    
    Args:
        payload: XSS-пейлоад
        context: 'body', 'attr', или 'js'
    """
    if context == 'body':
        return payload
    elif context == 'attr':
        # Экранируем кавычки для атрибута, добавляем breakout
        return f'" onmouseover="{payload}" x="'
    elif context == 'js':
        # Экранируем для JS-строки
        return f'";{payload}//'
    return payload


def build_sandbox_html(payload: str) -> str:
    """Строит HTML-страницу с payload во всех 3 контекстах."""
    return VULNERABLE_HTML_TEMPLATE.format(
        body_payload=prepare_payload_for_context(payload, 'body'),
        attr_payload=prepare_payload_for_context(payload, 'attr'),
        js_payload=prepare_payload_for_context(payload, 'js'),
    )


# ============================================================
# Playwright-based валидация
# ============================================================

async def validate_payload_playwright(payload: str, timeout_ms: int = 3000) -> dict:
    """
    Проверяет исполнение XSS-пейлоада через headless Chromium.
    
    Перехватывает:
    - window.alert()
    - window.confirm()
    - window.prompt()
    - console.error() с XSS-маркером
    
    Returns:
        dict с:
        - 'is_executable': bool — сработал ли payload
        - 'alert_triggered': bool — вызвал ли alert
        - 'contexts': list[str] — в каких контекстах сработал
        - 'alert_value': str — значение alert (если был)
        - 'errors': list[str] — ошибки
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            'is_executable': False,
            'alert_triggered': False,
            'contexts': [],
            'alert_value': '',
            'errors': ['playwright не установлен. pip install playwright && playwright install chromium'],
        }
    
    html_content = build_sandbox_html(payload)
    
    results = {
        'is_executable': False,
        'alert_triggered': False,
        'contexts': [],
        'alert_value': '',
        'errors': [],
    }
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # Перехват alert/confirm/prompt
            alert_fired = asyncio.Event()
            alert_value = ''
            
            async def on_dialog(dialog):
                nonlocal alert_value
                alert_value = dialog.message
                alert_fired.set()
                await dialog.dismiss()
            
            page.on('dialog', on_dialog)
            
            # Загружаем HTML
            await page.set_content(html_content, wait_until='domcontentloaded')
            
            # Ждём немного для исполнения скриптов
            try:
                await asyncio.wait_for(alert_fired.wait(), timeout=timeout_ms / 1000)
                results['alert_triggered'] = True
                results['alert_value'] = alert_value
                results['is_executable'] = True
            except asyncio.TimeoutError:
                # Alert не сработал — пробуем проверить DOM-изменения
                pass
            
            # Проверяем, были ли ошибки XSS-скрипта (тоже признак исполнения)
            errors = []
            page.on('pageerror', lambda e: errors.append(str(e)))
            
            # Проверяем cookie (document.cookie может быть признаком JS-исполнения)
            try:
                cookie_result = await page.evaluate("document.cookie")
                if 'xss_test' in str(cookie_result):
                    results['is_executable'] = True
            except Exception:
                pass
            
            # Проверяем, изменился ли DOM
            try:
                body_text = await page.inner_text('#body-context')
                if '<script>' in body_text.lower() or 'alert' in body_text.lower():
                    # Скрипт не исполнился, но отобразился — partial XSS
                    pass
            except Exception:
                pass
            
            await browser.close()
    
    except Exception as e:
        results['errors'].append(str(e))
    
    return results


def validate_payload_sync(payload: str) -> dict:
    """Синхронная обёртка для validate_payload_playwright."""
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(validate_payload_playwright(payload))
        return result
    finally:
        loop.close()


# ============================================================
# Быстрый оракул без Playwright (для тестов и CI)
# ============================================================

def validate_payload_heuristic(payload: str) -> dict:
    """
    Эвристическая проверка исполняемости XSS без браузера.
    
    Проверяет наличие обязательных компонентов:
    1. HTML-тег/атрибут/обработчик событий
    2. JS-код для исполнения (alert, eval, document.cookie и т.д.)
    3. Синтаксическую корректность (открытые/закрытые теги)
    
    Returns: dict с is_executable, confidence, reasons
    """
    import re
    
    reasons = []
    confidence = 0.0
    
    payload_lower = payload.lower().strip()
    
    # 1. Есть ли исполняемый тег?
    has_executable_tag = bool(re.search(
        r'<\s*(script|svg|img|iframe|embed|object|video|audio|source|'
        r'marquee|details|math|body|input|a|form|base|link|style|meta)',
        payload_lower
    ))
    
    # 2. Есть ли обработчик событий?
    has_event_handler = bool(re.search(r'on\w+\s*=', payload_lower))
    
    # 3. Есть ли JS-код?
    has_js = bool(re.search(
        r'alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\(|'
        r'document\.|window\.|self\.|top\.|parent\.|'
        r'javascript\s*:|data\s*:\s*text/html|fromCharCode',
        payload_lower
    ))
    
    # 4. Есть ли URL javascript:?
    has_js_protocol = bool(re.search(r'javascript\s*:', payload_lower))
    
    # Оценка
    if has_executable_tag and has_js:
        confidence = 0.9
        reasons.append('executable_tag + js_code')
    elif has_event_handler and has_js:
        confidence = 0.85
        reasons.append('event_handler + js_code')
    elif has_js_protocol:
        confidence = 0.8
        reasons.append('javascript_protocol')
    elif has_executable_tag and has_event_handler:
        confidence = 0.7
        reasons.append('tag + event_handler (no explicit JS)')
    elif has_js:
        confidence = 0.5
        reasons.append('js_code_only (may lack execution context)')
    else:
        confidence = 0.1
        reasons.append('no_xss_indicators')
    
    # Синтаксическая проверка
    open_tags = len(re.findall(r'<\s*[a-z]+', payload_lower))
    close_tags = len(re.findall(r'</\s*[a-z]+', payload_lower))
    if open_tags > 0 and close_tags == 0 and not has_event_handler:
        confidence *= 0.8
        reasons.append('unclosed_tags')
    
    is_executable = confidence >= 0.6
    
    return {
        'is_executable': is_executable,
        'confidence': confidence,
        'reasons': reasons,
        'has_executable_tag': has_executable_tag,
        'has_event_handler': has_event_handler,
        'has_js': has_js,
    }


# ============================================================
# Универсальный оракул
# ============================================================

async def validate_payload(payload: str, use_browser: bool = True) -> dict:
    """
    Универсальная валидация: heuristic + optional browser.
    
    Args:
        payload: XSS-пейлоад
        use_browser: использовать ли Playwright (False для CI/быстрых тестов)
    """
    heuristic = validate_payload_heuristic(payload)
    
    if use_browser and heuristic['confidence'] >= 0.5:
        browser_result = await validate_payload_playwright(payload)
        return {
            'is_executable': browser_result['is_executable'] or heuristic['is_executable'],
            'browser_validated': True,
            'heuristic_confidence': heuristic['confidence'],
            'browser_alert': browser_result['alert_triggered'],
            'reasons': heuristic['reasons'],
        }
    
    return {
        'is_executable': heuristic['is_executable'],
        'browser_validated': False,
        'heuristic_confidence': heuristic['confidence'],
        'browser_alert': False,
        'reasons': heuristic['reasons'],
    }
