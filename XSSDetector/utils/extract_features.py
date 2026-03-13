import re
import urllib


def extract_features1(text):
    """Извлекает 30+ признаков из HTML/JS кода"""
    features = {}

    features['text'] = text

    # Базовые признаки
    features['length'] = len(text)
    features['word_count'] = len(re.findall(r'\b\w+\b', text))

    # Бинарные признаки (категориальные для CatBoost)
    dangerous_patterns = {
        'html_has_script': r's.*c.*r.*i.*p.*t',
        'js_has_on_event': r'o.*n\w+\s*=',
        'js_has_alert': r'a.*l.*e.*r.*t',
        'js_has_prompt': r'p.*r.*o.*m.*p.*t',
        'js_has_confirm': r'c.*o.*n.*f.*i.*r.*m.*',
        'js_has_console': r'c.*o.*n.*s.*o.*l.*e',
        'has_javascript': r'j.*a.*v.*a.*s.*c.*r.*i.*p.*t.*',
        'has_vbscript': r'v.*b.*s.*c.*r.*i.*p.*t',
        # 'has_data_scheme': r'data:',
        'js_has_document': r'd.*o.*c.*u.*m.*e.*n.*t',
        'js_has_window': r'w.*i.*n.*d.*o.*w',
        'js_has_inner_html': r'i.*n.*n.*e.*r.*H.*T.*M.*L',
        'js_has_outer_html': r'o.*u.*t.*e.*r.*H.*T.*M.*L',
        'html_has_iframe': r'i.*f.*r.*a.*m.*e',
        'html_has_svg': r's.*v.*g',
        # 'has_embed': r'e.*m.*b.*e.*d',
        # 'has_applet': r'a.*p.*p.*l.*e.*t',
        'js_has_dangerous': r'f.*u.*n.*c.*t.*i.*o.*n|j.*o.*i.*n|c.*o.*n.*s.*t.*r.*u.*c.*t.*o.*r|a.*r.*r.*a.*y|o.*b.*j.*e.*c.*t|e.*v.*a.*l|f.*e.*t.*c.*h|x.*m.*l'
    }

    for name, pattern in dangerous_patterns.items():
        features[name] = 1 if re.search(pattern, text, re.IGNORECASE) else 0

    # Количественные признаки
    # features['angle_bracket_count'] = text.count('<') + text.count('>')
    # features['parenthesis_count'] = text.count('(') + text.count(')')
    features['quote_count'] = text.count('"') + text.count("'")
    # features['semicolon_count'] = text.count(';')
    features['equals_count'] = text.count('=')
    features['sum_count'] = text.count('+')

    # Признаки кодирования
    features['has_url_encoding'] = 1 if '%' in text else 0
    features['has_html_entities'] = 1 if re.search(
        r'&#?[xX]?[0-9a-fA-F]+;', text) else 0
    features['has_hex_encoding'] = len(re.findall(r'\\x[0-9a-fA-F]{2}', text))
    features['has_unicode'] = len(re.findall(r'\\u[0-9a-fA-F]{4}', text))

    # Статистические признаки
    features['special_char_ratio'] = len(re.findall(
        r'[<>\(\)\'\"=;:]', text)) / max(len(text), 1)
    # features['angle_bracket_ratio'] = features['angle_bracket_count'] / \
    #     max(len(text), 1)

    # Структурные признаки
    features['tag_count'] = len(re.findall(r'</?\w+', text))
    features['attribute_count'] = len(re.findall(r'\w+\s*=', text))
    features['comment_count'] = text.count('<!--')

    # Энтропия (мера случайности)
    if text:
        entropy = 0
        for char in set(text):
            p_x = text.count(char) / len(text)
            if p_x > 0:
                entropy += -p_x * np.log2(p_x)
        features['entropy'] = entropy
    else:
        features['entropy'] = 0

    # Контекстные признаки
    features['is_inside_quotes'] = 1 if (
        text.count('"') > 2 or text.count("'") > 2) else 0
    features['has_nested_tags'] = 1 if re.search(r'<[^>]*<', text) else 0

    return features


def extract_features2(text):
    """
    Извлекает 25 признаков безопасности из строки (URL/HTML/JS)
    на основе спецификации.

    Args:
        text: Входная строка (может содержать URL, HTML, JS код)

    Returns:
        Словарь с признаками безопасности
    """
    features = {
        'text': text
    }

    # 1. url_length - длина URL
    features['url_length'] = len(text)

    # 2. url_special_characters - специальные символы
    special_chars = r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?~`]'
    features['url_special_characters'] = len(re.findall(special_chars, text))

    # 3. url_tag_script - наличие <script> в URL
    features['url_tag_script'] = 1 if re.search(
        r'<script[^>]*>', text, re.IGNORECASE) else 0

    # 4. url_cookie - упоминания cookie в URL
    cookie_patterns = [
        r'cookie', r'session', r'token', r'auth',
        r'csrf', r'jwt', r'bearer'
    ]
    has_cookie = any(re.search(pattern, text, re.IGNORECASE)
                     for pattern in cookie_patterns)
    features['url_cookie'] = 1 if has_cookie else 0

    # 5. url_number_keywords_param - ключевые слова в параметрах
    keywords = [
        'signup', 'login', 'register', 'auth', 'authenticate',
        'query', 'search', 'filter', 'sort', 'order',
        'user', 'admin', 'password', 'secret', 'key',
        'token', 'id', 'email', 'phone', 'name'
    ]

    # Пытаемся разобрать URL
    keyword_count = 0
    try:
        parsed = urllib.parse.urlparse(text)
        query_params = urllib.parse.parse_qs(parsed.query)

        # Проверяем ключевые слова в параметрах
        for param_name in query_params.keys():
            param_lower = param_name.lower()
            for keyword in keywords:
                if keyword in param_lower:
                    keyword_count += 1
                    break

        # Проверяем ключевые слова в значениях параметров
        for param_values in query_params.values():
            for value in param_values:
                value_lower = str(value).lower()
                for keyword in keywords:
                    if keyword in value_lower:
                        keyword_count += 1
                        break
    except:
        # Если это не URL, проверяем всю строку
        text_lower = text.lower()
        for keyword in keywords:
            if keyword in text_lower:
                keyword_count += 1

    features['url_number_keywords_param'] = min(
        keyword_count, 10)  # Ограничиваем

    # 6. url_number_domain - количество доменов в URL
    domain_pattern = r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    domains = re.findall(domain_pattern, text)
    features['url_number_domain'] = len(set(domains))  # Уникальные домены

    # 7. html_tag_script - наличие <script> в HTML
    # Используем тот же признак
    features['html_tag_script'] = features['url_tag_script']

    # 8. html_tag_meta - наличие <meta>
    features['html_tag_meta'] = 1 if re.search(
        r'<meta[^>]*>', text, re.IGNORECASE) else 0

    # 9. html_tag_link - наличие <link>
    features['html_tag_link'] = 1 if re.search(
        r'<link[^>]*>', text, re.IGNORECASE) else 0

    # 10. html_tag_div - наличие <div>
    features['html_tag_div'] = 1 if re.search(
        r'<div[^>]*>', text, re.IGNORECASE) else 0

    # 11. html_tag_style - наличие <style>
    features['html_tag_style'] = 1 if re.search(
        r'<style[^>]*>', text, re.IGNORECASE) else 0

    # 12. html_attr_background - наличие атрибута background
    background_patterns = [
        r'background\s*=',
        r'style\s*=[^>]*background',
        r'bgcolor\s*='
    ]
    has_background = any(re.search(pattern, text, re.IGNORECASE)
                         for pattern in background_patterns)
    features['html_attr_background'] = 1 if has_background else 0

    # 13. html_attr_href - наличие атрибута href
    features['html_attr_href'] = 1 if re.search(
        r'href\s*=', text, re.IGNORECASE) else 0

    # 14. html_attr_src - наличие атрибута src
    features['html_attr_src'] = 1 if re.search(
        r'src\s*=', text, re.IGNORECASE) else 0

    # 15. html_event_onmouseout - наличие события onmouseout
    features['html_event_onmouseout'] = 1 if re.search(
        r'onmouseout\s*=', text, re.IGNORECASE) else 0

    # 16. js_file - ссылки на JS файлы
    js_file_patterns = [
        r'\.js\b',
        r'<script[^>]*src\s*=\s*["\'][^"\']+\.js',
        r'import.*\.js',
        r'require.*\.js'
    ]
    has_js_file = any(re.search(pattern, text, re.IGNORECASE)
                      for pattern in js_file_patterns)
    features['js_file'] = 1 if has_js_file else 0

    # 17. js_dom_location - использование location в JS
    features['js_dom_location'] = 1 if re.search(
        r'\blocation\b', text, re.IGNORECASE) else 0

    # 18. js_dom_document - использование document в JS
    features['js_dom_document'] = 1 if re.search(
        r'\bdocument\b', text, re.IGNORECASE) else 0

    # 19. js_method_getElementsByTagName - использование getElementsByTagName
    features['js_method_getElementsByTagName'] = 1 if re.search(
        r'getElementsByTagName', text, re.IGNORECASE) else 0

    # 20. js_method_getElementById - использование getElementById
    features['js_method_getElementById'] = 1 if re.search(
        r'getElementById', text, re.IGNORECASE) else 0

    # 21. js_method_alert - использование alert
    features['js_method_alert'] = 1 if re.search(
        r'\balert\s*\(', text, re.IGNORECASE) else 0

    # 22. js_min_length - минимальная длина JS строк (упрощенно)
    # Ищем строки в кавычках
    string_pattern = r'["\'`]([^"\']{1,50})["\'`]'
    strings = re.findall(string_pattern, text)

    if strings:
        min_length = min(len(s) for s in strings)
    else:
        min_length = 0

    features['js_min_length'] = min_length

    # 23. js_min_function_calls - минимальное количество вызовов функций
    # Считаем количество вызовов функций
    function_call_pattern = r'\b\w+\s*\('
    function_calls = re.findall(function_call_pattern, text)

    # Исключаем ключевые слова, которые не являются функциями
    non_function_keywords = {'if', 'else',
                             'for', 'while', 'switch', 'function'}
    valid_function_calls = [fc for fc in function_calls
                            if not any(kw in fc.lower() for kw in non_function_keywords)]

    features['js_min_function_calls'] = len(valid_function_calls)

    # 24. js_string_max_length - максимальная длина JS строк
    if strings:
        max_length = max(len(s) for s in strings)
    else:
        max_length = 0

    features['js_string_max_length'] = max_length

    # 25. html_length - длина HTML контента
    # Для чистоты, если это выглядит как HTML
    features['html_length'] = len(text) if ('<' in text and '>' in text) else 0

    return features


def extract_features(text):
    """Извлекает 80 признаков XSS из HTML/JS кода на основе исследования XSShield"""
    features = {
        'text': text
    }

    # Все 80 признаков из таблицы A.6 исследования XSShield
    # Формат: название_признака: регулярное_выражение_для_поиска
    xss_patterns = {
        # HTML теги (1-13)
        'html_tag_main': r'<main',
        'html_tag_section': r'<section',
        'html_tag_script': r'<script',
        'html_tag_iframe': r'<iframe',
        'html_tag_meta': r'<meta',
        'html_tag_link': r'<link',
        'html_tag_svg': r'<svg',
        'html_tag_form': r'<form',
        'html_tag_div': r'<div',
        'html_tag_style': r'<style',
        'html_tag_img': r'<img',
        'html_tag_input': r'<input',
        'html_tag_textarea': r'<textarea',

        # HTML атрибуты (14-21)
        'html_attr_selected': r'selected\s*=',
        'html_attr_target': r'target\s*=',
        'html_attr_class': r'class\s*=',
        'html_attr_action': r'action\s*=',
        'html_attr_background': r'background\s*=',
        'html_attr_href': r'href\s*=',
        'html_attr_src': r'src\s*=',
        'html_attr_http_equiv': r'http-equiv\s*=',

        # HTML события (22-28)
        'html_event_enhance': r'enhance\s*=',
        'html_event_onclick': r'onclick\s*=',
        'html_event_onfocus': r'onfocus\s*=',
        'html_event_onload': r'onload\s*=',
        'html_event_omouseover': r'omouseover\s*=',
        'html_event_onmouseover': r'onmouseover\s*=',
        'html_event_onsubmit': r'onsubmit\s*=',

        # HTML длина (29)
        'html_length': lambda t: len(t),

        # JS DOM объекты (30-38)
        'js_dom_document': r'document\.',
        'js_dom_window': r'window\.',
        'js_dom_navigator': r'navigator\.',
        'js_dom_location': r'location\.',
        'js_dom_localStorage': r'localStorage\.',
        'js_dom_sessionStorage': r'sessionStorage\.',
        'js_dom_history': r'history\.',
        'js_dom_console': r'console\.',
        'js_dom_alert': r'alert\(',

        # JS свойства (39-46)
        'js_prop_cookie': r'\.cookie',
        'js_prop_referrer': r'\.referrer',
        'js_prop_innerHTML': r'\.innerHTML',
        'js_prop_textContent': r'\.textContent',
        'js_prop_value': r'\.value',
        'js_prop_href': r'\.href',
        'js_prop_src': r'\.src',
        'js_prop_classList': r'\.classList',

        # JS методы (47-52)
        'js_method_getAttribute': r'\.getAttribute\(',
        'js_method_setAttribute': r'\.setAttribute\(',
        'js_method_write': r'\.write\(',
        'js_method_getElementsByTagName': r'\.getElementsByTagName\(',
        'js_method_getElementById': r'\.getElementById\(',
        'js_method_fromCharCode': r'\.fromCharCode\(',

        # JS длина строк (53-54)
        'js_min_length': lambda t: min([len(s) for s in re.findall(r'["\']([^"\']*)["\']', t)] or [0]),
        'js_max_length': lambda t: max([len(s) for s in re.findall(r'["\']([^"\']*)["\']', t)] or [0]),

        # JS функции (55-56)
        'js_define_function': r'function\s+\w+\s*\(|\w+\s*=\s*function\s*\(',
        'js_function_calls': len(re.findall(r'\w+\s*\(', text)),

        # JS файлы и протоколы (57-58)
        'js_file': r'\.js["\']',
        'js_pseudo_protocol': r'javascript:|data:|vbscript:',

        # URL признаки (59-68) - теги в URL
        'url_length': lambda t: len(t),
        'url_tag_script': r'script',
        'url_tag_iframe': r'iframe',
        'url_tag_link': r'link',
        'url_tag_frame': r'frame',
        'url_tag_form': r'form',
        'url_tag_style': r'style',
        'url_tag_video': r'video',
        'url_tag_img': r'img',
        'url_tag_main': r'main',

        # URL признаки (69-70) - дополнительные теги
        'url_tag_section': r'section',
        'url_tag_article': r'article',

        # URL атрибуты (71-73)
        'url_attr_action': r'action',
        'url_attr_data': r'data',
        'url_attr_src': r'src',

        # URL события (74-76)
        'url_event_onerror': r'onerror',
        'url_event_onload': r'onload',
        'url_event_onmouseover': r'onmouseover',

        # URL параметры и ключевые слова (77-78)
        'url_keywords_param': r'[\?&]\w+=',
        'url_keywords_evil': r'(alert|prompt|confirm|eval|script|iframe)',

        # URL дополнительные признаки (79-80)
        'url_cookie': r'cookie',
        'url_number_domain': len(re.findall(r'https?://([\w\.]+)', text))
    }

    # Извлекаем все признаки
    for feature_name, pattern in xss_patterns.items():
        if callable(pattern):
            # Если это функция (лямбда), вызываем её
            features[feature_name] = pattern(text)
        elif feature_name in ['js_function_calls', 'url_number_domain']:
            # Эти уже посчитаны в словаре
            features[feature_name] = pattern
        else:
            # Регулярное выражение - ищем совпадения
            if isinstance(pattern, int):
                features[feature_name] = pattern
            else:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if feature_name in ['js_min_length', 'js_max_length']:
                    features[feature_name] = matches if matches else 0
                else:
                    features[feature_name] = len(matches)

    return features
