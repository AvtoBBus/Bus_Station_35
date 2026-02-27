
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from catboost import CatBoostClassifier, Pool, cv
from sklearn.model_selection import train_test_split, StratifiedKFold
import re
import sys
import csv
from download_datasets import create_comprehensive_xss_dataset

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score


class XSSLearnDetector:
    """Класс для детектирования XSS с мониторингом"""

    def __init__(self, model_path=None):
        if model_path:
            self.model, self.metadata = self.load_model()
        else:
            self.model = None
            self.metadata = None

        # Статистика использования
        self.stats = {
            'total_predictions': 0,
            'xss_detected': 0,
            'false_positives': 0,
            'false_negatives': 0
        }

    def train(self, csv_file):
        """Обучение модели"""
        self.model, _ = full_training_pipeline(csv_file)

    def predict(self, code, threshold=0.5):
        """Предсказание с порогом"""
        if not self.model:
            raise ValueError("Модель не обучена!")

        self.stats['total_predictions'] += 1

        result = self.predict_xss(self.model, code, self.metadata)

        # Применяем порог
        final_prediction = result['probability'] >= threshold

        # Обновляем статистику
        if final_prediction:
            self.stats['xss_detected'] += 1

        return {
            'prediction': final_prediction,
            'probability': result['probability'],
            'details': result
        }

    def save_model(self, model, feature_names, cat_features, scaler=None):
        """Сохраняет модель и метаданные"""

        model_filename = "./model/catboost_xss_model.cbm"
        metadata_filename = "./model/model_metadata.pkl"

        # Сохраняем модель
        model.save_model(model_filename)

        # Сохраняем метаданные
        metadata = {
            'feature_names': list(feature_names),
            'cat_features': cat_features,
            'model_type': 'CatBoost',
            'version': '1.0'
        }

        joblib.dump(metadata, metadata_filename)

        if scaler:
            joblib.dump(scaler, 'scaler.pkl')

        print("💾 Модель сохранена:")
        print(f"  - {model_filename} (модель)")
        print(f"  - {metadata_filename} (метаданные)")

        return model_filename, metadata_filename

    def load_model(self):
        """Загружает модель и метаданные"""
        model = CatBoostClassifier()
        model.load_model('catboost_xss_model.cbm')
        metadata = joblib.load('model_metadata.pkl')

        print("📤 Модель загружена")
        return model, metadata

    def predict_xss(self, model, text, metadata):
        """Предсказывает XSS для нового кода"""

        # Извлекаем признаки
        features = extract_features(text)
        features_df = pd.DataFrame([features])

        # Убеждаемся, что порядок признаков правильный
        features_df = features_df[metadata['feature_names']]

        # Преобразуем категориальные признаки
        for col in metadata['cat_features']:
            if col in features_df.columns:
                features_df[col] = features_df[col].astype('category')

        # Предсказание
        prediction = model.predict(features_df)[0]
        probability = model.predict_proba(features_df)[0][1]

        # Интерпретация
        result = {
            'text': text[:100] + '...' if len(text) > 100 else text,
            'is_xss': bool(prediction),
            'probability': float(probability),
            'risk_level': 'HIGH' if probability > 0.7 else 'MEDIUM' if probability > 0.3 else 'LOW'
        }

        # Детальный анализ
        if probability > 0.5:
            # Анализируем, какие признаки вызвали срабатывание
            feature_importance = model.get_feature_importance(
                data=Pool(features_df, cat_features=metadata['cat_features']),
                type='PredictionValuesChange'
            )

            top_features_idx = np.argsort(feature_importance)[-3:][::-1]
            top_features = []
            for idx in top_features_idx:
                if feature_importance[idx] > 0:
                    top_features.append(
                        f"{metadata['feature_names'][idx]}: {features[metadata['feature_names'][idx]]}"
                    )

            result['triggered_features'] = top_features

        return result

    def batch_predict(self, model, texts, metadata):
        """Пакетное предсказание"""
        results = []
        for text in texts:
            results.append(self.predict_xss(model, text, metadata))
        return pd.DataFrame(results)

    def evaluate_on_dataset(self, test_csv, threshold=0.5):
        """Оценка на тестовом датасете"""
        test_df = pd.read_csv(test_csv)

        predictions = []
        probabilities = []

        for text in test_df['text']:
            result = self.predict(text, threshold)
            predictions.append(result['prediction'])
            probabilities.append(result['probability'])

        y_true = test_df['label'].values
        y_pred = np.array(predictions)

        print("\n📊 Оценка на тестовом датасете:")
        print(classification_report(y_true, y_pred))
        print(f"AUC: {roc_auc_score(y_true, probabilities):.4f}")

        # Обновляем статистику ошибок
        cm = confusion_matrix(y_true, y_pred)
        self.stats['false_positives'] += cm[0, 1]
        self.stats['false_negatives'] += cm[1, 0]

        return classification_report(y_true, y_pred, output_dict=True)

    def get_stats(self):
        """Получить статистику"""
        return self.stats.copy()


class XSSTestDetector:
    """Класс для детектирования XSS с загруженной моделью"""

    def __init__(self, model_path='catboost_xss_model.cbm',
                 metadata_path='model_metadata.pkl'):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self.model = None
        self.metadata = None
        self.load_model()

    def load_model(self):
        """Загружает модель из файлов"""
        try:
            # Загружаем CatBoost модель
            self.model = CatBoostClassifier()
            self.model.load_model(self.model_path)

            # Загружаем метаданные
            self.metadata = joblib.load(self.metadata_path)

            print(f"✅ Модель успешно загружена")
            print(f"   Признаков: {len(self.metadata['feature_names'])}")
            print(
                f"   Категориальных: {len(self.metadata.get('cat_features', []))}")

        except Exception as e:
            print(f"❌ Ошибка загрузки модели: {e}")
            raise

    def prepare_features(self, features_dict):
        """Подготовка признаков для модели"""
        # Создаем DataFrame
        features_df = pd.DataFrame([features_dict])

        # Убеждаемся в правильном порядке признаков
        expected_features = self.metadata['feature_names']
        for feature in expected_features:
            if feature not in features_df.columns:
                features_df[feature] = 0  # Заполняем недостающие нулями

        features_df = features_df[expected_features]

        # Преобразуем категориальные признаки
        cat_features = self.metadata.get('cat_features', [])
        for col in cat_features:
            if col in features_df.columns:
                features_df[col] = features_df[col].astype('category')

        return features_df

    def predict(self, code, threshold=0.5):
        """
        Предсказывает, является ли код XSS

        Args:
            code (str): HTML/JS код для проверки
            threshold (float): Порог вероятности (0.5 по умолчанию)

        Returns:
            dict: Результат предсказания
        """
        if self.model is None:
            raise ValueError("Модель не загружена!")

        # 1. Извлекаем признаки
        features = extract_features(code)

        # 2. Подготавливаем для модели
        features_df = self.prepare_features(features)

        # 3. Делаем предсказание
        prediction = self.model.predict(features_df)[0]
        probability = self.model.predict_proba(features_df)[0][1]

        # 4. Применяем порог
        is_xss = probability >= threshold

        return {
            'is_xss': bool(is_xss),
            'probability': float(probability),
            'prediction': prediction,
            'threshold': threshold,
            'code_sample': code[:100] + '...' if len(code) > 100 else code,
            'risk_level': self._get_risk_level(probability),
            'features': self._get_top_features(features_df, features)
        }

    def predict_batch(self, codes, threshold=0.5):
        """Пакетное предсказание"""
        results = []
        for code in codes:
            results.append(self.predict(code, threshold, return_details=True))
        return pd.DataFrame(results)

    def _get_risk_level(self, probability):
        """Определяет уровень риска"""
        if probability >= 0.8:
            return "CRITICAL"
        elif probability >= 0.6:
            return "HIGH"
        elif probability >= 0.4:
            return "MEDIUM"
        elif probability >= 0.2:
            return "LOW"
        else:
            return "SAFE"

    def _get_top_features(self, features_df, original_features):
        """Возвращает топ признаков, повлиявших на решение"""
        try:
            # Получаем важность признаков для этого конкретного предсказания
            shap_values = self.model.get_feature_importance(
                data=features_df,
                type='PredictionValuesChange'
            )

            # Сортируем по важности
            feature_names = self.metadata['feature_names']
            important = []

            for idx in np.argsort(shap_values)[-5:][::-1]:
                if shap_values[idx] > 0:
                    feature_name = feature_names[idx]
                    feature_value = original_features.get(feature_name, 0)
                    important.append(f"{feature_name}={feature_value}")

            return important
        except:
            return []

    def get_model_info(self):
        """Информация о модели"""
        if self.model is None:
            return "Модель не загружена"

        info = {
            'model_type': 'CatBoost',
            'feature_count': len(self.metadata['feature_names']),
            'cat_features': len(self.metadata.get('cat_features', [])),
            'tree_count': self.model.tree_count_ if hasattr(self.model, 'tree_count_') else 'N/A',
            'classes': list(self.model.classes_) if hasattr(self.model, 'classes_') else [0, 1]
        }

        return info


def extract_features(text):
    """Извлекает 30+ признаков из HTML/JS кода"""
    features = {}

    # Базовые признаки
    features['length'] = len(text)
    features['word_count'] = len(re.findall(r'\b\w+\b', text))

    # Бинарные признаки (категориальные для CatBoost)
    dangerous_patterns = {
        'has_script': r's.*c.*r.*i.*p.*t',
        'has_on_event': r'o.*n\w+\s*=',
        'has_alert': r'a.*l.*e.*r.*t',
        'has_prompt': r'p.*r.*o.*m.*p.*t',
        'has_confirm': r'c.*o.*n.*f.*i.*r.*m.*',
        'has_console': r'c.*o.*n.*s.*o.*l.*e',
        'has_javascript': r'j.*a.*v.*a.*s.*c.*r.*i.*p.*t.*',
        'has_vbscript': r'v.*b.*s.*c.*r.*i.*p.*t',
        # 'has_data_scheme': r'data:',
        'has_document': r'd.*o.*c.*u.*m.*e.*n.*t',
        'has_window': r'w.*i.*n.*d.*o.*w',
        'has_inner_html': r'i.*n.*n.*e.*r.*H.*T.*M.*L',
        'has_outer_html': r'o.*u.*t.*e.*r.*H.*T.*M.*L',
        'has_iframe': r'i.*f.*r.*a.*m.*e',
        'has_svg': r's.*v.*g',
        # 'has_embed': r'e.*m.*b.*e.*d',
        # 'has_applet': r'a.*p.*p.*l.*e.*t',
        'has_dangerous_js': r'f.*u.*n.*c.*t.*i.*o.*n|j.*o.*i.*n|c.*o.*n.*s.*t.*r.*u.*c.*t.*o.*r|a.*r.*r.*a.*y|o.*b.*j.*e.*c.*t|e.*v.*a.*l|f.*e.*t.*c.*h|x.*m.*l'
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
    # features['special_char_ratio'] = len(re.findall(
    #     r'[<>\(\)\'\"=;:]', text)) / max(len(text), 1)
    # features['angle_bracket_ratio'] = features['angle_bracket_count'] / \
    #     max(len(text), 1)

    # Структурные признаки
    features['tag_count'] = len(re.findall(r'</?\w+', text))
    features['attribute_count'] = len(re.findall(r'\w+\s*=', text))
    # features['comment_count'] = text.count('<!--')

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


def load_and_prepare_data(csv_file, with_label: bool = True):
    """Загружает CSV и преобразует в признаки"""
    print("📥 Загрузка данных...")
    df = pd.read_csv(csv_file)

    print("🔧 Извлечение признаков...")
    features_list = []
    for i, text in enumerate(df['text']):
        if i % 500 == 0:
            print(f"  Обработано {i}/{len(df)}...")
        features_list.append(extract_features(text))

    X = pd.DataFrame(features_list)
    y = df['label'].values if with_label else None

    print(
        f"✅ Данные подготовлены: {X.shape[0]} примеров, {X.shape[1]} признаков")
    if with_label:
        print(
            f"📊 Распределение классов: {y.sum()} XSS, {len(y)-y.sum()} нормальных")

    return X, y


def get_categorical_features(X: pd.DataFrame):
    """Определяет, какие признаки категориальные"""
    categorical = []

    for col in X.columns:
        if X[col].nunique() <= 5 and set(X[col].unique()).issubset({0, 1}):
            categorical.append(col)

    print(f"🎯 Категориальные признаки ({len(categorical)}): {categorical}")
    return categorical


def train_with_cross_validation(X, y, cat_features):
    """Обучает CatBoost с кросс-валидацией"""

    # Создаем Pool для CatBoost
    pool = Pool(data=X, label=y, cat_features=cat_features)

    # Параметры модели
    params = {
        'iterations': 100000,
        'depth': 6,
        'learning_rate': 0.05,
        'loss_function': 'Logloss',
        'verbose': 100,
        'random_seed': 42,
        'task_type': 'GPU',
        'eval_metric': 'AUC',
        'early_stopping_rounds': 50,
        'use_best_model': True,
        'bootstrap_type': 'Bernoulli',
        'subsample': 0.8,
        'l2_leaf_reg': 3,
        'metric_period': 50,
        'devices': '0:1'
    }

    print("🔄 Начинаю кросс-валидацию...")

    # 5-фолдная кросс-валидация
    cv_data = cv(
        pool=pool,
        params=params,
        fold_count=5,
        shuffle=True,
        partition_random_seed=42,
        stratified=True,
        verbose=False
    )

    # Выводим результаты CV
    print("\n📊 Результаты кросс-валидации:")
    print(f"Лучшая AUC на валидации: {cv_data['test-AUC-mean'].max():.4f}")
    print(
        f"Среднее AUC: {cv_data['test-AUC-mean'].mean():.4f} ± {cv_data['test-AUC-std'].mean():.4f}")

    return cv_data, params


def train_final_model(X, y, cat_features, params):
    """Обучает финальную модель на всех данных"""

    print('\n\n\n', cat_features, '\n\n\n')

    # Разделяем на train/validation
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Создаем Pool
    train_pool = Pool(X_train, y_train, cat_features=cat_features)
    val_pool = Pool(X_val, y_val, cat_features=cat_features)

    print("🚀 Обучение финальной модели...")

    # Инициализируем модель
    model = CatBoostClassifier(**params)

    # Обучаем с валидацией
    model.fit(
        train_pool,
        eval_set=val_pool,
        verbose=100,
        plot=True  # Построит график обучения
    )

    # Оценка на валидации
    y_pred = model.predict(X_val)
    y_pred_proba = model.predict_proba(X_val)[:, 1]

    print("\n📈 Метрики на валидационной выборке:")
    print(classification_report(y_val, y_pred))
    print(f"AUC: {roc_auc_score(y_val, y_pred_proba):.4f}")

    # Матрица ошибок
    cm = confusion_matrix(y_val, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Матрица ошибок')
    plt.ylabel('Истинные значения')
    plt.xlabel('Предсказанные значения')
    plt.savefig('./confusion_matrix.png')

    return model


def analyze_feature_importance(model, X):
    """Анализирует важность признаков"""

    # Получаем важность признаков
    feature_importance = model.get_feature_importance()
    feature_names = X.columns

    # Создаем DataFrame
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': feature_importance
    }).sort_values('importance', ascending=False)

    # Визуализация
    plt.figure(figsize=(12, 8))
    plt.barh(range(len(importance_df)), importance_df['importance'])
    plt.yticks(range(len(importance_df)), importance_df['feature'])
    plt.xlabel('Важность')
    plt.title('Важность признаков (CatBoost)')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig('./features.png')

    return importance_df


def full_training_pipeline(csv_file='xss_dataset.csv'):
    """Полный пайплайн от данных до модели"""

    print("=" * 60)
    print("🚀 ЗАПУСК ПОЛНОГО ПАЙПЛАЙНА ОБУЧЕНИЯ CATBOOST")
    print("=" * 60)

    learn_detector = XSSLearnDetector()

    # Шаг 1: Подготовка данных
    X, y = load_and_prepare_data(csv_file)

    # Шаг 2: Определение категориальных признаков
    cat_features = get_categorical_features(X)

    # Шаг 3: Кросс-валидация для подбора параметров
    cv_results, best_params = train_with_cross_validation(X, y, cat_features)

    # Шаг 4: Финальное обучение
    model = train_final_model(X, y, cat_features, best_params)

    # Шаг 5: Анализ важности признаков
    importance_df = analyze_feature_importance(model, X)

    # Шаг 6: Сохранение модели
    model_filename, metadata_filename = learn_detector.save_model(
        model, X.columns, cat_features)

    # Шаг 7: Тестирование на примерах
    print("\n🧪 Тестирование модели на примерах:")

    test_cases = [
        "<script>alert('XSS')</script>",
        "<div>Hello World</div>",
        "<img src=x onerror=alert(1)>",
        "<p>Normal paragraph</p>",
        "<svg onload=alert(document.cookie)>",
        "<a href='/about'>About</a>"
    ]

    metadata = {'feature_names': list(X.columns), 'cat_features': cat_features}

    for test in test_cases:
        result = learn_detector.predict_xss(model, test, metadata)
        print(f"\n📝 {result['text']}")
        print(
            f"   XSS: {result['is_xss']} | Вероятность: {result['probability']:.2%} | Риск: {result['risk_level']}")
        if 'triggered_features' in result:
            print(f"   Причины: {', '.join(result['triggered_features'])}")

    print("\n" + "=" * 60)
    print("✅ ОБУЧЕНИЕ ЗАВЕРШЕНО!")
    print("=" * 60)

    return model, importance_df, metadata, model_filename, metadata_filename


def main():

    if len(sys.argv) < 3:
        return

    train_filename = sys.argv[1]
    test_filename = sys.argv[2]

    # dataset_path = create_comprehensive_xss_dataset(
    #     train_filename, 'datasets_train')

    print("\n" + "="*60)
    print("НАЧАЛО ОБУЧЕНИЯ МОДЕЛИ DETECT XSS")
    print("="*60 + "\n")

    # Полный пайплайн
    model, importance, metadata, model_filename, metadata_filename = full_training_pipeline(
        train_filename)

    # Инициализируем детектор
    learn_detector = XSSLearnDetector()
    learn_detector.model = model
    learn_detector.metadata = metadata

    # Тестируем
    test_codes = [
        "Normal HTML:_|_<div class='test'>Hello</div>",
        "XSS:_|_<script>alert('hacked')</script>",
        "Tricky:_|_<img src='x' onerror='javascript:alert(1)'>",
        "Encoded:_|_%3Cscript%3Ealert('xss')%3C/script%3E"
    ]

    print("\n🧪 Тестовые предсказания:")
    for code in test_codes:
        result = learn_detector.predict_xss(
            model, code.split('_|_')[-1], metadata)
        print(f"\n📝 {result['text']}")
        print(
            f"   XSS: {result['is_xss']} | Вероятность: {result['probability']:.2%} | Риск: {result['risk_level']}")
        if 'triggered_features' in result:
            print(f"   Причины: {', '.join(result['triggered_features'])}")

    test_detector = XSSTestDetector(model_filename, metadata_filename)

    print("\n🧪 Тестирование на большом наборе данных:")

    df = None
    print("📥 Загрузка данных...")
    with open(test_filename, 'r', encoding='utf-8') as f:
        df = pd.read_csv(f)

    print("🧪 Тестирование...")

    with open('test_result.csv', 'w', encoding='utf-8', newline='') as file:
        writer = csv.writer(file, delimiter=";")

        writer.writerow([
            "Входная строка",
            "XSS",
            "Вероятность",
            "Риск",
        ])

        for i, text in enumerate(df['text']):
            result = test_detector.predict(text, 0.35)

            writer.writerow([
                text,
                f"{result['is_xss']}",
                f"{result['probability']:.2%}",
                result['risk_level'],
            ])
    print("\n\nЗавершено\n\n")


# ./VulnXSS-main/payloads/100_payload.txt
# ./VulnXSS-main/payloads/best_payload(1500).txt
# ./VulnXSS-main/payloads/xss-payload-list(6k).txt

# python .\main.py './VulnXSS-main/payloads/xss-payload-list(6k).txt' './VulnXSS-main/payloads/best_payload(1500).txt'
# python .\main.py './VulnXSS-main/payloads/xss-payload-list(6k).txt' XSS_dataset.csv
# python .\main.py XSS_dataset.csv './datasets_test/xss_dataset.csv'
if __name__ == "__main__":
    main()
