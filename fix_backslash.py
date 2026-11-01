path = r'd:\учёба\SSRW\xssdetector\compare_with_crs.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Считаем вхождения
count4 = content.count('\\\\\\\\')  # 4 обратных слэша
count2 = content.count('\\\\')      # 2 обратных слэша
print(f'Найдено 4 подряд: {count4}, 2 подряд: {count2}')

# Заменяем 4 на 2
content = content.replace('\\\\\\\\', '\\\\')

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print('После замены:')
count4 = content.count('\\\\\\\\')
count2 = content.count('\\\\')
print(f'4 подряд: {count4}, 2 подряд: {count2}')
print('Готово')