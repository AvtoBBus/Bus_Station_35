path = r'd:\учёба\SSRW\xssdetector\compare_with_crs.py'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "941410" in line or "941420" in line:
        # Заменяем \u на \\u и \x на \\x в этих строках
        line = line.replace(r"'\u", r"'\\u")
        line = line.replace(r"'\x", r"'\\x")
    new_lines.append(line)

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
print('Готово')