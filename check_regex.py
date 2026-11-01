import re
import ast

path = r'd:\учёба\SSRW\xssdetector\compare_with_crs.py'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 'CRS_XSS_RULES' in line or ('941' in line and "r'" in line):
        try:
            tree = ast.parse(line)
            for node in ast.walk(tree):
                if isinstance(node, ast.Tuple):
                    for elt in node.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            val = elt.value
                            if '<' in val or '\\' in val or '(' in val:
                                try:
                                    re.compile(val)
                                    print(f'LINE {i+1} OK: {val[:60]}')
                                except Exception as e:
                                    print(f'LINE {i+1} BAD: {val[:60]} -> {e}')
        except Exception:
            pass
print('Done checking')