#!/usr/bin/env python3
import plistlib
import sys
import os

def parse_plist(plist_path, output_path):
    with open(plist_path, 'rb') as f:
        data = plistlib.load(f)

    files = data.get('files', [])
    diagnostics = data.get('diagnostics', [])

    with open(output_path, 'w') as out:
        for diag in diagnostics:
            # Получаем контекст: функция и строка
            func_name = diag.get('issue_context')
            line_num = diag.get('location', {}).get('line')
            file_id = diag.get('location', {}).get('file', 0)

            if not func_name or not line_num or file_id >= len(files):
                continue

            filename = files[file_id]

            # Записываем в конфиг
            out.write(f"[file: {filename}]\n")
            out.write(f"function: {func_name}\n")
            out.write(f"line: {line_num}\n")
            out.write("\n")

    print(f"Конфигурация сохранена в: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python3 parse_plist_to_config.py <отчёт.plist> <вывод.cfg>")
        sys.exit(1)
    parse_plist(sys.argv[1], sys.argv[2])