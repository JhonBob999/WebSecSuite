# WebSecSuite

Desktop-инструмент на PySide6 (Python 3.13), стартовая вкладка — Scraper.

## Установка
1. Python 3.13.x
2. Создать окружение:
   python -m venv .venv
   .venv\Scripts\activate
3. Зависимости:
   pip install -r requirements.txt

## Генерация UI
powershell scripts\generate_ui.ps1
(или VS Code Task: "Generate UI")

## Запуск
python main.py

## Структура
ui/           # Сгенерированные PySide6 .py + исходные .ui
  main/
  panels/
core/         # Логика (здесь будет scraper, cve, ssl и т.д.)
