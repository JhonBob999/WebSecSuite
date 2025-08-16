#Класс Хайлайтер
# ui/log_highlighter.py
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PySide6.QtCore import Qt, QRegularExpression



class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        # Форматы
        self.f_info = QTextCharFormat()
        self.f_info.setForeground(QColor("#A0A0A0"))  # мягкий серый

        self.f_warn = QTextCharFormat()
        self.f_warn.setForeground(QColor("#C8A200"))  # жёлто-янтарный
        self.f_warn.setFontWeight(QFont.Bold)

        self.f_error = QTextCharFormat()
        self.f_error.setForeground(QColor("#E05A5A"))  # красный
        self.f_error.setFontWeight(QFont.Bold)

        self.f_result = QTextCharFormat()
        self.f_result.setForeground(QColor("#3CC3D3"))  # бирюзовый
        self.f_result.setFontWeight(QFont.DemiBold)

        self.f_taskid = QTextCharFormat()
        self.f_taskid.setForeground(QColor("#808080"))  # серый для [abcd1234]
        
        self._search_regex = QRegularExpression()
        self._search_fmt = QTextCharFormat()
        self._search_fmt.setBackground(QColor(255, 255, 0, 100))
        
        # 👇 для навигации
        self._match_ranges: list[tuple[int,int]] = []
        self._match_idx: int = -1

    def highlightBlock(self, text: str):
        # --- Подсветка уровней ---
        if "] [ERROR]" in text:
            self.setFormat(0, len(text), self.f_error)
        elif "] [WARN]" in text:
            self.setFormat(0, len(text), self.f_warn)
        elif "] [RESULT]" in text:
            self.setFormat(0, len(text), self.f_result)
        elif "] [INFO]" in text:
            self.setFormat(0, len(text), self.f_info)

        # --- Подсветка короткого task_id вида [e0f1a2b3] ---
        start = 0
        while True:
            i = text.find("[", start)
            if i < 0:
                break
            j = text.find("]", i + 1)
            if j < 0:
                break
            token = text[i:j + 1]
            # [abcdef12] — восьмизначный hex?
            if len(token) == 10 and all(c in "0123456789abcdef" for c in token[1:-1].lower()):
                self.setFormat(i, j - i + 1, self.f_taskid)
            start = j + 1

        # --- Доп. подсветка поиска + сбор абсолютных диапазонов ---
        # ВАЖНО: self._match_ranges должен очищаться ДО rehighlight() (в set_search)
        if hasattr(self, "_search_regex") and self._search_regex.isValid() and self._search_regex.pattern():
            block_pos = self.currentBlock().position()  # абсолютное смещение начала блока
            it = self._search_regex.globalMatch(text)
            while it.hasNext():
                m = it.next()
                s, ln = m.capturedStart(), m.capturedLength()
                # локальная подсветка
                self.setFormat(s, ln, self._search_fmt)
                # накопление абсолютных диапазонов для навигации
                if hasattr(self, "_match_ranges"):
                    self._match_ranges.append((block_pos + s, block_pos + s + ln))

            
    def set_search(self, text: str, *, regex_mode: bool = False, case_sensitive: bool = False, whole_word: bool = False):
        # сбрасываем прошлые совпадения
        self._match_ranges.clear()
        self._match_idx = -1

        if not text:
            self._search_regex = QRegularExpression()
            self.rehighlight()
            return

        if regex_mode:
            # если пользователь явно ввёл regex — не экранируем
            pattern = text
            if whole_word:
                # оборачиваем как слово: \b(?:...)\b
                pattern = r"\b(?:" + pattern + r")\b"
        else:
            # обычный текст → экранируем
            pattern = QRegularExpression.escape(text)
            if whole_word:
                pattern = r"\b" + pattern + r"\b"

        rx = QRegularExpression(pattern)
        rx.setPatternOptions(
            QRegularExpression.NoPatternOption if case_sensitive
            else QRegularExpression.CaseInsensitiveOption
        )
        self._search_regex = rx
        self._match_ranges.clear()
        self._match_idx = -1
        self.rehighlight()

    def get_match_ranges(self) -> list[tuple[int,int]]:
        return list(self._match_ranges)

    @property
    def match_count(self) -> int:
        return len(self._match_ranges)

    def next_match(self):
        n = len(self._match_ranges)
        if n == 0:
            self._match_idx = -1
            return (-1, 0)
        self._match_idx = (self._match_idx + 1) % n
        return (self._match_idx, n)

    def prev_match(self):
        n = len(self._match_ranges)
        if n == 0:
            self._match_idx = -1
            return (-1, 0)
        self._match_idx = (self._match_idx - 1) % n
        return (self._match_idx, n)