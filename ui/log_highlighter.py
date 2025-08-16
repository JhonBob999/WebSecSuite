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

    def highlightBlock(self, text: str):
        # Уровни
        if "] [ERROR]" in text:
            self.setFormat(0, len(text), self.f_error)
        elif "] [WARN]" in text:
            self.setFormat(0, len(text), self.f_warn)
        elif "] [RESULT]" in text:
            self.setFormat(0, len(text), self.f_result)
        elif "] [INFO]" in text:
            self.setFormat(0, len(text), self.f_info)

        # Подсветим короткий task_id вида [e0f1a2b3]
        # (пробегаем и находим такие подпоследовательности)
        start = 0
        while True:
            i = text.find("[", start)
            if i < 0:
                break
            j = text.find("]", i + 1)
            if j < 0:
                break
            token = text[i:j+1]
            # [abcdef12] — восьмизначный hex?
            if len(token) == 10 and all(c in "0123456789abcdef" for c in token[1:-1].lower()):
                self.setFormat(i, j - i + 1, self.f_taskid)
            start = j + 1
            
        # --- ДОПОЛНИТЕЛЬНАЯ ПОДСВЕТКА ПОИСКА ---
        if hasattr(self, "_search_regex") and self._search_regex.isValid() and self._search_regex.pattern():
            it = self._search_regex.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), self._search_fmt)
            
    def set_pattern(self, text: str, *, regex_mode=False, case_sensitive=False):
        if not text:
            self._search_regex = QRegularExpression()
            self.rehighlight()
            return
        pattern = text if regex_mode else QRegularExpression.escape(text)
        rx = QRegularExpression(pattern)
        rx.setPatternOptions(
            QRegularExpression.NoPatternOption if case_sensitive
            else QRegularExpression.CaseInsensitiveOption
        )
        self._search_regex = rx
        self.rehighlight()