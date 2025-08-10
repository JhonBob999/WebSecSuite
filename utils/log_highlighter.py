# utils/log_highlighter.py
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor
from PySide6.QtCore import QRegularExpression

class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self._regex = QRegularExpression()
        self._fmt = QTextCharFormat()
        # Мяглая жёлтая подложка; можно поменять при желании
        self._fmt.setBackground(QColor(255, 255, 0, 100))

    def set_pattern(self, text: str, *, regex_mode: bool = False, case_sensitive: bool = False):
        """Установить паттерн для подсветки. Пустая строка — очистка подсветки."""
        if not text:
            self._regex = QRegularExpression()
            self.rehighlight()
            return

        pattern = text if regex_mode else QRegularExpression.escape(text)
        rx = QRegularExpression(pattern)
        rx.setPatternOptions(
            QRegularExpression.NoPatternOption if case_sensitive
            else QRegularExpression.CaseInsensitiveOption
        )
        self._regex = rx
        self.rehighlight()

    def highlightBlock(self, text: str):
        if not self._regex.isValid() or not self._regex.pattern():
            return
        it = self._regex.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt)
