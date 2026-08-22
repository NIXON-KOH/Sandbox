class Log:
    # ANSI Color Codes
    COLORS = {
        'INFO': ['\033[94m', "*"],      # Blue
        'SUCCESS': ['\033[92m', "+"],   # Green
        'WARNING':[ '\033[93m', "~"],   # Yellow
        'ERROR': ['\033[91m', "-"],     # Red
        'CRITICAL': ['\033[95m', "!"],  # Magenta
        'RESET': '\033[0m',
        'BOLD': '\033[1m'
    }
    

    def _log(self, level: str, message: str, use_bold: bool = False):
        """Internal method to format and print colored messages."""
        color = self.COLORS.get(level, self.COLORS['RESET'])
        bold = self.COLORS['BOLD'] if use_bold else ''

        lvl_str = f"[{level}]"
        mx_len = 10

        print(f"{bold}{color[0]}{lvl_str:<{mx_len}} [{color[1]}] {message}{self.COLORS['RESET']}")

    def info(self, message: str):
        self._log('INFO', message)

    def success(self, message: str):
        self._log('SUCCESS', message, use_bold=True)

    def warning(self, message: str):
        self._log('WARNING', message)

    def error(self, message: str):
        self._log('ERROR', message, use_bold=True)

    def critical(self, message: str):
        self._log('CRITICAL', message, use_bold=True)

