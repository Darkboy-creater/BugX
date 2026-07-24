class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @staticmethod
    def success(text):
        return Colors.GREEN + "[+] " + text + Colors.RESET

    @staticmethod
    def error(text):
        return Colors.RED + "[-] " + text + Colors.RESET

    @staticmethod
    def info(text):
        return Colors.CYAN + "[*] " + text + Colors.RESET

    @staticmethod
    def warning(text):
        return Colors.YELLOW + "[!] " + text + Colors.RESET

    @staticmethod
    def input_prompt(text):
        return Colors.PURPLE + "[?] " + text + Colors.RESET
