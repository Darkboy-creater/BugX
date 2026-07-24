import os
import sys
import time
import importlib
from core.colors import Colors
from core.session_mgr import SessionManager


class Console:
    def __init__(self):
        self.version = "3.0.0"
        self.session_mgr = SessionManager()
        self.modules = {
            "scanner/port_scanner": {
                "name": "Port Scanner",
                "desc": "Multi-threaded port scanner",
                "path": "modules.scanner.port_scanner"
            },
            "payload/reverse_shell": {
                "name": "Payload Generator",
                "desc": "Advanced reverse shell creator",
                "path": "modules.payload.reverse_shell"
            },
            "vuln_test/vuln_scanner": {
                "name": "Vulnerability Scanner",
                "desc": "CVE-based vuln detector",
                "path": "modules.vuln_test.vuln_scanner"
            },
            "listener/multi_handler": {
                "name": "Multi Handler",
                "desc": "Multi-client listener",
                "path": "modules.listener.multi_handler"
            },
            "web/sql_scanner": {
                "name": "SQL Injection Scanner",
                "desc": "SQLi vulnerability detector",
                "path": "modules.web.sql_scanner"
            },
            "web/xss_scanner": {
                "name": "XSS Scanner",
                "desc": "XSS vulnerability detector",
                "path": "modules.web.xss_scanner"
            },
            "web/subdomain_finder": {
                "name": "Subdomain Finder",
                "desc": "DNS brute force subdomains",
                "path": "modules.web.subdomain_finder"
            },
            "web/admin_finder": {
                "name": "Admin Panel Finder",
                "desc": "500+ admin paths checker",
                "path": "modules.web.admin_finder"
            },
            "web/dir_bruteforce": {
                "name": "Directory Bruteforcer",
                "desc": "Hidden files and dirs finder",
                "path": "modules.web.dir_bruteforce"
            },
            "web/header_check": {
                "name": "Header Checker",
                "desc": "Security headers analyzer",
                "path": "modules.web.header_check"
            },
            "web/cms_detect": {
                "name": "CMS Detector",
                "desc": "WordPress Joomla Drupal detect",
                "path": "modules.web.cms_detect"
            },
            "web/full_scan": {
                "name": "Full Web Scanner",
                "desc": "All-in-One web security scan",
                "path": "modules.web.full_scan"
            },
        }

    def banner(self):
        os.system('clear')
        alive = self.session_mgr.get_alive_count()
        total = len(self.session_mgr.sessions)
        r = Colors.RED
        re = Colors.RESET
        cy = Colors.CYAN
        ye = Colors.YELLOW
        gr = Colors.GREEN
        wh = Colors.WHITE
        print(r + """
  ████████╗███████╗██████╗ ███╗   ███╗██╗   ██╗██╗  ██╗██╗  ██╗
  ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║   ██║╚██╗██╔╝╚██╗██╔╝
     ██║   █████╗  ██████╔╝██╔████╔██║██║   ██║ ╚███╔╝  ╚███╔╝
     ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║ ██╔██╗  ██╔██╗
     ██║   ███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝██╔╝ ██╗██╔╝ ██╗
     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
        """ + re)
        print(cy + "    [ TermuxX Framework v" + self.version + " ]" + re)
        print(ye + "    [ Advanced Pentesting Toolkit ]" + re)
        print(gr + "    [ Modules: " + str(len(self.modules)) + " | Sessions: " + str(alive) + "/" + str(total) + " ]" + re)
        print(wh + "    Type help for commands" + re)
        print()

    def show_help(self):
        cy = Colors.CYAN
        gr = Colors.GREEN
        ye = Colors.YELLOW
        wh = Colors.WHITE
        re = Colors.RESET
        print(cy + """
+======================================================+
|           TERMUXX v3.0 COMMANDS                      |
+======================================================+""" + re)
        print(gr + "  help" + re + "            Show this help")
        print(gr + "  show modules" + re + "    List all modules")
        print(gr + "  use <module>" + re + "    Load and run a module")
        print(gr + "  sessions" + re + "        Show active sessions")
        print(gr + "  interact <id>" + re + "   Interact with session")
        print(gr + "  kill <id>" + re + "       Kill a session")
        print(gr + "  kill_all" + re + "        Kill all sessions")
        print(gr + "  activity" + re + "        Show activity log")
        print(gr + "  clear" + re + "           Clear screen")
        print(gr + "  exit" + re + "            Exit framework")
        print(cy + """
+======================================================+
|  WEB MODULES                                         |
+======================================================+""" + re)
        print(wh + "  use web/sql_scanner" + re)
        print(wh + "  use web/xss_scanner" + re)
        print(wh + "  use web/subdomain_finder" + re)
        print(wh + "  use web/admin_finder" + re)
        print(wh + "  use web/dir_bruteforce" + re)
        print(wh + "  use web/header_check" + re)
        print(wh + "  use web/cms_detect" + re)
        print(wh + "  use web/full_scan" + re)
        print(cy + """
+======================================================+
|  OTHER MODULES                                       |
+======================================================+""" + re)
        print(wh + "  use scanner/port_scanner" + re)
        print(wh + "  use payload/reverse_shell" + re)
        print(wh + "  use listener/multi_handler" + re)
        print(wh + "  use vuln_test/vuln_scanner" + re)
        print()

    def show_modules(self):
        print(Colors.info("\n=== AVAILABLE MODULES ===\n"))
        print("  MODULE                         NAME                     DESC")
        print("  " + "-" * 75)
        for key, info in self.modules.items():
            print(
                "  " + Colors.GREEN + key + Colors.RESET +
                " " * (30 - len(key)) +
                info['name'] +
                " " * (25 - len(info['name'])) +
                info['desc']
            )
        print()

    def show_sessions(self):
        sessions = self.session_mgr.list_sessions()
        if not sessions:
            print(Colors.warning("No active sessions!"))
            return
        print(Colors.info("\n=== SESSIONS ==="))
        print("  ID   IP                PORT    STATUS    CONNECTED")
        print("  " + "-" * 60)
        for sid, info in sessions.items():
            if info['alive']:
                sc = Colors.GREEN
                st = "ALIVE"
            else:
                sc = Colors.RED
                st = "DEAD"
            print(
                "  " + str(info['id']) +
                " " * (5 - len(str(info['id']))) +
                info['ip'] +
                " " * (18 - len(info['ip'])) +
                str(info['port']) +
                " " * (8 - len(str(info['port']))) +
                sc + st + Colors.RESET +
                " " * (10 - len(st)) +
                info['connected']
            )
        print()

    def show_activity(self):
        logs = self.session_mgr.get_activity_log()
        if not logs:
            print(Colors.warning("No activity yet."))
            return
        print(Colors.info("\n=== ACTIVITY LOG ==="))
        for log in logs[-20:]:
            if log['event'] == 'SESSION_CLOSED':
                ec = Colors.RED
            elif log['event'] == 'KILL_ALL':
                ec = Colors.YELLOW
            else:
                ec = Colors.GREEN
            print(
                "  [" + log['time'] + "] " +
                ec + "[" + log['event'] + "]" +
                Colors.RESET + " " + log['details']
            )
        print()

    def use_module(self, module_name):
        if module_name not in self.modules:
            print(Colors.error("Module not found: " + module_name))
            print(Colors.info("Type show modules to see all"))
            return
        mod_info = self.modules[module_name]
        print(Colors.info("Loading " + mod_info['name'] + "..."))
        try:
            module = importlib.import_module(mod_info['path'])
            importlib.reload(module)
            print(Colors.success("Module loaded!\n"))
            module.run()
        except ModuleNotFoundError as e:
            print(Colors.error("Module file missing: " + str(e)))
        except KeyboardInterrupt:
            print(Colors.warning("\nModule stopped."))
        except Exception as e:
            print(Colors.error("Error: " + str(e)))

    def run(self):
        self.banner()
        while True:
            try:
                alive = self.session_mgr.get_alive_count()
                if alive > 0:
                    si = "(" + Colors.GREEN + str(alive) + " sessions" + Colors.RESET + ")"
                else:
                    si = ""
                prompt = Colors.RED + "TermuxX" + Colors.RESET + " " + si + "> "
                cmd = input(prompt).strip()
                if not cmd:
                    continue
                cl = cmd.lower()

                if cl == "help":
                    self.show_help()

                elif cl == "show modules":
                    self.show_modules()

                elif cl.startswith("use "):
                    self.use_module(cmd[4:].strip())

                elif cl == "sessions":
                    self.show_sessions()

                elif cl == "activity":
                    self.show_activity()

                elif cl.startswith("interact "):
                    try:
                        sid = int(cl.split()[1])
                        from modules.listener.multi_handler import get_handler
                        handler = get_handler()
                        handler.interactive_shell(sid)
                    except Exception as e:
                        print(Colors.error("Usage: interact <id> | Error: " + str(e)))

                elif cl.startswith("kill "):
                    try:
                        sid = int(cl.split()[1])
                        if self.session_mgr.remove_session(sid):
                            print(Colors.success("Session " + str(sid) + " killed"))
                        else:
                            print(Colors.error("Session not found"))
                    except Exception as e:
                        print(Colors.error("Usage: kill <id>"))

                elif cl == "kill_all":
                    self.session_mgr.kill_all()
                    print(Colors.warning("All sessions killed."))

                elif cl == "clear":
                    os.system('clear')

                elif cl == "banner":
                    self.banner()

                elif cl in ["exit", "quit", "q"]:
                    print(Colors.warning("Shutting down..."))
                    self.session_mgr.kill_all()
                    print(Colors.success("Goodbye!"))
                    sys.exit(0)

                else:
                    print(Colors.error("Unknown command: " + cmd + " | Type help"))

            except KeyboardInterrupt:
                print(Colors.warning("\nType exit to quit."))
            except EOFError:
                sys.exit(0)
