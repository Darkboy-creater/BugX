import threading
import socket
from datetime import datetime


class Session:
    def __init__(self, session_id, conn, addr,
                 session_type="reverse_tcp"):
        self.id = session_id
        self.conn = conn
        self.addr = addr
        self.ip = addr[0]
        self.port = addr[1]
        self.session_type = session_type
        self.connected_at = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.is_alive = True
        self.os_info = "Unknown"
        self.hostname = "Unknown"
        self.history = []

    def send_command(self, command):
        try:
            if not self.is_alive:
                return "[!] Session is dead"
            self.conn.send(command.encode('utf-8'))
            self.conn.settimeout(10)
            response = b""
            while True:
                try:
                    chunk = self.conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(chunk) < 4096:
                        break
                except socket.timeout:
                    break
            decoded = response.decode(
                'utf-8', errors='ignore'
            )
            self.history.append({
                'cmd': command,
                'response': decoded[:500],
                'time': datetime.now().strftime(
                    "%H:%M:%S"
                )
            })
            return decoded
        except (BrokenPipeError,
                ConnectionResetError, OSError):
            self.is_alive = False
            return "[!] Connection lost"

    def check_alive(self):
        try:
            self.conn.send(b"echo alive\n")
            self.conn.settimeout(3)
            data = self.conn.recv(1024)
            if data:
                self.is_alive = True
                return True
        except:
            self.is_alive = False
        return False

    def close(self):
        try:
            self.conn.close()
        except:
            pass
        self.is_alive = False

    def get_info(self):
        return {
            'id': self.id,
            'ip': self.ip,
            'port': self.port,
            'type': self.session_type,
            'alive': self.is_alive,
            'connected': self.connected_at,
            'os': self.os_info,
            'hostname': self.hostname
        }


class SessionManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(
                        SessionManager, cls
                    ).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.sessions = {}
        self.session_counter = 0
        self.lock = threading.Lock()
        self.activity_log = []
        self._initialized = True

    def add_session(self, conn, addr,
                    session_type="reverse_tcp"):
        with self.lock:
            self.session_counter += 1
            session = Session(
                self.session_counter,
                conn, addr, session_type
            )
            self.sessions[
                self.session_counter
            ] = session
            self.activity_log.append({
                'time': datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                'event': 'NEW_SESSION',
                'details': (
                    "Session " +
                    str(self.session_counter) +
                    " from " +
                    str(addr[0]) +
                    ":" +
                    str(addr[1])
                )
            })
            return session

    def get_session(self, session_id):
        return self.sessions.get(session_id)

    def remove_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].close()
                self.activity_log.append({
                    'time': datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    'event': 'SESSION_CLOSED',
                    'details': (
                        "Session " +
                        str(session_id) +
                        " closed"
                    )
                })
                del self.sessions[session_id]
                return True
        return False

    def list_sessions(self):
        result = {}
        for sid, s in self.sessions.items():
            result[sid] = s.get_info()
        return result

    def get_alive_count(self):
        count = 0
        for s in self.sessions.values():
            if s.is_alive:
                count += 1
        return count

    def get_activity_log(self):
        return self.activity_log

    def kill_all(self):
        with self.lock:
            for sid in list(self.sessions.keys()):
                self.sessions[sid].close()
            self.sessions.clear()
            self.activity_log.append({
                'time': datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                'event': 'KILL_ALL',
                'details': 'All sessions terminated'
            })
