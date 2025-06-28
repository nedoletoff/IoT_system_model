import sqlite3
import json
import bcrypt
from datetime import datetime, timedelta
import logger

log = logger.init_logger('database', 'logs/database.log')


class Database:
    _instance = None

    def __new__(cls, path='iot_system.db'):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.conn = sqlite3.connect(path, check_same_thread=False)
            cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        cursor = self.conn.cursor()

        # Create tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            port INTEGER NOT NULL,
            secret_key BLOB NOT NULL,
            state TEXT,
            compromised BOOLEAN DEFAULT 0,
            gateway_id TEXT,
            last_seen TIMESTAMP
        )''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS gateways (
            id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            secret_key BLOB NOT NULL,
            cloud_host TEXT,
            cloud_port INTEGER,
            last_seen TIMESTAMP
        )''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            gateway_id TEXT NOT NULL,
            user_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0
        )''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            source TEXT,
            target TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Add users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Add user tokens table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_tokens (
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            gateway_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')

        self.conn.commit()

        # Create default admin user
        try:
            self.create_user('admin', 'admin123', is_admin=True)
        except:
            pass  # Admin already exists

    def log_event(self, event_type, source, target, details):
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO events (type, source, target, details) 
        VALUES (?, ?, ?, ?)
        ''', (event_type, source, target, details))
        self.conn.commit()

    def add_device(self, device_id, device_type, port, secret_key, gateway_id=None):
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT OR REPLACE INTO devices (id, type, port, secret_key, state, gateway_id) 
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (device_id, device_type, port, secret_key, json.dumps({}), gateway_id))
        self.conn.commit()

    def get_device(self, device_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'type': row[1],
                'port': row[2],
                'secret_key': row[3],
                'state': json.loads(row[4]) if row[4] else {},
                'compromised': bool(row[5]),
                'gateway_id': row[6],
                'last_seen': row[7]
            }
        return None

    def update_device_state(self, device_id, state):
        cursor = self.conn.cursor()
        cursor.execute('''
        UPDATE devices SET state = ?, last_seen = CURRENT_TIMESTAMP 
        WHERE id = ?
        ''', (json.dumps(state), device_id))
        self.conn.commit()

    def mark_device_compromised(self, device_id):
        cursor = self.conn.cursor()
        cursor.execute('UPDATE devices SET compromised = 1 WHERE id = ?', (device_id,))
        self.conn.commit()

    def add_gateway(self, gateway_id, host, port, secret_key, cloud_host, cloud_port):
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT OR REPLACE INTO gateways (id, host, port, secret_key, cloud_host, cloud_port) 
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (gateway_id, host, port, secret_key, cloud_host, cloud_port))
        self.conn.commit()

    def get_gateway(self, gateway_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM gateways WHERE id = ?', (gateway_id,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'host': row[1],
                'port': row[2],
                'secret_key': row[3],
                'cloud_host': row[4],
                'cloud_port': row[5],
                'last_seen': row[6]
            }
        return None

    def add_token(self, token, gateway_id, expires_hours: timedelta = 24, is_admin=False):
        log.info(f'add token {token=} {gateway_id=} {expires_hours=}')
        expires_at = datetime.now() + expires_hours
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO tokens (token, gateway_id, expires_at, is_admin) 
        VALUES (?, ?, ?, ?)
        ''', (token, gateway_id, expires_at.isoformat(), int(is_admin)))
        log.info(f'added token {token=} {gateway_id=} {expires_hours=}')
        self.conn.commit()

    def validate_token(self, token):
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT * FROM tokens 
        WHERE token = ? AND datetime(expires_at) > datetime('now')
        ''', (token,))
        row = cursor.fetchone()
        if row:
            return {
                'token': row[0],
                'gateway_id': row[1],
                'user_id': row[2],
                'created_at': row[3],
                'expires_at': row[4],
                'is_admin': bool(row[5])
            }
        return None

    def create_user(self, username, password, is_admin=False):
        cursor = self.conn.cursor()
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
        INSERT INTO users (username, password, is_admin) 
        VALUES (?, ?, ?)
        ''', (username, hashed, int(is_admin)))
        self.conn.commit()

    def get_user(self, username):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'username': row[1],
                'password': row[2],
                'is_admin': bool(row[3]),
                'created_at': row[4]
            }
        return None

    def get_user_by_id(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'username': row[1],
                'password': row[2],
                'is_admin': bool(row[3]),
                'created_at': row[4]
            }
        return None

    def verify_user(self, username, password):
        user = self.get_user(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return user
        return None

    def add_user_token(self, user_id, token, gateway_id, expires_hours: timedelta = 24):
        self.add_token(token, gateway_id, expires_hours, is_admin=False)
        expires_at = datetime.now() + expires_hours
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO user_tokens (user_id, token, gateway_id, expires_at) 
        VALUES (?, ?, ?, ?)
        ''', (user_id, token, gateway_id, expires_at.isoformat()))
        self.conn.commit()
        log.info(f'added user token {user_id=} {token=} {gateway_id=}')

    def get_user_tokens(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT * FROM user_tokens 
        WHERE user_id = ? AND datetime(expires_at) > datetime('now')
        ''', (user_id,))
        return [
            {
                'token': row[1],
                'gateway_id': row[2],
                'created_at': row[3],
                'expires_at': row[4]
            }
            for row in cursor.fetchall()
        ]

    def get_all_users(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users')
        return [
            {
                'id': row[0],
                'username': row[1],
                'is_admin': bool(row[3]),
                'created_at': row[4]
            }
            for row in cursor.fetchall()
        ]

    def get_all_tokens(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT u.username, t.token, t.gateway_id, t.created_at, t.expires_at 
        FROM user_tokens t
        JOIN users u ON t.user_id = u.id
        ''')
        return [
            {
                'username': row[0],
                'token': row[1],
                'gateway_id': row[2],
                'created_at': row[3],
                'expires_at': row[4]
            }
            for row in cursor.fetchall()
        ]

    def get_devices_for_gateway(self, gateway_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE gateway_id = ?', (gateway_id,))
        return [
            {
                'id': row[0],
                'type': row[1],
                'port': row[2],
                'state': json.loads(row[4]) if row[4] else {},
                'compromised': bool(row[5])
            }
            for row in cursor.fetchall()
        ]

    def get_all_devices(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM devices')
        return [
            {
                'id': row[0],
                'type': row[1],
                'port': row[2],
                'state': json.loads(row[4]) if row[4] else {},
                'compromised': bool(row[5]),
                'gateway_id': row[6]
            }
            for row in cursor.fetchall()
        ]

    def get_all_gateways(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM gateways')
        return [
            {
                'id': row[0],
                'host': row[1],
                'port': row[2],
                'cloud_host': row[4],
                'cloud_port': row[5],
                'last_seen': row[6]
            }
            for row in cursor.fetchall()
        ]

    def delete_user(self, user_id):
        cursor = self.conn.cursor()
        # Удаляем пользователя и связанные токены
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        cursor.execute('DELETE FROM user_tokens WHERE user_id = ?', (user_id,))
        self.conn.commit()

    def delete_token(self, token):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM user_tokens WHERE token = ?', (token,))
        self.conn.commit()