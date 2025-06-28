import socket
import threading
import json
from cryptography.exceptions import InvalidTag
from crypto import CryptoUtils
from database import Database
from logger import init_logger
import time
import logging


class Gateway:
    def __init__(self, gateway_id, host, port, secret_key, cloud_host, cloud_port):
        self.id = gateway_id
        self.host = host
        self.port = port
        self.secret_key = secret_key
        self.cloud_host = cloud_host
        self.cloud_port = cloud_port
        self.devices = {}
        self.session_keys = {}
        self.cloud_session = None
        self.logger = init_logger(f'gateway_{gateway_id}')

        # Логирование ключей
        self.logger.info(f"Gateway {gateway_id} secret key: {secret_key.hex()}")
        logging.info(f"Gateway {gateway_id} secret key: {secret_key.hex()}")

        # Register in database
        db = Database()
        db.add_gateway(self.id, self.host, self.port, self.secret_key, self.cloud_host, self.cloud_port)
        db.log_event('gateway_init', self.id, None, f'Gateway initialized on port {port}')

    def start(self):
        self.logger.info(f"Starting gateway {self.id} on port {self.port}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)

        # Connect to cloud
        threading.Thread(target=self.connect_to_cloud).start()

        # Start telemetry sender
        threading.Thread(target=self.send_telemetry_loop, daemon=True).start()

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_connection, args=(conn,)).start()

    def connect_to_cloud(self):
        self.logger.info(f"Connecting to cloud at {self.cloud_host}:{self.cloud_port}")
        try:
            # Generate nonce for verification
            nonce = CryptoUtils.generate_nonce(12)

            # Encrypt nonce with our secret key
            encrypted_nonce = CryptoUtils.encrypt(nonce, self.secret_key)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.cloud_host, self.cloud_port))
                sock.send(json.dumps({
                    'type': 'gateway_verify',
                    'gateway_id': self.id,
                    'encrypted_nonce': encrypted_nonce.hex()
                }).encode())

                response = json.loads(sock.recv(4096).decode())
                if response.get('status') == 'verified':
                    # Decrypt session key with our secret key
                    encrypted_session = bytes.fromhex(response['encrypted_session'])
                    self.cloud_session = CryptoUtils.decrypt(encrypted_session, self.secret_key)
                    self.logger.info("Cloud verification successful")

                    # Логирование сессионного ключа
                    self.logger.info(f"Cloud session key: {self.cloud_session.hex()}")
                    logging.info(f"Gateway {self.id} cloud session key: {self.cloud_session.hex()}")
                else:
                    self.logger.error(f"Cloud verification failed: {response.get('reason', 'unknown')}")
        except Exception as e:
            self.logger.error(f"Cloud connection error: {str(e)}")

    def handle_connection(self, conn):
        try:
            data = conn.recv(4096)
            if not data:
                return

            try:
                message = json.loads(data.decode())
                self.logger.debug(f"Received message: {message}")
            except json.JSONDecodeError:
                self.logger.error("Invalid JSON received")
                conn.close()
                return

            if message.get('type') == 'from_cloud':
                self.handle_cloud_command(conn, message)
            elif message.get('type') == 'telemetry':
                self.handle_device_telemetry(conn, message)
            elif message.get('command') == 'verify':
                self.handle_device_verification(conn, message)
            else:
                self.logger.warning(f"Unknown message: {message}")

        except Exception as e:
            self.logger.error(f"Connection error: {str(e)}")
        finally:
            conn.close()

    def handle_cloud_command(self, conn, message):
        if not self.cloud_session:
            self.logger.error("No cloud session established")
            conn.send(json.dumps({'status': 'error', 'reason': 'no cloud session'}).encode())
            return

        encrypted_cmd = bytes.fromhex(message['encrypted_cmd'])
        try:
            # Decrypt cloud command
            cmd_data = CryptoUtils.decrypt(encrypted_cmd, self.cloud_session)
            cmd = json.loads(cmd_data.decode())
            self.logger.info(f"Executing cloud command: {cmd}")

            device_id = cmd['device_id']
            device_command = cmd['command']

            # Verify device if needed
            if device_id not in self.session_keys:
                if not self.verify_device(device_id):
                    conn.send(json.dumps({'status': 'error', 'reason': 'device verification failed'}).encode())
                    return

            # Forward command to device
            device_response = self.send_to_device(device_id, device_command)

            # Encrypt and send response to cloud
            encrypted_response = CryptoUtils.encrypt(
                json.dumps(device_response).encode(),
                self.cloud_session
            )
            conn.send(json.dumps({
                'status': 'success',
                'encrypted_response': encrypted_response.hex()
            }).encode())

        except InvalidTag:
            self.logger.error("Cloud command decryption failed")
            conn.send(json.dumps({'status': 'error', 'reason': 'decryption failed'}).encode())
            self.cloud_session = None
        except Exception as e:
            self.logger.error(f"Command handling error: {str(e)}")
            conn.send(json.dumps({'status': 'error', 'reason': str(e)}).encode())

    def handle_device_telemetry(self, conn, message):
        device_id = message.get('device_id')
        if not device_id:
            self.logger.error("Telemetry message missing device_id")
            conn.send(json.dumps({'status': 'error', 'reason': 'missing device_id'}).encode())
            return

        encrypted_telemetry = bytes.fromhex(message['encrypted_data'])

        # Check if we have session with this device
        if device_id not in self.session_keys:
            self.logger.error(f"No session key for device {device_id}")
            conn.send(json.dumps({'status': 'error', 'reason': 'no session key'}).encode())
            return

        try:
            # Decrypt telemetry
            decrypted = CryptoUtils.decrypt(encrypted_telemetry, self.session_keys[device_id])
            telemetry = json.loads(decrypted.decode())

            # Store telemetry temporarily
            if device_id not in self.devices:
                self.devices[device_id] = {}
            self.devices[device_id]['state'] = telemetry

            conn.send(json.dumps({'status': 'success'}).encode())
            self.logger.info(f"Received telemetry from {device_id}")

        except InvalidTag:
            self.logger.error("Telemetry decryption failed")
            conn.send(json.dumps({'status': 'error', 'reason': 'decryption failed'}).encode())
        except json.JSONDecodeError:
            self.logger.error("Invalid telemetry JSON")
            conn.send(json.dumps({'status': 'error', 'reason': 'invalid data'}).encode())
        except Exception as e:
            self.logger.error(f"Telemetry handling error: {str(e)}")
            conn.send(json.dumps({'status': 'error', 'reason': str(e)}).encode())

    def handle_device_verification(self, conn, message):
        device_id = message.get('device_id')
        self.logger.info(f"Starting verification for device: {device_id}")

        # Request device key from cloud
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.cloud_host, self.cloud_port))
                sock.send(json.dumps({
                    'type': 'device_key_request',
                    'gateway_id': self.id,
                    'device_id': device_id
                }).encode())

                response_data = sock.recv(4096)
                if not response_data:
                    self.logger.error("Empty response from cloud")
                    conn.send(json.dumps({'status': 'error', 'reason': 'cloud error'}).encode())
                    return

                response = json.loads(response_data.decode())
        except Exception as e:
            self.logger.error(f"Cloud request error: {str(e)}")
            conn.send(json.dumps({'status': 'error', 'reason': 'cloud connection failed'}).encode())
            return

        if response.get('status') != 'success':
            reason = response.get('reason', 'unknown')
            self.logger.error(f"Failed to get device key: {reason}")
            conn.send(json.dumps({'status': 'error', 'reason': reason}).encode())
            return

        # Decrypt device key with cloud session
        encrypted_key = bytes.fromhex(response['encrypted_key'])
        try:
            device_key = CryptoUtils.decrypt(encrypted_key, self.cloud_session)
            self.logger.info(f"Retrieved key for device {device_id}")
        except InvalidTag:
            self.logger.error("Device key decryption failed")
            conn.send(json.dumps({'status': 'error', 'reason': 'key decryption failed'}).encode())
            return

        # Generate nonce and encrypt with device key
        nonce = CryptoUtils.generate_nonce(12)
        try:
            encrypted_nonce = CryptoUtils.encrypt(nonce, device_key)
        except Exception as e:
            self.logger.error(f"Nonce encryption failed: {str(e)}")
            conn.send(json.dumps({'status': 'error', 'reason': 'encryption error'}).encode())
            return

        # Send challenge to device
        conn.send(json.dumps({
            'status': 'challenge',
            'encrypted_nonce': encrypted_nonce.hex()
        }).encode())

        # Wait for device response
        try:
            response_data = conn.recv(4096)
            if not response_data:
                self.logger.error("No response from device")
                return

            response = json.loads(response_data.decode())
        except Exception as e:
            self.logger.error(f"Device response error: {str(e)}")
            return

        if response.get('status') == 'verified':
            # Generate session key
            session_key = CryptoUtils.derive_key(nonce + device_key)
            self.session_keys[device_id] = session_key

            # Store device info
            db = Database()
            device = db.get_device(device_id)
            if device:
                self.devices[device_id] = device

            # Логирование сессионного ключа
            self.logger.info(f"Device session key for {device_id}: {session_key.hex()}")
            logging.info(f"Gateway {self.id} device {device_id} session key: {session_key.hex()}")

            self.logger.info(f"Device {device_id} verified successfully")
        else:
            self.logger.warning(f"Device verification failed: {response.get('reason', 'unknown')}")

    def verify_device(self, device_id):
        db = Database()
        device = db.get_device(device_id)
        if not device:
            self.logger.error(f"Device {device_id} not found")
            return False

        if device['compromised']:
            self.logger.warning(f"Device {device_id} is compromised")
            return False

        # Try to establish session
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(('localhost', device['port']))
                sock.send(json.dumps({
                    'command': 'verify',
                    'device_id': device_id
                }).encode())

                response = json.loads(sock.recv(4096).decode())
                return response.get('status') == 'verified'
        except Exception as e:
            self.logger.error(f"Device verification error: {str(e)}")
            return False

    def send_to_device(self, device_id, command):
        if device_id not in self.session_keys:
            self.logger.error(f"No session key for device {device_id}")
            return {'status': 'error', 'reason': 'no session key'}

        # Encrypt command with session key
        encrypted_cmd = CryptoUtils.encrypt(
            json.dumps(command).encode(),
            self.session_keys[device_id]
        )

        return self.send_to_device_raw(device_id, {
            'command': 'execute',
            'encrypted_cmd': encrypted_cmd.hex()
        })

    def send_to_device_raw(self, device_id, message):
        device = self.devices.get(device_id)
        if not device:
            db = Database()
            device = db.get_device(device_id)
            if not device:
                return None
            self.devices[device_id] = device

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(('localhost', device['port']))
                sock.send(json.dumps(message).encode())
                response = sock.recv(4096)
                return json.loads(response.decode()) if response else None
        except Exception as e:
            self.logger.error(f"Device communication error: {str(e)}")
            return None

    def send_telemetry_loop(self):
        while True:
            time.sleep(60)  # Send telemetry every minute

            if not self.cloud_session:
                self.logger.warning("No cloud session, skipping telemetry")
                continue

            # Collect telemetry from all devices
            telemetry = {}
            for device_id, device_data in self.devices.items():
                if 'state' in device_data:
                    telemetry[device_id] = device_data['state']

            if not telemetry:
                continue

            try:
                # Encrypt telemetry with cloud session key
                encrypted_telemetry = CryptoUtils.encrypt(
                    json.dumps(telemetry).encode(),
                    self.cloud_session
                )

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((self.cloud_host, self.cloud_port))
                    sock.send(json.dumps({
                        'type': 'telemetry',
                        'gateway_id': self.id,
                        'encrypted_data': encrypted_telemetry.hex()
                    }).encode())

                    response = json.loads(sock.recv(4096).decode())
                    if response.get('status') == 'success':
                        self.logger.info(f"Sent telemetry for {len(telemetry)} devices")
                    else:
                        self.logger.error(f"Telemetry send failed: {response.get('reason')}")

            except Exception as e:
                self.logger.error(f"Telemetry send error: {str(e)}")