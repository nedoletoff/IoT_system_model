import socket
import threading
import json
from cryptography.exceptions import InvalidTag
from crypto import CryptoUtils
from database import Database
from logger import init_logger
import time
import logging


class BaseDevice:
    def __init__(self, device_id, device_type, port, secret_key, gateway_host, gateway_port):
        self.id = device_id
        self.type = device_type
        self.port = port
        self.secret_key = secret_key
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.state = {}
        self.compromised = False
        self.session_key = None
        self.nonce_cache = {}
        self.logger = init_logger(f'device_{device_id}')

        # Логирование ключа устройства
        self.logger.info(f"Device {device_id} secret key: {secret_key.hex()}")
        logging.info(f"Device {device_id} secret key: {secret_key.hex()}")

        # Register in database
        db = Database()
        db.add_device(self.id, self.type, self.port, self.secret_key)
        db.log_event('device_init', self.id, None, f'Device initialized on port {port}')

    def start(self):
        self.logger.info(f"Starting device {self.id} on port {self.port}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('localhost', self.port))
        server.listen(5)

        # Start telemetry sender
        threading.Thread(target=self.send_telemetry_loop, daemon=True).start()

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_connection, args=(conn,)).start()

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

            if message.get('command') == 'verify':
                self.handle_verification(conn, message)
            elif message.get('command') == 'execute':
                self.handle_execute(conn, message)
            else:
                self.logger.warning(f"Unknown command: {message.get('command')}")

        except Exception as e:
            self.logger.error(f"Connection error: {str(e)}")
        finally:
            conn.close()

    def handle_verification(self, conn, message):
        if message.get('status') == 'challenge':
            self.handle_challenge(conn, message)
        else:
            self.handle_initial_verification(conn, message)

    def handle_initial_verification(self, conn, message):
        initiator_id = message['initiator_id']
        encrypted_nonce = bytes.fromhex(message['encrypted_nonce'])

        # Get initiator key from DB
        db = Database()
        initiator = db.get_gateway(initiator_id) or db.get_device(initiator_id)
        if not initiator:
            self.logger.error(f"Initiator {initiator_id} not found")
            conn.send(json.dumps({'status': 'error', 'reason': 'initiator not found'}).encode())
            return

        initiator_key = initiator['secret_key']

        # Decrypt nonce
        try:
            nonce = CryptoUtils.decrypt(encrypted_nonce, initiator_key)
        except InvalidTag:
            self.logger.error("Decryption failed: Invalid tag")
            conn.send(json.dumps({'status': 'error', 'reason': 'decryption failed'}).encode())
            return

        # Generate session key
        self.session_key = CryptoUtils.derive_key(nonce + self.secret_key)
        self.logger.info(f"Verification successful with {initiator_id}")

        # Логирование сессионного ключа
        self.logger.info(f"Session key with {initiator_id}: {self.session_key.hex()}")
        logging.info(f"Device {self.id} session key with {initiator_id}: {self.session_key.hex()}")

        # Send success response
        conn.send(json.dumps({
            'status': 'verified'
        }).encode())

    def handle_challenge(self, conn, message):
        encrypted_nonce = bytes.fromhex(message['encrypted_nonce'])
        self.logger.info("Received verification challenge")

        try:
            # Decrypt nonce with our secret key
            nonce = CryptoUtils.decrypt(encrypted_nonce, self.secret_key)
            self.logger.info("Decrypted challenge nonce")

            # Generate session key
            self.session_key = CryptoUtils.derive_key(nonce + self.secret_key)
            self.logger.info("Generated session key from challenge")

            # Логирование сессионного ключа
            self.logger.info(f"Session key: {self.session_key.hex()}")
            logging.info(f"Device {self.id} session key: {self.session_key.hex()}")

            conn.send(json.dumps({
                'status': 'verified'
            }).encode())

        except InvalidTag:
            self.logger.error("Challenge decryption failed")
            conn.send(json.dumps({'status': 'error', 'reason': 'decryption failed'}).encode())
        except Exception as e:
            self.logger.error(f"Challenge handling error: {str(e)}")
            conn.send(json.dumps({'status': 'error', 'reason': str(e)}).encode())

    def handle_execute(self, conn, message):
        if self.compromised:
            self.logger.warning("Device compromised, ignoring command")
            return

        if not self.session_key:
            self.logger.error("No session key established")
            conn.send(json.dumps({'status': 'error', 'reason': 'no session key'}).encode())
            return

        encrypted_cmd = bytes.fromhex(message['encrypted_cmd'])
        try:
            # Decrypt command
            cmd_data = CryptoUtils.decrypt(encrypted_cmd, self.session_key)
            cmd = json.loads(cmd_data.decode())
            self.logger.info(f"Executing command: {cmd}")

            # Execute command
            result = self.execute_command(cmd)

            # Update state
            if 'state' in result:
                self.state = result['state']
                db = Database()
                db.update_device_state(self.id, self.state)

            # Encrypt response
            encrypted_result = CryptoUtils.encrypt(
                json.dumps(result).encode(),
                self.session_key
            )
            conn.send(json.dumps({
                'status': 'success',
                'encrypted_result': encrypted_result.hex()
            }).encode())

        except InvalidTag:
            self.logger.error("Command decryption failed")
            conn.send(json.dumps({'status': 'error', 'reason': 'decryption failed'}).encode())
            self.session_key = None  # Reset session on failure
        except Exception as e:
            self.logger.error(f"Command execution error: {str(e)}")
            conn.send(json.dumps({'status': 'error', 'reason': str(e)}).encode())

    def send_telemetry_loop(self):
        while True:
            time.sleep(60)  # Send telemetry every minute

            # Если нет сессионного ключа, попытаться верифицироваться
            if not self.session_key:
                self.logger.info("No session key, attempting verification")
                if not self.verify_with_gateway():
                    self.logger.warning("Verification failed, skipping telemetry")
                    time.sleep(10)  # Подождать перед следующей попыткой
                    continue

            telemetry = self.get_telemetry()
            if not telemetry:
                continue

            try:
                # Encrypt telemetry with session key
                encrypted_telemetry = CryptoUtils.encrypt(
                    json.dumps(telemetry).encode(),
                    self.session_key
                )

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((self.gateway_host, self.gateway_port))
                    telemetry_msg = {
                        'type': 'telemetry',
                        'device_id': self.id,
                        'encrypted_data': encrypted_telemetry.hex()
                    }
                    sock.send(json.dumps(telemetry_msg).encode())

                    response = sock.recv(4096)
                    if response:
                        try:
                            response_data = json.loads(response.decode())
                            if response_data.get('status') == 'success':
                                self.logger.debug("Telemetry sent successfully")
                            else:
                                self.logger.error(f"Telemetry send failed: {response_data.get('reason')}")
                        except json.JSONDecodeError:
                            self.logger.error("Invalid response to telemetry")
                    else:
                        self.logger.error("No response to telemetry")

            except Exception as e:
                self.logger.error(f"Telemetry send error: {str(e)}")
                # Сбросить сессию при ошибке
                self.session_key = None

    def verify_with_gateway(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.gateway_host, self.gateway_port))

                # Get gateway from DB
                db = Database()
                # Extract gateway ID from device ID (gateway_1_bulb_1 -> gateway_1)
                gateway_id = "_".join(self.id.split("_")[:2])
                gateway = db.get_gateway(gateway_id)

                if not gateway:
                    self.logger.error(f"Gateway {gateway_id} not found in DB")
                    return False

                # Create verification message
                verify_msg = {
                    'command': 'verify',
                    'device_id': self.id
                }

                sock.send(json.dumps(verify_msg).encode())

                # Получаем и парсим ответ
                response_data = sock.recv(4096)
                if not response_data:
                    self.logger.error("Empty response from gateway")
                    return False

                try:
                    response = json.loads(response_data.decode())
                except json.JSONDecodeError:
                    self.logger.error("Invalid JSON response from gateway")
                    return False

                if response.get('status') == 'challenge':
                    return self.handle_remote_challenge(sock, response)
                elif response.get('status') == 'verified':
                    # Legacy mode - should not happen with new protocol
                    self.logger.warning("Using legacy verification")
                    return True
                else:
                    self.logger.warning(f"Verification failed: {response.get('reason', 'unknown')}")

        except Exception as e:
            self.logger.error(f"Verification with gateway failed: {str(e)}")

        return False

    def handle_remote_challenge(self, sock, message):
        encrypted_nonce = bytes.fromhex(message['encrypted_nonce'])
        self.logger.info("Received challenge from gateway")

        try:
            # Decrypt nonce with our secret key
            nonce = CryptoUtils.decrypt(encrypted_nonce, self.secret_key)

            # Generate session key
            self.session_key = CryptoUtils.derive_key(nonce + self.secret_key)
            self.logger.info("Generated session key from gateway challenge")

            # Логирование сессионного ключа
            self.logger.info(f"Session key: {self.session_key.hex()}")
            logging.info(f"Device {self.id} session key: {self.session_key.hex()}")

            sock.send(json.dumps({
                'status': 'verified'
            }).encode())
            return True

        except InvalidTag:
            self.logger.error("Challenge decryption failed")
        except Exception as e:
            self.logger.error(f"Challenge handling error: {str(e)}")

        return False

    def execute_command(self, command):
        raise NotImplementedError("Subclasses must implement this method")

    def get_telemetry(self):
        raise NotImplementedError("Subclasses must implement this method")