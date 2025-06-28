import json
import logging
import socket
import threading

from cryptography.exceptions import InvalidTag

from crypto import CryptoUtils
from database import Database
from logger import init_logger


class CloudServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.gateways = {}
        self.logger = init_logger('cloud_server')
        self.db = Database()

    def start(self):
        self.logger.info(f"Starting cloud server on {self.host}:{self.port}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)

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

            if message.get('type') == 'gateway_verify':
                self.handle_gateway_verify(conn, message)
            elif message.get('type') == 'user_command':
                self.handle_user_command(conn, message)
            elif message.get('type') == 'telemetry':
                self.handle_telemetry(conn, message)
            elif message.get('type') == 'device_key_request':
                self.handle_device_key_request(conn, message)
            else:
                self.logger.warning("Unknown message type")

        except Exception as e:
            self.logger.error(f"Connection error: {str(e)}")
        finally:
            conn.close()

    def handle_gateway_verify(self, conn, message):
        gateway_id = message['gateway_id']
        encrypted_nonce = bytes.fromhex(message['encrypted_nonce'])

        # Get gateway key from DB
        gateway = self.db.get_gateway(gateway_id)
        if not gateway:
            self.logger.error(f"Gateway {gateway_id} not found")
            conn.send(json.dumps({'status': 'error', 'reason': 'gateway not found'}).encode())
            return

        try:
            # Decrypt nonce with gateway key
            nonce = CryptoUtils.decrypt(encrypted_nonce, gateway['secret_key'])
            self.logger.info(f"Decrypted nonce for gateway {gateway_id}")

            # Generate session key
            session_key = CryptoUtils.derive_key(nonce + gateway['secret_key'])
            self.gateways[gateway_id] = session_key

            # Логирование сессионного ключа
            self.logger.info(f"Session key with gateway {gateway_id}: {session_key.hex()}")
            logging.info(f"Cloud session key with gateway {gateway_id}: {session_key.hex()}")

            # Encrypt session key with gateway secret key
            encrypted_session = CryptoUtils.encrypt(session_key, gateway['secret_key'])

            conn.send(json.dumps({
                'status': 'verified',
                'encrypted_session': encrypted_session.hex()
            }).encode())
            self.logger.info(f"Gateway {gateway_id} verified successfully")

        except InvalidTag:
            self.logger.error("Decryption failed: Invalid tag")
            conn.send(json.dumps({'status': 'error', 'reason': 'decryption failed'}).encode())
        except Exception as e:
            self.logger.error(f"Verification error: {str(e)}")
            conn.send(json.dumps({'status': 'error', 'reason': str(e)}).encode())

    def handle_user_command(self, conn, message):
        token = message.get('token')
        device_id = message.get('device_id')
        command = message.get('command')

        # Validate token
        token_info = self.db.validate_token(token)
        if not token_info:
            conn.send(json.dumps({'status': 'error', 'reason': 'invalid token'}).encode())
            return

        gateway_id = token_info['gateway_id']
        gateway = self.db.get_gateway(gateway_id)
        if not gateway:
            conn.send(json.dumps({'status': 'error', 'reason': 'gateway not found'}).encode())
            return

        # Check if device belongs to this gateway
        device = self.db.get_device(device_id)
        if not device or device.get('gateway_id') != gateway_id:
            conn.send(json.dumps({'status': 'error', 'reason': 'device not found'}).encode())
            return

        # Check if we have session key for this gateway
        if gateway_id not in self.gateways:
            conn.send(json.dumps({'status': 'error', 'reason': 'no active session with gateway'}).encode())
            return

        # Send command to gateway
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((gateway['host'], gateway['port']))

                # Encrypt command with session key
                encrypted_cmd = CryptoUtils.encrypt(
                    json.dumps({
                        'device_id': device_id,
                        'command': command
                    }).encode(),
                    self.gateways[gateway_id]
                )

                sock.send(json.dumps({
                    'type': 'from_cloud',
                    'encrypted_cmd': encrypted_cmd.hex()
                }).encode())

                response = json.loads(sock.recv(4096).decode())
                conn.send(json.dumps(response).encode())

        except Exception as e:
            conn.send(json.dumps({
                'status': 'error',
                'reason': str(e)
            }).encode())

    def handle_telemetry(self, conn, message):
        gateway_id = message.get('gateway_id')
        encrypted_data = bytes.fromhex(message['encrypted_data'])

        # Validate gateway session
        if gateway_id not in self.gateways:
            self.logger.error(f"No active session for gateway {gateway_id}")
            conn.send(json.dumps({'status': 'error', 'reason': 'no active session'}).encode())
            return

        try:
            # Decrypt telemetry data
            decrypted = CryptoUtils.decrypt(encrypted_data, self.gateways[gateway_id])
            telemetry = json.loads(decrypted.decode())
            self.logger.info(f"Received telemetry from {gateway_id}: {telemetry}")

            # Update device states in DB
            for device_id, data in telemetry.items():
                self.db.update_device_state(device_id, data)
                self.logger.debug(f"Updated state for {device_id}")

            conn.send(json.dumps({'status': 'success'}).encode())

        except InvalidTag:
            self.logger.error("Telemetry decryption failed: Invalid tag")
            conn.send(json.dumps({'status': 'error', 'reason': 'decryption failed'}).encode())
        except Exception as e:
            self.logger.error(f"Telemetry handling error: {str(e)}")
            conn.send(json.dumps({'status': 'error', 'reason': str(e)}).encode())

    def handle_device_key_request(self, conn, message):
        gateway_id = message.get('gateway_id')
        device_id = message.get('device_id')

        self.logger.info(f"Device key request from {gateway_id} for {device_id}")

        # Validate gateway session
        if gateway_id not in self.gateways:
            self.logger.error(f"Gateway {gateway_id} not authenticated")
            conn.send(json.dumps({'status': 'error', 'reason': 'gateway not authenticated'}).encode())
            return

        # Check device belongs to this gateway
        db = Database()
        device = db.get_device(device_id)
        if not device or device.get('gateway_id') != gateway_id:
            self.logger.error(f"Device {device_id} not found or not assigned to gateway")
            conn.send(json.dumps({'status': 'error', 'reason': 'device not found'}).encode())
            return

        # Encrypt device key with gateway session key
        try:
            encrypted_key = CryptoUtils.encrypt(
                device['secret_key'],
                self.gateways[gateway_id]
            )

            conn.send(json.dumps({
                'status': 'success',
                'encrypted_key': encrypted_key.hex()
            }).encode())
            self.logger.info(f"Sent device key to gateway {gateway_id} for {device_id}")

        except Exception as e:
            self.logger.error(f"Key encryption failed: {str(e)}")
            conn.send(json.dumps({
                'status': 'error',
                'reason': 'encryption error'
            }).encode())