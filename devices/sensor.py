from .base_device import BaseDevice
import secrets


class Sensor(BaseDevice):
    def __init__(self, device_id, port, secret_key, gateway_host, gateway_port):
        super().__init__(device_id, 'sensor', port, secret_key, gateway_host, gateway_port)
        self.state = {'humidity': 50.0, 'temperature': 22.0}

    def get_telemetry(self):
        return {'humidity': self.state['humidity'], 'temperature': self.state['temperature']}

    def execute_command(self, command):
        action = command.get('action')
        if action == 'read':
            # Simulate sensor reading
            self.state['humidity'] = secrets.SystemRandom().uniform(40.0, 60.0)
            self.state['temperature'] = secrets.SystemRandom().uniform(20.0, 25.0)
            return {'success': True, 'state': self.state}
        return {'success': False, 'reason': 'Unknown action'}