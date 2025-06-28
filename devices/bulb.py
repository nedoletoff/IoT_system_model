from .base_device import BaseDevice


class Bulb(BaseDevice):
    def __init__(self, device_id, port, secret_key, gateway_host, gateway_port):
        super().__init__(device_id, 'bulb', port, secret_key, gateway_host, gateway_port)
        self.state = {'brightness': 0, 'on': False}

    def get_telemetry(self):
        return {'brightness': self.state['brightness'], 'on': self.state['on']}

    def execute_command(self, command):
        action = command.get('action')
        if action == 'set_brightness':
            brightness = command['value']
            if 0 <= brightness <= 100:
                self.state['brightness'] = brightness
                self.state['on'] = brightness > 0
                return {'success': True, 'state': self.state}
            return {'success': False, 'reason': 'Invalid brightness value'}
        elif action == 'get_state':
            return {'success': True, 'state': self.state}
        elif action == 'toggle':
            self.state['on'] = not self.state['on']
            if not self.state['on']:
                self.state['brightness'] = 0
            return {'success': True, 'state': self.state}
        return {'success': False, 'reason': 'Unknown action'}