from .base_device import BaseDevice


class Lock(BaseDevice):
    def __init__(self, device_id, port, secret_key, gateway_host, gateway_port):
        super().__init__(device_id, 'lock', port, secret_key, gateway_host, gateway_port)
        self.state = {'locked': True}

    def get_telemetry(self):
        return {'locked': self.state['locked']}

    def execute_command(self, command):
        action = command.get('action')
        if action == 'lock':
            self.state['locked'] = True
            return {'success': True, 'state': self.state}
        elif action == 'unlock':
            self.state['locked'] = False
            return {'success': True, 'state': self.state}
        elif action == 'get_state':
            return {'success': True, 'state': self.state}
        elif action == 'toggle_lock':
            self.state['locked'] = not self.state['locked']
            return {'success': True, 'state': self.state}
        return {'success': False, 'reason': 'Unknown action'}