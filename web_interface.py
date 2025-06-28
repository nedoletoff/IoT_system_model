import datetime
import json
import secrets
import socket
from datetime import timedelta

import logger

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_login import LoginManager, UserMixin, login_required, logout_user, current_user, login_user

from database import Database

log = logger.init_logger('web_interface', 'logs/web_interface.log')


def create_app():
    app = Flask(__name__)
    app.secret_key = 'super_secret_key'
    app.config['SESSION_TYPE'] = 'filesystem'

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    class User(UserMixin):
        def __init__(self, user_id, username, is_admin):
            self.id = user_id
            self.username = username
            self.is_admin = is_admin

    @login_manager.user_loader
    def load_user(user_id):
        db = Database()
        user_data = db.get_user_by_id(user_id)
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['is_admin'])
        return None

    @app.route('/')
    def home():
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            db = Database()
            user = db.verify_user(username, password)
            if user:
                user_obj = User(user['id'], user['username'], user['is_admin'])
                login_user(user_obj)
                session['is_admin'] = user['is_admin']
                return redirect(url_for('dashboard'))
            return render_template('login.html', error='Неверное имя пользователя или пароль')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        session.clear()
        return redirect(url_for('login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        db = Database()
        if current_user.is_admin:
            stats = {
                'devices': len(db.get_all_devices()),
                'gateways': len(db.get_all_gateways()),
                'users': len(db.get_all_users()),
                'active_tokens': len(db.get_all_tokens())
            }
            return render_template('admin/dashboard.html', stats=stats)
        else:
            tokens = db.get_user_tokens(current_user.id)
            return render_template('user/dashboard.html', tokens=tokens)

    # Admin sections
    @app.route('/admin/devices')
    @login_required
    def admin_devices():
        if not current_user.is_admin:
            return redirect(url_for('dashboard'))
        db = Database()
        devices = db.get_all_devices()
        gateways = db.get_all_gateways()
        return render_template('admin/devices.html', devices=devices, gateways=gateways)

    @app.route('/admin/mark_compromised', methods=['POST'])
    @login_required
    def mark_compromised():
        if not current_user.is_admin:
            return jsonify({'status': 'error', 'message': 'Доступ запрещен'}), 403
        device_id = request.json.get('device_id')
        db = Database()
        db.mark_device_compromised(device_id)
        return jsonify({'status': 'success'})

    @app.route('/admin/gateways')
    @login_required
    def admin_gateways():
        if not current_user.is_admin:
            return redirect(url_for('dashboard'))
        db = Database()
        gateways = db.get_all_gateways()
        return render_template('admin/gateways.html', gateways=gateways)

    @app.route('/admin/tokens')
    @login_required
    def admin_tokens():
        if not current_user.is_admin:
            return redirect(url_for('dashboard'))
        db = Database()
        tokens = db.get_all_tokens()
        users = db.get_all_users()
        gateways = db.get_all_gateways()
        return render_template('admin/tokens.html', tokens=tokens, users=users, gateways=gateways)

    @app.route('/admin/generate_token', methods=['POST'])
    @login_required
    def admin_generate_token():
        if not current_user.is_admin:
            return jsonify({'status': 'error', 'message': 'Доступ запрещен'}), 403

        user_id = request.json.get('user_id')
        gateway_id = request.json.get('gateway_id')
        expires_hours = int(request.json.get('expires_hours', 24))

        # Проверка существования пользователя и шлюза
        db = Database()
        user = db.get_user_by_id(user_id)
        gateway = db.get_gateway(gateway_id)

        if not user:
            return jsonify({'status': 'error', 'message': 'Пользователь не найден'}), 400

        if not gateway:
            return jsonify({'status': 'error', 'message': 'Шлюз не найден'}), 400

        # Генерация токена
        token = secrets.token_hex(16)
        try:
            db.add_user_token(user_id, token, gateway_id, timedelta(hours=expires_hours))
            log.info(f"Generated token: {token}")
            return jsonify({'status': 'success', 'token': token})
        except Exception as e:
            log.error(e)
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/admin/delete_token', methods=['POST'])
    @login_required
    def delete_token():
        if not current_user.is_admin:
            return jsonify({'status': 'error', 'message': 'Доступ запрещен'}), 403

        token = request.json.get('token')
        db = Database()
        try:
            db.delete_token(token)
            log.info(f"Deleted token: {token}")
            return jsonify({'status': 'success'})
        except Exception as e:
            log.error(e)
            return jsonify({'status': 'error', 'message': str(e)}), 400

    @app.route('/admin/users')
    @login_required
    def admin_users():
        if not current_user.is_admin:
            return redirect(url_for('dashboard'))
        db = Database()
        users = db.get_all_users()
        return render_template('admin/users.html', users=users)

    @app.route('/admin/create_user', methods=['POST'])
    @login_required
    def create_user():
        if not current_user.is_admin:
            return jsonify({'status': 'error', 'message': 'Доступ запрещен'}), 403
        username = request.json.get('username')
        password = request.json.get('password')
        is_admin = request.json.get('is_admin', False)

        db = Database()
        try:
            db.create_user(username, password, is_admin)
            log.info(f"Created user: {username}")
            return jsonify({'status': 'success'})
        except Exception as e:
            log.error(e)
            return jsonify({'status': 'error', 'message': str(e)}), 400

    @app.route('/admin/delete_user', methods=['POST'])
    @login_required
    def delete_user():
        if not current_user.is_admin:
            return jsonify({'status': 'error', 'message': 'Доступ запрещен'}), 403
        user_id = request.json.get('user_id')

        db = Database()
        try:
            db.delete_user(user_id)
            log.info(f"Deleted user: {user_id}")
            return jsonify({'status': 'success'})
        except Exception as e:
            log.error(e)
            return jsonify({'status': 'error', 'message': str(e)}), 400

    # User sections
    @app.route('/user/dashboard')
    @login_required
    def user_dashboard():
        db = Database()
        tokens = db.get_user_tokens(current_user.id)
        return render_template('user/dashboard.html', tokens=tokens)

    @app.route('/user/insert_token', methods=['POST'])
    @login_required
    def user_insert_token():

        token = request.form.get('token')

        db = Database()
        try:
            # Проверяем существование токена
            if not db.validate_token(token):
                flash('Токен неверен', 'error')
                log.info(f'Invalid token: {token}, user: {current_user.id}')
                return redirect(url_for('user_dashboard'))

            flash('Токен успешно добавлен', 'success')
            log.info(f'Inserted token: {token}, user: {current_user.id}')

        except Exception as e:
            log.error(e)
            flash(f'Ошибка: {str(e)}', 'error')

        return redirect(url_for('user_dashboard'))

    @app.route('/user/devices/<token>')
    @login_required
    def user_devices(token):
        db = Database()
        tokens = db.get_user_tokens(current_user.id)
        token_data = next((t for t in tokens if t['token'] == token), None)

        if not token_data:
            flash('Неверный токен или срок действия истек', 'error')
            return redirect(url_for('dashboard'))

        gateway_id = token_data['gateway_id']
        devices = db.get_devices_for_gateway(gateway_id)
        return render_template('user/device_control.html', devices=devices, token=token, gateway_id=gateway_id)

    @app.route('/user/send_command', methods=['POST'])
    @login_required
    def send_command():
        token = request.json.get('token')
        device_id = request.json.get('device_id')
        command = request.json.get('command')

        db = Database()
        tokens = db.get_user_tokens(current_user.id)
        token_data = next((t for t in tokens if t['token'] == token), None)

        if not token_data:
            return jsonify({'status': 'error', 'message': 'Неверный токен'}), 403

        try:
            # Отправляем команду через облачный сервер
            gateway_id = token_data['gateway_id']
            gateway = db.get_gateway(gateway_id)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((gateway['cloud_host'], gateway['cloud_port']))

                payload = {
                    'type': 'user_command',
                    'token': token,
                    'device_id': device_id,
                    'command': command
                }

                sock.send(json.dumps(payload).encode())
                response = sock.recv(4096)
                return jsonify(json.loads(response.decode()))

        except Exception as e:
            log.error(e)
            return jsonify({'status': 'error', 'message': str(e)}), 500

    return app