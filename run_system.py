import argparse
import threading
import time
from gateway import Gateway
from cloud import CloudServer
from devices.bulb import Bulb
from devices.lock import Lock
from devices.sensor import Sensor
from web_interface import create_app
from database import Database
import secrets
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='system_keys.log',
    filemode='w'
)

def generate_secret_key():
    # Generate 32 bytes (256 bits) for key
    key = secrets.token_bytes(32)
    logging.info(f"Generated secret key: {key.hex()}")
    return key

def run_system(num_gateways, devices_per_gateway):
    # Создаем базу данных и добавляем администратора
    db = Database()
    try:
        db.create_user('admin', 'admin123', is_admin=True)
    except:
        pass  # Админ уже существует

    # Запускаем облачный сервер
    cloud = CloudServer(host='0.0.0.0', port=6000)
    cloud_thread = threading.Thread(target=cloud.start, daemon=True)
    cloud_thread.start()
    print(f"Облачный сервер запущен на порту 6000")

    # Запускаем шлюзы
    gateway_threads = []
    for i in range(num_gateways):
        gateway_id = f"gateway_{i + 1}"
        gateway_port = 7000 + i
        secret_key = generate_secret_key()

        gateway = Gateway(
            gateway_id=gateway_id,
            host='localhost',
            port=gateway_port,
            secret_key=secret_key,
            cloud_host='localhost',
            cloud_port=6000
        )

        # Регистрируем шлюз в базе данных
        db.add_gateway(
            gateway_id,
            'localhost',
            gateway_port,
            secret_key,
            'localhost',
            6000
        )

        gateway_thread = threading.Thread(
            target=gateway.start,
            daemon=True
        )
        gateway_thread.start()
        gateway_threads.append(gateway_thread)
        print(f"Шлюз {gateway_id} запущен на порту {gateway_port}")

    # Запускаем устройства
    device_threads = []
    device_port = 8000
    for i in range(num_gateways):
        gateway_id = f"gateway_{i + 1}"

        for j in range(devices_per_gateway):
            device_type = ['bulb', 'sensor', 'lock'][j % 3]
            device_id = f"{gateway_id}_{device_type}_{j + 1}"
            secret_key = generate_secret_key()

            # Создаем устройство в зависимости от типа
            if device_type == 'bulb':
                device = Bulb(
                    device_id=device_id,
                    port=device_port,
                    secret_key=secret_key,
                    gateway_host='localhost',
                    gateway_port=7000 + i
                )
            elif device_type == 'lock':
                device = Lock(
                    device_id=device_id,
                    port=device_port,
                    secret_key=secret_key,
                    gateway_host='localhost',
                    gateway_port=7000 + i
                )
            else:  # sensor
                device = Sensor(
                    device_id=device_id,
                    port=device_port,
                    secret_key=secret_key,
                    gateway_host='localhost',
                    gateway_port=7000 + i
                )

            # Регистрируем устройство в базе данных
            db.add_device(
                device_id,
                device_type,
                device_port,
                secret_key,
                gateway_id
            )

            device_thread = threading.Thread(
                target=device.start,
                daemon=True
            )
            device_thread.start()
            device_threads.append(device_thread)
            print(f"Устройство {device_id} запущено на порту {device_port}")
            device_port += 1

    # Запускаем веб-сервер
    app = create_app()
    web_thread = threading.Thread(
        target=lambda: app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False),
        daemon=True
    )
    web_thread.start()
    print(f"Веб-интерфейс доступен по адресу http://localhost:5000")
    print("Для входа используйте admin/admin123")

    # Бесконечный цикл для поддержания работы всех потоков
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nСистема остановлена")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Запуск всей IoT системы')
    parser.add_argument('--gateways', type=int, default=2, help='Количество шлюзов')
    parser.add_argument('--devices-per-gateway', type=int, default=3, help='Количество устройств на шлюз')

    args = parser.parse_args()
    run_system(args.gateways, args.devices_per_gateway)