from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import argparse
import ipaddress
import random
from datetime import datetime

zero_ip = "0.0.0.0"
# ====================== ОБРОБНИК ЗАПИТУ ======================
def handle_rarp(pkt):
    global server_mac, server_ip, assign_ip, iface, logfile

    # Перевіряємо EtherType (RARP = 0x8035) та наявність сирих даних
    if Ether not in pkt or pkt[Ether].type != 0x8035 or Raw not in pkt:
        return

    payload = pkt[Raw].load

    # Структура RARP (ARP) заголовка:
    # Опкод (Opcode) — це байти на зміщенні 6:8
    # Sender Hardware Address (SHA) — це байти на зміщенні 8:14
    
    if len(payload) < 14:  # Мінімальна довжина для витягування MAC
        return

    # Витягуємо Opcode (2 байти, big-endian)
    opcode = int.from_bytes(payload[6:8], byteorder='big')

    if opcode != 3:  # Тільки RARP Request
        return

    # Витягуємо MAC клієнта і форматуємо в рядок aa:bb:cc...
    client_mac_raw = payload[8:14]
    client_mac = ':'.join(f'{b:02x}' for b in client_mac_raw)

    # Формуємо RARP Reply
    reply_pkt = Ether(dst=client_mac, src=server_mac, type=0x8035) / \
                ARP(op=4,                          # Reply
                   hwsrc=server_mac,
                   psrc=server_ip,
                   hwdst=client_mac,
                   pdst=assign_ip,
                )

    # Відправка
    if iface is None:
        sendp(reply_pkt, verbose=1)
    else:
        sendp(reply_pkt, iface=iface, verbose=1)

    # ====================== ЛОГУВАННЯ ======================
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"[{now}] RARP Reply видано\n"
        f"   MAC клієнта : {client_mac}\n"
        f"   Видана IP   : {assign_ip}\n"
        f"   Інтерфейс   : {iface if iface else 'ALL'}\n"
        f"   Пакет       : {reply_pkt.summary()}\n"
        f"{'='*60}\n\n"
    )

    # Вивід у консоль
    print(log_entry.strip())

    # Запис у текстовий лог
    try:
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Помилка запису в лог: {e}")

def main() -> None:
    global server_mac, assign_ip, iface, logfile, server_ip
    # ====================== ПАРСЕР ПАРАМЕТРІВ ======================
    parser = argparse.ArgumentParser(description="RARP Server (зворотна частина) — видає IP на запит RARP")
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Інтерфейс для прослуховування (наприклад "Ethernet"). Якщо не вказано — авто')
    parser.add_argument('--all', action='store_true',
                        help='Слухати ВСІ інтерфейси (відповідь йде через default interface)')
    parser.add_argument('--assign-ip', type=str, default=None,
                        help='Фіксована IP-адреса для видачі (наприклад 192.168.1.100). Якщо не вказано — генерується випадкова')
    parser.add_argument('--logfile', type=str, default='rarp_server.log',
                        help='Файл логу (за замовчуванням rarp_server.log)')
    parser.add_argument('-t', '--timeout', type=int, default=None,
                        help='Час очікування запиту (секунди). За замовчуванням — нескінченно')
    parser.add_argument('--int-interactive', action='store_true',
                        help='Інтерактивний вибір інтерфейсу: виводить список і чекає вводу номеру')
                        
    args = parser.parse_args()

    # ====================== НАЛАШТУВАННЯ ======================
    logfile = args.logfile

    # Вибір інтерфейсу
    if args.int_interactive:
        print("Доступні інтерфейси:")
        ifaces_list = list(conf.ifaces.values())
        for i, iface_obj in enumerate(ifaces_list):
            print(f"{i}: {iface_obj.description} ({iface_obj.name})")
        
        try:
            num = int(input("Введіть номер інтерфейсу: "))
            if 0 <= num < len(ifaces_list):
                iface = ifaces_list[num].description  # Використовуємо дружнє ім'я (працює на Windows)
                print(f"✅ Обрано інтерфейс: {iface}")
            else:
                print("❌ Невірний номер. Вихід.")
                return
        except ValueError:
            print("❌ Невірний ввід. Вихід.")
            return
    elif args.all:
        iface = None
        print("⚠️  Режим: ВСІ інтерфейси")
    else:
        if args.interface:
            iface = args.interface
        else:
            iface = get_working_if()
        print(f"✅ Прослуховування інтерфейсу: {iface}")

    # MAC сервера
    if iface is None:
        server_mac = get_if_hwaddr(get_working_if())
    else:
        server_mac = get_if_hwaddr(iface)
    print(f"✅ MAC сервера: {server_mac}")

    # IP сервера
    if iface is None:
        server_ip = get_if_addr(conf.iface)
    else:
        server_ip = get_if_addr(iface)
    print(f"✅ IP сервера: {server_ip}")

    # IP для видачі
    if args.assign_ip:
        try:
            ipaddress.IPv4Address(args.assign_ip)
        except ipaddress.AddressValueError:
            print(f"❌ Невідома IP-адреса: {args.assign_ip}")
            return
        assign_ip = args.assign_ip
        print(f"✅ Фіксована IP для видачі: {assign_ip}")
    else:
        # Генерація довільної приватної IP (один раз на запуск)
        assign_ip = f"192.168.{random.randint(10, 99)}.{random.randint(1, 254)}"
        print(f"✅ Згенеровано випадкову IP: {assign_ip}")

    # ====================== ЗАПУСК СЕРВЕРА ======================
    print(f"\n🚀 RARP-сервер запущено! (лог: {logfile})")
    print("   Очікуємо RARP Request...")
    print("   Натисніть Ctrl+C для зупинки\n")

    try:
        sniff(iface=iface,
            prn=handle_rarp,
            store=0,                       # не зберігати пакети в пам'ять
            timeout=args.timeout if args.timeout else None
        )
    except KeyboardInterrupt:
        print("\n\n🛑 RARP-сервер зупинено користувачем.")
    except Exception as e:
        print(f"\n❌ Помилка: {e}")

    print("До побачення!")

if __name__ == "__main__":
    main()