from scapy.all import *
import argparse
import random
from datetime import datetime

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
args = parser.parse_args()

# ====================== НАЛАШТУВАННЯ ======================
logfile = args.logfile

# Вибір інтерфейсу
if args.all:
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

# IP для видачі
if args.assign_ip:
    assign_ip = args.assign_ip
    print(f"✅ Фіксована IP для видачі: {assign_ip}")
else:
    # Генерація довільної приватної IP (один раз на запуск)
    assign_ip = f"192.168.{random.randint(10, 99)}.{random.randint(1, 254)}"
    print(f"✅ Згенеровано випадкову IP: {assign_ip}")

# ====================== ОБРОБНИК ЗАПИТУ ======================
def handle_rarp(pkt):
    if not (ARP in pkt and pkt[ARP].op == 3):  # тільки RARP Request (opcode 3)
        return

    client_mac = pkt[ARP].hwsrc.lower()

    # Формуємо RARP Reply
    reply_pkt = Ether(dst=client_mac, src=server_mac, type=0x8035) / \
                ARP(op=4,                          # Reply
                    hwsrc=server_mac,
                    psrc=assign_ip,
                    hwdst=client_mac,
                    pdst=client_mac)

    # Відправка
    if iface is None:
        sendp(reply_pkt, verbose=0)
    else:
        sendp(reply_pkt, iface=iface, verbose=0)

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


# ====================== ЗАПУСК СЕРВЕРА ======================
print(f"\n🚀 RARP-сервер запущено! (лог: {logfile})")
print("   Очікуємо RARP Request...")
print("   Натисніть Ctrl+C для зупинки\n")

try:
    sniff(iface=iface,
          filter="ether proto 0x8035",   # тільки RARP-пакети
          prn=handle_rarp,
          store=0,                       # не зберігати пакети в пам'ять
          timeout=None)                  # працює нескінченно
except KeyboardInterrupt:
    print("\n\n🛑 RARP-сервер зупинено користувачем.")
except Exception as e:
    print(f"\n❌ Помилка: {e}")

print("До побачення!")