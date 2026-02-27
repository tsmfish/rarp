from scapy.all import *
import argparse
import time

zero_ip = "0.0.0.0"

# ====================== НАЛАШТУВАННЯ АРГУМЕНТІВ ======================
parser = argparse.ArgumentParser(description="RARP Request + очікування відповіді (Scapy + Npcap)")
parser.add_argument('-m', '--mac',     type=str, help='MAC-адреса (формат: 00:0c:29:11:22:33). Якщо не вказано — береться з інтерфейсу')
parser.add_argument('-i', '--iface',   type=str, help='Назва інтерфейсу (Ethernet або \\Device\\NPF_...). Якщо не вказано — автоматично')
parser.add_argument('-t', '--timeout', type=int, default=60, help='Час очікування відповіді в секундах (за замовчуванням 60)')
args = parser.parse_args()

timeout_sec = args.timeout

# ====================== АВТО-ВИБІР ІНТЕРФЕЙСУ ТА MAC ======================
if args.iface:
    iface = args.iface
    print(f"✅ Використовуємо вказаний інтерфейс: {iface}")
else:
    iface = get_working_if()
    print(f"✅ Автоматично обрано активний інтерфейс: {iface}")

if args.mac:
    src_mac = args.mac.lower()
    print(f"✅ Використовуємо вказаний MAC: {src_mac}")
else:
    src_mac = get_if_hwaddr(iface).lower()
    print(f"✅ MAC взято з інтерфейсу: {src_mac}")

dst_mac = "ff:ff:ff:ff:ff:ff"
# ====================== ФОРМУВАННЯ RARP REQUEST ======================
pkt = Ether(dst=dst_mac, src=src_mac, type=0x8035) / \
      ARP(op=3,
          hwsrc=src_mac,
          psrc=zero_ip,
          hwdst=dst_mac,
          pdst=zero_ip)

print("\n=== RARP Request пакет ===")
pkt.show()

# ====================== ВІДПРАВКА ======================
print(f"\nВідправляємо RARP Request на інтерфейс {iface}...")
sendp(pkt, iface=iface, count=1, verbose=1)
print("✅ RARP Request відправлено!")

# ====================== ОЧІКУВАННЯ ВІДПОВІДІ ======================
print(f"\n⏳ Чекаємо RARP Reply протягом {timeout_sec} секунд...")

def is_our_rarp_reply(p):
    """Перевіряє, чи це саме RARP Reply для нашого MAC"""
    if ARP in p and p[ARP].op == 4:                    # Opcode 4 = Reply
        if p[ARP].hwdst.lower() == src_mac:                # Target MAC = наш
            return True
    return False

# Sniff тільки RARP-пакети
start_time = time.time()
ans = sniff(iface=iface,
            filter="ether proto 0x8035",   # тільки RARP (0x8035)
            timeout=timeout_sec,
            stop_filter=is_our_rarp_reply,
            count=1,
            store=1)

if ans:
    reply = ans[0]
    ip = reply[ARP].psrc
    print(f"\n🎉 RARP Reply отримано!")
    print(f"   Ваша IP-адреса: {ip}")
    print(f"   Час очікування: {time.time() - start_time:.1f} сек")
else:
    print(f"\n❌ Таймаут {timeout_sec} секунд: відповідь від RARP-сервера не отримана.")
    print("   (Перевірте, чи сервер RARP запущений і чи інтерфейс правильно обрано)")

print("\nГотово.")