# RARP — Reverse Address Resolution Protocol

Навчальна реалізація протоколу **RARP** (RFC 903) на Python (Scapy) та C (BPF).  
RARP дозволяє клієнту дізнатись свою IP-адресу, маючи лише MAC-адресу.

---

## 📁 Структура проекту

| Файл | Опис |
|------|------|
| `rarp_client.py` | Python-клієнт: надсилає RARP Request і чекає Reply |
| `rarp_server.py` | Python-сервер: приймає RARP Request і відповідає IP |
| `rarp_send.c` | C-реалізація клієнта через BPF (BSD/macOS) |
| `requirements.txt` | Залежності Python |

---

## ⚙️ Встановлення

```bash
pip install -r requirements.txt
```

> **Windows:** також потрібен [Npcap](https://npcap.com/) для роботи Scapy.

---

## 🖥️ rarp_client.py — RARP-клієнт

Надсилає широкомовний RARP Request і очікує Reply від сервера.

```bash
python rarp_client.py [OPTIONS]
```

### Аргументи

| Ключ | Довгий ключ | За замовчуванням | Опис |
|------|-------------|-----------------|------|
| `-m` | `--mac` | MAC з інтерфейсу | MAC-адреса клієнта (формат: `00:0c:29:11:22:33`) |
| `-i` | `--iface` | авто | Назва інтерфейсу (`Ethernet` або `\Device\NPF_...`) |
| `-t` | `--timeout` | `60` | Час очікування відповіді, секунди |

### Приклади

```bash
# Авто-визначення інтерфейсу та MAC
python rarp_client.py

# Вказати конкретний MAC і інтерфейс
python rarp_client.py -m 00:0c:29:11:22:33 -i Ethernet

# Встановити таймаут 10 секунд
python rarp_client.py -t 10
```

---

## 🖧 rarp_server.py — RARP-сервер

Слухає мережу, перехоплює RARP Request і відповідає Reply з IP-адресою.

```bash
python rarp_server.py [OPTIONS]
```

### Аргументи

| Ключ | За замовчуванням | Опис |
|------|-----------------|------|
| `-i`, `--interface` | авто | Інтерфейс для прослуховування |
| `--all` | вимкнено | Слухати всі інтерфейси одночасно |
| `--assign-ip` | випадкова `192.168.X.Y` | Фіксована IP для видачі клієнту |
| `--logfile` | `rarp_server.log` | Шлях до файлу логу |

### Приклади

```bash
# Запуск із авто-налаштуваннями
python rarp_server.py

# Фіксована IP на конкретному інтерфейсі
python rarp_server.py -i Ethernet --assign-ip 192.168.1.100

# Слухати всі інтерфейси, лог у кастомний файл
python rarp_server.py --all --logfile my.log
```

---

## 🔧 rarp_send.c — C-клієнт (BSD/macOS)

Низькорівнева реалізація через `/dev/bpf*`. Вимагає C-компілятор.

```bash
# Компіляція
gcc rarp_send.c -o rarp_send

# Надати права на виконання
chmod +x rarp_send

# Запуск (потребує root для доступу до BPF)
sudo ./rarp_send
```

> MAC-адреса клієнта жорстко закодована у файлі: `{0x00, 0x0c, 0x29, 0x11, 0x22, 0x33}`.  
> Інтерфейс за замовчуванням: `lnc0`. Відредагуйте код під свої потреби.

---

## 🔬 Моніторинг трафіку (WireShark)

Для перехоплення RARP-пакетів у **WireShark** використовуйте фільтр:

```
eth.type == 0x8035
```

| Поле | Значення |
|------|----------|
| EtherType | `0x8035` (RARP) |
| Opcode 3 | RARP Request |
| Opcode 4 | RARP Reply |

> Запустіть сервер і клієнт, відкрийте WireShark на тому самому інтерфейсі — ви побачите обмін пакетами в реальному часі.

---

## 🔗 Залежності

- **Python ≥ 3.8**
- **[Scapy](https://scapy.net/) ≥ 2.5.0**
- **Npcap** (тільки Windows) — [npcap.com](https://npcap.com/)

---

## 📖 Протокол

| Поле | Request | Reply |
|------|---------|-------|
| Opcode | 3 | 4 |
| hwsrc | MAC клієнта | MAC сервера |
| hwdst | `ff:ff:ff:ff:ff:ff` | MAC клієнта |
| psrc | `0.0.0.0` | IP клієнта (видана) |
| pdst | `0.0.0.0` | `0.0.0.0` |

> Специфікація: [RFC 903](https://www.rfc-editor.org/rfc/rfc903)
> Опис [Опис](.\ReverseAddressResolutionProtocol.md)
