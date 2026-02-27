#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    int fd = -1;
    struct ifreq ifr;
    unsigned char pkt[42];
    unsigned char mac[] = {0x00, 0x0c, 0x29, 0x11, 0x22, 0x33};
    int i;
    char dev[32];
    int one = 1;
    struct timeval timeout;
    unsigned char buf[4096];
    ssize_t len;
    unsigned char *p;
    int found;
    struct bpf_hdr *bh;
    unsigned int hdrlen;
    unsigned int caplen;
    unsigned char *pkt_data;
    unsigned char *ip;

    for (i = 0; i < 256; i++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%d", i);
        fd = open(dev, O_RDWR);
        if (fd >= 0) break;
    }
    if (fd < 0) {
        perror("Cannot open bpf device");
        return 1;
    }

    /* Встановлюємо прапор для повного заголовка */
    if (ioctl(fd, BIOCSHDRCMPLT, &one) < 0) {
        perror("ioctl(BIOCSHDRCMPLT)");
        close(fd);
        return 1;
    }
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "lnc0");
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        perror("ioctl(BIOCSETIF)");
        close(fd);
        return 1;
    }

    /* Immediate mode + таймаут */
    if (ioctl(fd, BIOCIMMEDIATE, &one) < 0) {
        perror("ioctl(BIOCIMMEDIATE)");
        close(fd);
        return 1;
    }
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (ioctl(fd, BIOCSRTIMEOUT, &timeout) < 0) {
        perror("ioctl(BIOCSRTIMEOUT)");
        close(fd);
        return 1;
    }

    /* Формування пакету RARP Request */
    memset(pkt, 0xff, 6);                    /* Broadcast Dest */
    memcpy(pkt + 6, mac, 6);                 /* Source MAC */
    pkt[12] = 0x80; pkt[13] = 0x35;          /* EtherType: RARP */
    pkt[14] = 0x00; pkt[15] = 0x01;          /* HW: Ethernet */
    pkt[16] = 0x08; pkt[17] = 0x00;          /* Proto: IP */
    pkt[18] = 0x06; pkt[19] = 0x04;          /* Sizes */
    pkt[20] = 0x00; pkt[21] = 0x03;          /* Opcode: Request (3) */
    memcpy(pkt + 22, mac, 6);                /* Sender MAC */
    memset(pkt + 28, 0, 4);                  /* Sender IP */
    memset(pkt + 32, 0xff, 6);               /* Target MAC */
    memset(pkt + 38, 0, 4);                  /* Target IP */

    if (write(fd, pkt, sizeof(pkt)) < 0) {
        perror("write to bpf");
        close(fd);
        return 1;
    }
    printf("RARP Request sent successfully!\n");

    /* Читання відповіді */
    len = read(fd, buf, sizeof(buf));
    if (len < 0) {
        perror("read from bpf");
        close(fd);
        return 1;
    }
    if (len == 0) {
        printf("No RARP response received within timeout.\n");
        close(fd);
        return 1;
    }

    p = buf;
    found = 0;
    while (p < buf + len) {
        if (p + sizeof(struct bpf_hdr) > buf + len) {
            break;
        }
        bh = (struct bpf_hdr *)p;
        hdrlen = bh->bh_hdrlen;
        caplen = bh->bh_caplen;

        if (p + hdrlen + caplen > buf + len) {
            break;
        }

        pkt_data = p + hdrlen;

        if (caplen >= 42 &&
            pkt_data[12] == 0x80 && pkt_data[13] == 0x35 &&      /* RARP */
            pkt_data[20] == 0x00 && pkt_data[21] == 0x04 &&      /* Opcode: Reply */
            memcmp(pkt_data + 32, mac, 6) == 0) {                /* Target MAC = наш */

            ip = pkt_data + 28;
            printf("Your IP address is %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
            found = 1;
            break;
        }

        p += BPF_WORDALIGN(hdrlen + caplen);
    }

    if (!found) {
        printf("No valid RARP reply found in captured packets.\n");
    }

    close(fd);
    return 0;
}