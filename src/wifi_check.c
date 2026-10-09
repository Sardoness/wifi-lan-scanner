/*
 * wifi_check.c
 *
 * Semplice monitor per la propria rete locale (LAN/Wi-Fi), per macOS e Linux.
 * Individua i dispositivi connessi tramite scansione TCP e tabella ARP,
 * li confronta con un elenco di dispositivi noti, e puo' ripetere la
 * scansione nel tempo per segnalare quando un dispositivo entra o esce.
 *
 * NON esegue (e non eseguira') alcuna azione sui dispositivi altrui:
 * nessuna disconnessione forzata, nessun ARP/deauth spoofing. E' pensato
 * per l'amministrazione della propria rete domestica.
 *
 * Compilazione: cc -O2 -Wall -Wextra -o wifi_check wifi_check.c
 * Aiuto:        ./wifi_check -h
 *
 * Licenza: MIT (vedi file LICENSE del repository)
 */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_PORTS 16
#define MAX_KNOWN 256

typedef struct {
    int alive;
    unsigned open_mask;
    char mac[18];
    char hostname[128];
    const char *known_name; /* NULL se non in elenco */
} Host;

typedef struct {
    char mac[18];
    char name[192];
} KnownDevice;

/* ---------------- impostazioni da riga di comando ---------------- */
static int g_ports[MAX_PORTS] = {22, 53, 80, 443, 445, 8080};
static int g_nports = 6;
static int g_timeout_ms = 800;
static int g_resolve_dns = 1;
static int g_watch_seconds = 0;
static int g_learn = 0;
static const char *g_known_file = NULL;
static const char *g_csv_file = NULL;

/* ---------------- stato ---------------- */
static Host g_hosts[256];
static Host g_prev_hosts[256];
static KnownDevice g_known[MAX_KNOWN];
static int g_nknown = 0;
static volatile sig_atomic_t g_stop = 0;

static void handle_sigint(int signum) {
    (void)signum;
    g_stop = 1;
}

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000L + tv.tv_usec / 1000;
}

static void format_time(char *buf, size_t size, const char *fmt) {
    time_t t = time(NULL);
    struct tm tm_val;
    localtime_r(&t, &tm_val);
    strftime(buf, size, fmt, &tm_val);
}

/* ------------------------------------------------------------------ */
/* Indirizzi MAC                                                       */
/* ------------------------------------------------------------------ */

/* Normalizza un MAC testuale (macOS a volte omette gli zeri iniziali). */
static int normalize_mac(const char *input, char *output) {
    unsigned b[6];
    if (sscanf(input, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return 0;
    for (int i = 0; i < 6; i++)
        if (b[i] > 255) return 0;
    snprintf(output, 18, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    return 1;
}

/* Bit "locally administered": tipico degli indirizzi privati/casuali
 * usati di default da iPhone e Android recenti. */
static int is_private_mac(const char *mac) {
    unsigned first_byte = 0;
    if (sscanf(mac, "%2x", &first_byte) != 1) return 0;
    return (first_byte & 0x02) != 0;
}

/* ------------------------------------------------------------------ */
/* Elenco dei dispositivi noti/presenti nell'abitazione                                         */
/* ------------------------------------------------------------------ */

static void load_known_devices(void) {
    FILE *f = fopen(g_known_file, "r");
    char line[320];
    if (!f) return; /* file non ancora creato: va bene, l'elenco resta vuoto */
    while (g_nknown < MAX_KNOWN && fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char mac_raw[64], name[192] = "";
        int fields = sscanf(line, "%63s %191[^\n]", mac_raw, name);
        if (fields < 1) continue;
        if (!normalize_mac(mac_raw, g_known[g_nknown].mac)) continue;
        snprintf(g_known[g_nknown].name, sizeof g_known[g_nknown].name, "%s",
                 fields == 2 ? name : "(senza nome)");
        g_nknown++;
    }
    fclose(f);
}

static const char *find_known_device(const char *mac) {
    for (int i = 0; i < g_nknown; i++)
        if (strcmp(g_known[i].mac, mac) == 0) return g_known[i].name;
    return NULL;
}

/* Aggiunge all'elenco i dispositivi attualmente connessi e non ancora noti. */
static void learn_current_devices(int own_host) {
    FILE *f = fopen(g_known_file, "a");
    int added = 0;
    if (!f) { perror("impossibile aprire il file dei dispositivi noti"); return; }
    for (int h = 1; h <= 254; h++) {
        Host *host = &g_hosts[h];
        if (!host->alive || h == own_host || !host->mac[0] || host->known_name) continue;
        fprintf(f, "%s dispositivo-%d\n", host->mac, h);
        added++;
    }
    fclose(f);
    printf("Aggiunti %d dispositivi a %s. Apri il file e assegna un nome a ciascuno.\n",
           added, g_known_file);
}

/* ------------------------------------------------------------------ */
/* Rilevamento interfaccia di rete                                     */
/* ------------------------------------------------------------------ */

static int find_interface(const char *wanted, char *ifname_out, struct in_addr *ip_out) {
    struct ifaddrs *addrs, *cur;
    int found = 0;
    if (getifaddrs(&addrs) < 0) return 0;
    for (cur = addrs; cur; cur = cur->ifa_next) {
        if (!cur->ifa_addr || cur->ifa_addr->sa_family != AF_INET) continue;
        if (!(cur->ifa_flags & IFF_UP) || (cur->ifa_flags & IFF_LOOPBACK)) continue;
        if (wanted && strcmp(wanted, cur->ifa_name) != 0) continue;
        *ip_out = ((struct sockaddr_in *)cur->ifa_addr)->sin_addr;
        strncpy(ifname_out, cur->ifa_name, IF_NAMESIZE - 1);
        ifname_out[IF_NAMESIZE - 1] = '\0';
        found = 1;
        break;
    }
    freeifaddrs(addrs);
    return found;
}

/* ------------------------------------------------------------------ */
/* Scansione TCP (connect non bloccante su una subnet /24)             */
/* ------------------------------------------------------------------ */

static void scan_port_across_subnet(uint32_t subnet_base, int port_index, int own_host) {
    int sockets[256];
    fd_set write_set;
    int max_fd = -1, pending = 0;

    FD_ZERO(&write_set);
    for (int h = 0; h < 256; h++) sockets[h] = -1;

    for (int h = 1; h <= 254; h++) {
        if (h == own_host) continue;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        fcntl(fd, F_SETFL, O_NONBLOCK);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(g_ports[port_index]);
        addr.sin_addr.s_addr = htonl(subnet_base | (uint32_t)h);

        int rc = connect(fd, (struct sockaddr *)&addr, sizeof addr);
        if (rc == 0) {
            g_hosts[h].alive = 1;
            g_hosts[h].open_mask |= 1u << port_index;
            close(fd);
        } else if (errno == EINPROGRESS) {
            sockets[h] = fd;
            FD_SET(fd, &write_set);
            if (fd > max_fd) max_fd = fd;
            pending++;
        } else {
            if (errno == ECONNREFUSED) g_hosts[h].alive = 1; /* host vivo, porta chiusa */
            close(fd);
        }
    }

    long deadline = now_ms() + g_timeout_ms;
    while (pending > 0) {
        long remaining = deadline - now_ms();
        if (remaining <= 0) break;
        struct timeval tv = {remaining / 1000, (remaining % 1000) * 1000};
        fd_set ready = write_set;
        if (select(max_fd + 1, NULL, &ready, NULL, &tv) <= 0) break;

        for (int h = 1; h <= 254; h++) {
            if (sockets[h] < 0 || !FD_ISSET(sockets[h], &ready)) continue;
            int err = 0;
            socklen_t len = sizeof err;
            getsockopt(sockets[h], SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) {
                g_hosts[h].alive = 1;
                g_hosts[h].open_mask |= 1u << port_index;
            } else if (err == ECONNREFUSED) {
                g_hosts[h].alive = 1;
            }
            FD_CLR(sockets[h], &write_set);
            close(sockets[h]);
            sockets[h] = -1;
            pending--;
        }
    }
    for (int h = 1; h <= 254; h++)
        if (sockets[h] >= 0) close(sockets[h]);
}

/* ------------------------------------------------------------------ */
/* Tabella ARP del sistema (per ottenere i MAC)                        */
/* ------------------------------------------------------------------ */

static void record_arp_entry(uint32_t subnet_base, const char *ip_str, const char *mac_raw) {
    struct in_addr addr;
    char mac[18];
    if (!normalize_mac(mac_raw, mac)) return; /* scarta voci tipo "(incomplete)" */
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return;
    uint32_t ip_val = ntohl(addr.s_addr);
    if ((ip_val & 0xFFFFFF00u) != subnet_base) return;
    int h = (int)(ip_val & 0xFF);
    if (h < 1 || h > 254) return;
    memcpy(g_hosts[h].mac, mac, sizeof mac);
    g_hosts[h].alive = 1;
}

static void load_arp_table(uint32_t subnet_base) {
    char line[256];
#ifdef __APPLE__
    /* esempio di riga: ? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet] */
    FILE *f = popen("arp -an 2>/dev/null", "r");
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        char ip[64], mac[64];
        if (sscanf(line, "%*s (%63[^)]) at %63s", ip, mac) == 2)
            record_arp_entry(subnet_base, ip, mac);
    }
    pclose(f);
#else
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return;
    if (!fgets(line, sizeof line, f)) { fclose(f); return; } /* intestazione */
    while (fgets(line, sizeof line, f)) {
        char ip[64], hw_type[32], flags[16], mac[64];
        if (sscanf(line, "%63s %31s %15s %63s", ip, hw_type, flags, mac) == 4 &&
            strcmp(flags, "0x0") != 0)
            record_arp_entry(subnet_base, ip, mac);
    }
    fclose(f);
#endif
}

/* ------------------------------------------------------------------ */
/* Nome host (DNS/mDNS inverso) e SSID                                 */
/* ------------------------------------------------------------------ */

static void resolve_hostname(uint32_t ip_val, char *out, size_t size) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
#if defined(__APPLE__) && defined(__MACH__)
    addr.sin_len = sizeof addr;
#endif
    addr.sin_addr.s_addr = htonl(ip_val);
    if (getnameinfo((struct sockaddr *)&addr, sizeof addr, out, (socklen_t)size, NULL, 0,
                     NI_NAMEREQD) != 0)
        out[0] = '\0';
}

static void print_ssid(const char *ifname) {
    char cmd[128], line[256];
#ifdef __APPLE__
    snprintf(cmd, sizeof cmd, "networksetup -getairportnetwork %s 2>/dev/null", ifname);
#else
    (void)ifname;
    snprintf(cmd, sizeof cmd, "iwgetid -r 2>/dev/null");
#endif
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return;
    if (fgets(line, sizeof line, pipe)) {
        line[strcspn(line, "\n")] = '\0';
#ifdef __APPLE__
        char *marker = strstr(line, "Current Wi-Fi Network: ");
        if (marker) printf("Rete Wi-Fi (SSID): %s\n", marker + strlen("Current Wi-Fi Network: "));
#else
        if (line[0]) printf("Rete Wi-Fi (SSID): %s\n", line);
#endif
    }
    pclose(pipe);
}

/* ------------------------------------------------------------------ */
/* Una scansione completa                                              */
/* ------------------------------------------------------------------ */

static void run_full_scan(uint32_t subnet_base, int own_host) {
    memset(g_hosts, 0, sizeof g_hosts);
    for (int i = 0; i < g_nports; i++) scan_port_across_subnet(subnet_base, i, own_host);
    load_arp_table(subnet_base);
    for (int h = 1; h <= 254; h++) {
        Host *host = &g_hosts[h];
        if (!host->alive || h == own_host) continue;
        if (host->mac[0]) host->known_name = find_known_device(host->mac);
        if (g_resolve_dns && !g_stop)
            resolve_hostname(subnet_base | (uint32_t)h, host->hostname, sizeof host->hostname);
    }
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

static void ip_at(uint32_t subnet_base, int h, char *out) {
    struct in_addr addr;
    addr.s_addr = htonl(subnet_base | (uint32_t)h);
    inet_ntop(AF_INET, &addr, out, INET_ADDRSTRLEN);
}

static void format_open_ports(unsigned mask, char *out, size_t size) {
    size_t used = 0;
    out[0] = '\0';
    for (int i = 0; i < g_nports; i++) {
        if (!(mask & (1u << i))) continue;
        int n = snprintf(out + used, size - used, "%s%d", used ? "," : "", g_ports[i]);
        if (n < 0 || (size_t)n >= size - used) break;
        used += (size_t)n;
    }
    if (!out[0]) snprintf(out, size, "-");
}

static void format_note(const Host *host, char *out, size_t size) {
    out[0] = '\0';
    if (host->known_name)
        snprintf(out, size, "%s", host->known_name);
    else if (g_known_file)
        snprintf(out, size, "sconosciuto");
    if (host->mac[0] && is_private_mac(host->mac)) {
        size_t len = strlen(out);
        snprintf(out + len, size - len, "%s[MAC privato]", len ? " " : "");
    }
}

static void print_table(uint32_t subnet_base, int own_host) {
    int total = 0, unknown = 0;
    printf("%-16s %-18s %-26s %-14s %s\n", "IP", "MAC", "Nome host", "Porte", "Note");
    printf("---------------------------------------------------------------------------------\n");
    for (int h = 1; h <= 254; h++) {
        Host *host = &g_hosts[h];
        if (!host->alive || h == own_host) continue;
        char ip[INET_ADDRSTRLEN], ports[96], note[300];
        ip_at(subnet_base, h, ip);
        format_open_ports(host->open_mask, ports, sizeof ports);
        format_note(host, note, sizeof note);
        printf("%-16s %-18s %-26.26s %-14.14s %s\n", ip, host->mac[0] ? host->mac : "?",
               host->hostname[0] ? host->hostname : "-", ports, note);
        total++;
        if (g_known_file && !host->known_name) unknown++;
    }
    printf("\nDispositivi rilevati: %d (escluso questo computer)", total);
    if (g_known_file) printf(" | sconosciuti: %d", unknown);
    printf("\n");
}

static void print_differences(uint32_t subnet_base, int own_host) {
    char timestamp[16];
    int changes = 0;
    format_time(timestamp, sizeof timestamp, "%H:%M:%S");
    for (int h = 1; h <= 254; h++) {
        if (h == own_host) continue;
        Host *cur = &g_hosts[h], *prev = &g_prev_hosts[h];
        char ip[INET_ADDRSTRLEN], note[300];
        ip_at(subnet_base, h, ip);

        if (cur->alive && !prev->alive) {
            format_note(cur, note, sizeof note);
            printf("[%s] [+] ENTRATO  %-15s %-18s %-20.20s %s\n", timestamp, ip,
                   cur->mac[0] ? cur->mac : "?", cur->hostname[0] ? cur->hostname : "-", note);
            if (g_known_file && !cur->known_name)
                printf("             ^ non presente nell'elenco dei dispositivi noti\n");
            changes++;
        } else if (!cur->alive && prev->alive) {
            printf("[%s] [-] USCITO   %-15s %-18s\n", timestamp, ip,
                   prev->mac[0] ? prev->mac : "?");
            changes++;
        } else if (cur->alive && prev->alive && cur->mac[0] && prev->mac[0] &&
                   strcmp(cur->mac, prev->mac) != 0) {
            printf("[%s] [!] %s ha cambiato MAC (%s -> %s)\n", timestamp, ip, prev->mac, cur->mac);
            changes++;
        }
    }
    if (!changes) printf("[%s] nessuna variazione\n", timestamp);
    fflush(stdout);
}

static void write_csv_field(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"') fputc('"', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

static void append_csv_row(uint32_t subnet_base, int own_host) {
    FILE *f = fopen(g_csv_file, "a");
    char timestamp[32];
    if (!f) { perror("impossibile aprire il file CSV"); return; }
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0) fprintf(f, "timestamp,ip,mac,hostname,porte,note\n");
    format_time(timestamp, sizeof timestamp, "%Y-%m-%d %H:%M:%S");
    for (int h = 1; h <= 254; h++) {
        Host *host = &g_hosts[h];
        if (!host->alive || h == own_host) continue;
        char ip[INET_ADDRSTRLEN], ports[96], note[300];
        ip_at(subnet_base, h, ip);
        format_open_ports(host->open_mask, ports, sizeof ports);
        format_note(host, note, sizeof note);
        fprintf(f, "%s,%s,", timestamp, ip);
        write_csv_field(f, host->mac);      fputc(',', f);
        write_csv_field(f, host->hostname); fputc(',', f);
        write_csv_field(f, ports);          fputc(',', f);
        write_csv_field(f, note);           fputc('\n', f);
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Riga di comando                                                     */
/* ------------------------------------------------------------------ */

static void print_usage(const char *prog) {
    printf(
        "Uso: %s [opzioni]\n"
        "\n"
        "Rileva i dispositivi attivi sulla propria rete locale.\n"
        "\n"
        "  -i IF     interfaccia di rete da usare (macOS: en0, Linux: wlan0...)\n"
        "  -p LISTA  porte da provare, separate da virgola (default 22,53,80,443,445,8080)\n"
        "  -t MS     timeout per porta in millisecondi (default 800)\n"
        "  -k FILE   elenco dei dispositivi noti: una riga \"MAC nome\" per ciascuno\n"
        "  -a        aggiunge i dispositivi attualmente connessi al file indicato con -k\n"
        "  -o FILE   aggiunge ogni scansione a un file CSV\n"
        "  -w SEC    modalita' monitor: ripete la scansione ogni SEC secondi (Ctrl+C per fermare)\n"
        "  -n        non risolvere i nomi host (scansione piu' veloce)\n"
        "  -h        mostra questo aiuto\n"
        "\n"
        "Esempi:\n"
        "  %s                          scansione singola della rete corrente\n"
        "  %s -k noti.txt -a           registra i dispositivi attuali come \"noti\"\n"
        "  %s -k noti.txt -w 30        monitor continuo, segnala gli sconosciuti\n",
        prog, prog, prog, prog);
}

static int parse_port_list(char *list) {
    g_nports = 0;
    for (char *tok = strtok(list, ","); tok && g_nports < MAX_PORTS; tok = strtok(NULL, ",")) {
        int value = atoi(tok);
        if (value < 1 || value > 65535) return 0;
        g_ports[g_nports++] = value;
    }
    return g_nports > 0;
}

int main(int argc, char **argv) {
    const char *wanted_if = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "i:p:t:k:ao:w:nh")) != -1) {
        switch (opt) {
        case 'i': wanted_if = optarg; break;
        case 'p':
            if (!parse_port_list(optarg)) {
                fprintf(stderr, "Lista di porte non valida.\n");
                return 1;
            }
            break;
        case 't': g_timeout_ms = atoi(optarg); if (g_timeout_ms < 50) g_timeout_ms = 50; break;
        case 'k': g_known_file = optarg; break;
        case 'a': g_learn = 1; break;
        case 'o': g_csv_file = optarg; break;
        case 'w': g_watch_seconds = atoi(optarg); if (g_watch_seconds < 1) g_watch_seconds = 1; break;
        case 'n': g_resolve_dns = 0; break;
        case 'h': print_usage(argv[0]); return 0;
        default: print_usage(argv[0]); return 1;
        }
    }
    if (g_learn && !g_known_file) {
        fprintf(stderr, "L'opzione -a richiede anche -k FILE.\n");
        return 1;
    }

    char ifname[IF_NAMESIZE] = "";
    struct in_addr local_ip;
    int found;
    if (wanted_if) {
        found = find_interface(wanted_if, ifname, &local_ip);
    } else {
        found = 0;
#ifdef __APPLE__
        found = find_interface("en0", ifname, &local_ip); /* Wi-Fi sui Mac, di solito */
#endif
        if (!found) found = find_interface(NULL, ifname, &local_ip);
    }
    if (!found) {
        fprintf(stderr, "Nessuna interfaccia di rete attiva trovata.\n");
        return 1;
    }

    if (g_known_file) load_known_devices();
    signal(SIGINT, handle_sigint);

    uint32_t local_ip_val = ntohl(local_ip.s_addr);
    uint32_t subnet_base = local_ip_val & 0xFFFFFF00u;
    int own_host = (int)(local_ip_val & 0xFF);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_ip, ip_str, sizeof ip_str);
    printf("Interfaccia: %s | IP: %s | Scansione: %u.%u.%u.0/24\n", ifname, ip_str,
           (subnet_base >> 24) & 255, (subnet_base >> 16) & 255, (subnet_base >> 8) & 255);
    print_ssid(ifname);
    if (g_known_file) printf("Dispositivi noti caricati: %d\n", g_nknown);
    if (g_watch_seconds) printf("Modalita' monitor ogni %d s. Premi Ctrl+C per uscire.\n", g_watch_seconds);
    printf("Scansione in corso...\n\n");

    int round = 0;
    do {
        run_full_scan(subnet_base, own_host);
        if (g_stop) break;

        if (round == 0 || !g_watch_seconds)
            print_table(subnet_base, own_host);
        else
            print_differences(subnet_base, own_host);

        if (g_csv_file) append_csv_row(subnet_base, own_host);
        if (g_learn && round == 0) learn_current_devices(own_host);

        memcpy(g_prev_hosts, g_hosts, sizeof g_hosts);
        round++;
        for (int s = 0; g_watch_seconds && s < g_watch_seconds && !g_stop; s++) sleep(1);
    } while (g_watch_seconds && !g_stop);

    if (g_watch_seconds) printf("\nMonitor terminato.\n");
    return 0;
}
