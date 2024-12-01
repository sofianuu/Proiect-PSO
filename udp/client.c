#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 8080
#define MAXLINE 1024

// Structura antetului DNS
struct DNSHeader {
    unsigned short id; // ID-ul cererii
    unsigned char rd :1; // Recursion Desired
    unsigned char tc :1; // Truncated Message
    unsigned char aa :1; // Authoritative Answer
    unsigned char opcode :4; // Opcode
    unsigned char qr :1; // Query/Response Flag

    unsigned char rcode :4; // Return Code
    unsigned char cd :1; // Checking Disabled
    unsigned char ad :1; // Authenticated Data
    unsigned char z :1; // Reserved
    unsigned char ra :1; // Recursion Available

    unsigned short q_count; // Număr întrebări
    unsigned short ans_count; // Număr răspunsuri
    unsigned short auth_count; // Număr autorități
    unsigned short add_count; // Număr secțiuni adiționale
};

// Structura întrebării DNS
struct DNSQuestion {
    char *qname; // Numele domeniului
    unsigned short qtype; // Tipul întrebării (A, AAAA, etc.)
    unsigned short qclass; // Clasa (de obicei 1 pentru Internet)
};

// Funcție pentru a transforma un nume de domeniu în format DNS
void formatDNSName(char *dns, char *host) {
    int lock = 0;
    strcat(host, ".");
    for (int i = 0; i < strlen(host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

// Funcție pentru a construi un pachet DNS
int createDNSPacket(char *domain, unsigned char *packet) {
    struct DNSHeader dnsHeader = {0};
    dnsHeader.id = htons(1234); // ID-ul cererii
    dnsHeader.qr = 0; // Query
    dnsHeader.opcode = 0; // Standard query
    dnsHeader.aa = 0; // Non-authoritative
    dnsHeader.tc = 0; // Non-truncated
    dnsHeader.rd = 1; // Recursion desired
    dnsHeader.ra = 0; // No recursion available
    dnsHeader.z = 0; // Reserved
    dnsHeader.ad = 0; // Not authenticated
    dnsHeader.cd = 0; // Not disabled
    dnsHeader.rcode = 0; // No error
    dnsHeader.q_count = htons(1); // O întrebare
    dnsHeader.ans_count = 0;
    dnsHeader.auth_count = 0;
    dnsHeader.add_count = 0;

    char qname[256];
    formatDNSName(qname, domain);

    struct DNSQuestion question;
    question.qname = qname;
    question.qtype = htons(1); // A record
    question.qclass = htons(1); // IN (Internet)

    int offset = 0;

    // Copiere antet DNS în buffer
    memcpy(packet + offset, &dnsHeader, sizeof(dnsHeader));
    offset += sizeof(dnsHeader);

    // Copiere nume domeniu în buffer
    memcpy(packet + offset, qname, strlen(qname) + 1);
    offset += strlen(qname) + 1;

    // Copiere tip și clasă în buffer
    memcpy(packet + offset, &question.qtype, sizeof(question.qtype));
    offset += sizeof(question.qtype);
    memcpy(packet + offset, &question.qclass, sizeof(question.qclass));
    offset += sizeof(question.qclass);

    return offset; // Lungimea totală a pachetului
}

// Extragerea IP-ului din răspunsul DNS     --aici ai probleme
void extractIPAddress(unsigned char *buffer, int n, char *domain) {
    // Lungimea numelui domeniului în format DNS
    int domain_len = strlen(domain) + 2; // +2 pentru formatul DNS (lungime și terminator)
    
    // Calculăm offset-ul inițial
    int offset = 12 + domain_len + 4; // 12 (antet DNS) + lungime domeniu + QTYPE și QCLASS (4 octeți)

    // Verificăm dacă offset-ul este valid
    if (offset + 4 > n) {
        printf("Pachet DNS corupt sau răspuns incomplet.\n");
        return;
    }

    // Extragerea adresei IP (presupunem că primul răspuns este un record A valid)
    unsigned char ip_address[4];
    memcpy(ip_address, &buffer[offset], 4);

    // Afișarea adresei IP
    printf("IP-ul pentru domeniul %s este: %d.%d.%d.%d\n",
           domain, ip_address[0], ip_address[1], ip_address[2], ip_address[3]);
}


int main() {
    int sockfd;
    struct sockaddr_in servaddr;
    unsigned char packet[512];

    // Creare socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Eroare la crearea socket-ului");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Configurare adresa serverului
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    while (1) {
        char domain[256];
        printf("Introduceți numele domeniului (sau 'exit' pentru a ieși): ");
        if (scanf("%255s", domain) != 1) {
            fprintf(stderr, "Eroare la citirea domeniului.\n");
            continue;
        }

        if (strcmp(domain, "exit") == 0) {
            break;
        }

        // Construire pachet DNS
        int packet_size = createDNSPacket(domain, packet);

        // Trimitere pachet către server
        sendto(sockfd, packet, packet_size, MSG_CONFIRM,
               (const struct sockaddr *)&servaddr, sizeof(servaddr));
        printf("Pachet DNS trimis pentru domeniul: %s\n", domain);

        // Așteaptă răspunsul de la server
        unsigned char buffer[MAXLINE];
        int n, len;
        n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &servaddr, &len);
        if (n < 0) {
            perror("Eroare la primirea răspunsului");
            continue;
        }

        printf("Răspuns primit de la server:\n");
        // Verifică codul de răspuns DNS
        unsigned char rcode = buffer[3] & 0x0F;  // Extrage rcode (4 lsb din octetul 3)
        if (rcode != 0) {
            printf("Eroare la rezolvarea domeniului: cod eroare %d\n", rcode);
            continue;
        }

        // Afișăm răspunsul DNS (poți procesa răspunsul DNS mai detaliat aici)
        for (int i = 0; i < n; i++) {
            printf("%02x ", buffer[i]);
        }
        printf("\n");

        // Apelează funcția pentru extragerea IP-ului
        extractIPAddress(buffer, n, domain);
    }

    close(sockfd);
    return 0;
}
