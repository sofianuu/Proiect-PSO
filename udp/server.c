#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define MAXLINE 1024
#define DNS_PORT 8080
#define DNS_RESPONSE 0x8180
#define DNS_NXDOMAIN 0x8183
#define MAX_LINE_LENGTH 256

// Structura header-ului DNS
typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} DNSHeader;

// Structura interogării DNS
typedef struct {
    char *qname;
    unsigned short qtype;
    unsigned short qclass;
} DNSQuery;

// Funcție pentru a procesa cererea DNS și a extrage tipul de înregistrare cerut
void processDNSRequest(unsigned char *packet, DNSQuery *query) {
    DNSHeader *header = (DNSHeader*)packet;

    // Verificăm dacă există interogări în pachetul DNS
    if (header->qdcount > 0) {
        unsigned char *query_section = packet + sizeof(DNSHeader);

        // Extragem numele domeniului
        query->qname = (char*)query_section; // Aici trebuie să implementezi logica pentru a extrage corect numele domeniului

        // Avansăm în secțiunea de interogare pentru a extrage tipul și clasa
        query->qtype = (query_section + strlen(query->qname) + 1)[0] << 8 | (query_section + strlen(query->qname) + 2)[0];
        query->qclass = (query_section + strlen(query->qname) + 3)[0] << 8 | (query_section + strlen(query->qname) + 4)[0];

        // Afișăm tipul cererii
        printf("Tipul cererii: %d\n", query->qtype);
    }
}

// Funcție care caută în fișierul de zonă și returnează IP-ul asociat cu un domeniu
char* getDNSRecordFromZone(const char *domain_name, const char *record_type) {
    // Calea fișierului de zonă
    const char *zone_file = "/home/alexia/Desktop/PSO/udp/zones/db.exemplu.com";
    static char record_value[INET_ADDRSTRLEN]; // Buffer pentru valoarea înregistrării
    char command[512];

    // Construim comanda grep bazată pe domeniu și tipul de înregistrare
    snprintf(command, sizeof(command),
             "grep -w \"%s   IN   %s\" %s | rev | cut -f1 -d\" \" | rev",
             domain_name, record_type, zone_file);

    // Executăm comanda folosind popen
    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("Nu s-a putut executa comanda");
        return NULL;
    }

    // Citim rezultatul din comanda grep
    if (fgets(record_value, sizeof(record_value), fp)) {
        // Eliminăm newline-ul de la sfârșit
        record_value[strcspn(record_value, "\n")] = '\0';
        printf("valoare: %s\n", record_value);
        pclose(fp);
        return record_value;
    }

    pclose(fp);
    return NULL; // Dacă nu se găsește înregistrarea dorită
}

// Funcție pentru a extrage domeniul din cererea DNS
void extract_domain_from_dns_request(char *request, char *domain_name) {
    int i = 12;  // Punctul de început pentru domeniu în cererea DNS (după header)
    int j = 0;

    while (i < MAXLINE && request[i] != 0) {
        unsigned char len = request[i];
        i++;
        for (int k = 0; k < len; k++) {
            domain_name[j++] = request[i + k];
        }
        if (request[i + len] != 0) {
            domain_name[j++] = '.';
        }
        i += len;
    }
    domain_name[j++] = '.';
    domain_name[j] = '\0';
}

// Crearea răspunsului DNS pentru client
void create_dns_response(unsigned char *response, const char *domain_name, unsigned short qtype,char* ip) {
    unsigned char *ptr = response;

    // Adăugăm header-ul DNS
    DNSHeader *header = (DNSHeader*)ptr;
    header->id = htons(1234); // ID-ul cererii, poate fi același cu ID-ul cererii primite
    header->flags = htons(DNS_RESPONSE); // Setăm flag-ul pentru răspuns
    header->qdcount = htons(1); // O singură întrebare
    header->ancount = htons(1); // Un singur răspuns
    header->nscount = 0;
    header->arcount = 0;
    ptr += sizeof(DNSHeader);

    // Adăugăm secțiunea de interogare
    unsigned char *qname = ptr;
    const char *dot = domain_name;
    while (*dot) {
        unsigned char len = 0;
        while (*dot && *dot != '.') {
            qname[len++] = *dot++;
        }
        qname[len] = '\0';
        ptr += len + 1;
        if (*dot) dot++; // Sărim peste punctul '.'
    }

    unsigned short *qtype_ptr = (unsigned short*)ptr;
    *qtype_ptr = htons(qtype); // Tipul cererii (A, MX etc.)
    ptr += sizeof(unsigned short);

    unsigned short *qclass_ptr = (unsigned short*)ptr;
    *qclass_ptr = htons(1); // Clasa IN
    ptr += sizeof(unsigned short);

    // Adăugăm secțiunea de răspuns (A)
    unsigned char *answer_name = ptr;
    *answer_name = 0; // Secțiunea de răspuns
    ptr++;

    unsigned short *type_ptr = (unsigned short*)ptr;
    *type_ptr = htons(qtype); // Tipul de înregistrare (A)
    ptr += sizeof(unsigned short);

    unsigned short *class_ptr = (unsigned short*)ptr;
    *class_ptr = htons(1); // Clasa IN
    ptr += sizeof(unsigned short);

    unsigned int *ttl_ptr = (unsigned int*)ptr;
    *ttl_ptr = htonl(3600); // TTL de 1 oră
    ptr += sizeof(unsigned int);

    unsigned short *data_len_ptr = (unsigned short*)ptr;
    *data_len_ptr = htons(4); // Lungimea datelor pentru un IP (4 octeți)
    ptr += sizeof(unsigned short);

    // Adresa IP
    inet_pton(AF_INET, ip, ptr); // Convertește IP-ul la format binar
    ptr += 4;

    // Calculăm lungimea totală a răspunsului
    int response_len = ptr - response;
    printf("Lungimea răspunsului: %d\n", response_len);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    unsigned char buffer[MAXLINE];
    socklen_t len;
    ssize_t n;

    // Crează socketul UDP
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Eroare la crearea socketului");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));

    // Configurează adresa serverului
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    // Leagă socket-ul de adresa și portul specificat
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Eroare la bind");
        exit(1);
    }

    printf("Serverul DNS rulează pe portul %d...\n", DNS_PORT);

    // Așteaptă cereri de la client
    while (1) {
        len = sizeof(client_addr);

        // Primește mesajul de la client
        n = recvfrom(sockfd, buffer, MAXLINE, 0, (struct sockaddr *)&client_addr, &len);
        if (n < 0) {
            perror("Eroare la recvfrom");
            exit(1);
        }

        // Procesăm cererea DNS
        DNSQuery query;
        processDNSRequest(buffer, &query);

        // Extragem domeniul din cererea DNS
        char domain_name[MAX_LINE_LENGTH];
        extract_domain_from_dns_request(buffer, domain_name);
        printf("Domeniul cerut: %s\n", domain_name);

        // Căutăm înregistrarea DNS în fișierul de zonă
        char *ip = getDNSRecordFromZone(domain_name, "A");

        // Creăm răspunsul DNS
        unsigned char response[MAXLINE];
        create_dns_response(response, domain_name, 1,ip); // 1 pentru tipul A

        printf("raspuns: %s",response);

        // Trimitem răspunsul înapoi clientului
        sendto(sockfd, response, sizeof(response), 0, (struct sockaddr *)&client_addr, len);
    }

    close(sockfd);
    return 0;
}
