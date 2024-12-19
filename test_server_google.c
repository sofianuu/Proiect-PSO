#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>

#define MAX_PACKET_SIZE 65535

// Funcția query_dns care caută tipuri de înregistrări DNS (A, AAAA, TXT)
char* query_dns_a(const char *domain, const char *dns_server) {
    unsigned char query_buf[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    int query_len, i;
    static char ip_str[INET_ADDRSTRLEN]; // pentru a salva adresa IP găsită

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, dns_server, &dest.sin_addr);

    // Folosim resolv pentru a trimite interogarea DNS
    query_len = res_query(domain, ns_c_in, ns_t_a, query_buf, sizeof(query_buf));
    if (query_len < 0) {
        perror("res_query failed");
        return NULL;
    }

    // Procesăm răspunsul
    if (ns_initparse(query_buf, query_len, &handle) < 0) {
        perror("ns_initparse failed");
        return NULL;
    }

    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr failed");
            return NULL;
        }

        // Verifică tipul de înregistrare (A, CNAME, etc.)
        if (ns_rr_type(rr) == ns_t_a) {
            struct in_addr ip_addr;
            memcpy(&ip_addr, ns_rr_rdata(rr), sizeof(ip_addr));

            // Convertește adresa IP în formatul șirului de caractere
            if (inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)) != NULL) {
                return ip_str; // Returnează prima adresă găsită
            }
        }
    }

    // Dacă nu s-a găsit nici o adresă
    return NULL;
}

// Funcția query_dns_aaaa care caută înregistrări de tip AAAA (IPv6)
void query_dns_aaaa(const char *domain, const char *dns_server) {
    unsigned char query_buf[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    int query_len, i;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, dns_server, &dest.sin_addr);

    // Folosim resolv pentru a trimite interogarea DNS de tip AAAA
    query_len = res_query(domain, ns_c_in, ns_t_aaaa, query_buf, sizeof(query_buf));
    if (query_len < 0) {
        perror("res_query failed");
        return;
    }

    // Procesăm răspunsul
    if (ns_initparse(query_buf, query_len, &handle) < 0) {
        perror("ns_initparse failed");
        return;
    }

    // Iterăm prin răspunsuri și extragem adresele IPv6
    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr failed");
            return;
        }

        // Verificăm dacă înregistrarea este de tip AAAA (IPv6)
        if (ns_rr_type(rr) == ns_t_aaaa) {
            char ip_addr[INET6_ADDRSTRLEN];
            // Copiem datele IPv6 și le convertim într-un format lizibil
            struct in6_addr *ipv6_addr = (struct in6_addr *)ns_rr_rdata(rr);
            if (inet_ntop(AF_INET6, ipv6_addr, ip_addr, INET6_ADDRSTRLEN)) {
                printf("Domeniul %s are IP-ul (IPv6) %s\n", domain, ip_addr);
            } else {
                perror("inet_ntop failed");
            }
        }
    }
}

// Funcția query_dns_txt care caută înregistrări de tip TXT
void query_dns_txt(const char *domain, const char *dns_server) {
    unsigned char query_buf[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    int query_len, i;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, dns_server, &dest.sin_addr);

    // Folosim resolv pentru a trimite interogarea DNS de tip TXT
    query_len = res_query(domain, ns_c_in, ns_t_txt, query_buf, sizeof(query_buf));
    if (query_len < 0) {
        perror("res_query failed");
        return;
    }

    // Procesăm răspunsul
    if (ns_initparse(query_buf, query_len, &handle) < 0) {
        perror("ns_initparse failed");
        return;
    }

    // Iterăm prin răspunsuri și extragem înregistrările TXT
    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr failed");
            return;
        }

        // Verificăm dacă înregistrarea este de tip TXT
        if (ns_rr_type(rr) == ns_t_txt) {
            const unsigned char *txt_data = ns_rr_rdata(rr); // Pointer const pentru datele TXT
            unsigned int txt_len = ns_rr_rdlen(rr); // Folosim ns_rr_rdlen pentru lungimea datelor

            // Afișăm datele din înregistrarea TXT
            printf("Domeniul %s are înregistrarea TXT: ", domain);
            for (unsigned int j = 0; j < txt_len; j++) {
                printf("%c", txt_data[j]);
            }
            printf("\n");
        }
    }
}

// Funcția query_dns care caută diferite tipuri de înregistrări DNS (A, AAAA, TXT)
char* query_dns(const char *domain, const char *dns_server, int query_type) {
    unsigned char query_buf[MAX_PACKET_SIZE];  // Mărirea bufferului
    ns_msg handle;
    ns_rr rr;
    int query_len, i;
    static char result[1024];  // Buffer static pentru a stoca rezultatul

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, dns_server, &dest.sin_addr);

    // Alegem tipul de interogare DNS
    int query_class = ns_c_in; // CLasa de interogare (internet)
    
    // Realizăm interogarea DNS
    query_len = res_query(domain, query_class, query_type, query_buf, sizeof(query_buf));
    if (query_len < 0) {
        perror("res_query failed");
        exit(-1);
    }

    // Procesăm răspunsul
    if (ns_initparse(query_buf, query_len, &handle) < 0) {
        perror("ns_initparse failed");
        exit(-1);
    }

    // Iterăm prin răspunsuri și procesăm fiecare înregistrare
    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr failed");
            exit(-1);
        }

        // Procesăm înregistrările de tip A (IPv4)
        if (query_type == ns_t_a && ns_rr_type(rr) == ns_t_a) {
            struct in_addr ip_addr;
            memcpy(&ip_addr, ns_rr_rdata(rr), sizeof(ip_addr));
            snprintf(result, sizeof(result), "Domeniul %s are IP-ul (IPv4) %s", domain, inet_ntoa(ip_addr));
            return result;
        }
        
        // Procesăm înregistrările de tip AAAA (IPv6)
        else if (query_type == ns_t_aaaa && ns_rr_type(rr) == ns_t_aaaa) {
            char ip_addr[INET6_ADDRSTRLEN];
            memcpy(ip_addr, ns_rr_rdata(rr), sizeof(struct in6_addr));
            snprintf(result, sizeof(result), "Domeniul %s are IP-ul (IPv6) %s", domain, inet_ntop(AF_INET6, &ip_addr, ip_addr, INET6_ADDRSTRLEN));
            return result;
        }

        // Procesăm înregistrările de tip TXT
        else if (query_type == ns_t_txt && ns_rr_type(rr) == ns_t_txt) {
            const unsigned char *txt_data = ns_rr_rdata(rr); // Pointer pentru datele TXT
            unsigned int txt_len = ns_rr_rdlen(rr); // Lungimea datelor TXT

            // Afișează înregistrarea TXT
            snprintf(result, sizeof(result), "Domeniul %s are înregistrarea TXT: ", domain);
            for (unsigned int j = 0; j < txt_len; j++) {
                snprintf(result + strlen(result), sizeof(result) - strlen(result), "%c", txt_data[j]);
            }
            return result;
        }
    }

    return NULL;  // Returnează NULL dacă nu s-au găsit înregistrări
}


// Funcția main care va apela query_dns
int main() {
    const char *domain = "mta.ro"; // Domeniul pentru care dorim să căutăm IP-ul
    const char *dns_server = "8.8.8.8";  // Serverul DNS (de exemplu, serverul Google DNS)

// Pentru cererea de tip A (IPv4)
    char *ip = query_dns_a(domain, dns_server);

    if (ip != NULL) {
        printf("Adresa IP pentru %s este: %s\n", domain, ip);
    } else {
        printf("Nu s-a găsit nicio adresă IP pentru %s\n", domain);
    }

    printf("Interogare pentru tipul AAAA (IPv6): \n");
    //query_dns_aaaa(domain, dns_server);

    printf("Interogare pentru tipul TXT: \n");
    //query_dns_txt(domain, dns_server);

    // Pentru cererea de tip AAAA (IPv6)
    //printf("\nInterogare pentru tipul AAAA (IPv6): %s\n",query_dns(domain, dns_server, ns_t_aaaa));
    //query_dns(domain, dns_server, ns_t_aaaa);

    // Pentru cererea de tip TXT
    //printf("\nInterogare pentru tipul TXT: %s\n", query_dns(domain, dns_server, ns_t_txt));
    //query_dns(domain, dns_server, ns_t_txt);


    return 0;
}
