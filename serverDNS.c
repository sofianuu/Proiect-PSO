#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <ctype.h>
#include <arpa/nameser.h>

#include "dns.h" //header dns 

#define BUFFER_SIZE 1500
#define MAX_PACKET_SIZE 65535
#define MAX_DNS_BUFFER 65536


#define THREAD_NUM 5

int number=0;

typedef struct Received
{
    uint8_t  buffer[BUFFER_SIZE];
    int len;
    int sock;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
}Received;

typedef struct DNSCacheEntry {
    char* domain_name;
    char* record_value;
    char type_value[5];
    time_t timestamp;
    int ttl;
    struct DNSCacheEntry *next;
} DNSCacheEntry;

DNSCacheEntry *dns_cache = NULL;

static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x0080;
static const uint32_t RCODE_MASK = 0x000F;

struct Received recv_queue[256];
int queueCount=0;


pthread_mutex_t mutexQueue;
pthread_cond_t condQueue;

FILE *log_file = NULL;

void init_logging(const char *filename) {
    log_file = fopen(filename, "a");
    if (!log_file) {
        perror("Eroare la deschiderea fișierului de log");
    }
}

void log_message(const char *level, const char *format, ...) {
    if (!log_file) {
        fprintf(stderr, "Fișierul de log nu este deschis!\n");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buffer[20];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", t);

    fprintf(log_file, "[%s] %s: ", time_buffer, level);

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fflush(log_file);
}

void close_logging() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void rotate_logs(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0 && st.st_size > 1024 * 1024) {
        char backup_name[256];
        snprintf(backup_name, sizeof(backup_name), "%s.bak", filename);
        rename(filename, backup_name);
    }
}

void add_to_cache(const char *domain, const char *value, const char* type) {
    DNSCacheEntry *new_entry = (DNSCacheEntry *)malloc(sizeof(DNSCacheEntry));
    if (!new_entry) {
        perror("Eroare la alocarea memoriei pentru cache");
        return;
    }

    new_entry->domain_name = (char *)malloc(strlen(domain) + 1);
    new_entry->record_value = (char *)malloc(strlen(value) + 1);
    
    if (!new_entry->domain_name || !new_entry->record_value) {
        perror("Eroare la alocarea memoriei pentru numele domeniului sau valoarea inregistrarii");
        free(new_entry);
        return;
    }

    strcpy(new_entry->domain_name, domain);
    strcpy(new_entry->record_value, value);
    strcpy(new_entry->type_value, type);
    new_entry->timestamp = time(NULL);
    new_entry->ttl = 300;
    new_entry->next = dns_cache;
    dns_cache = new_entry;
}

void print_cache() 
{
    DNSCacheEntry *current = dns_cache;

    FILE *file = fopen("cache_file", "w");
    if (!file) 
    {
        perror("Eroare la deschiderea fișierului cache_file");
        return;
    }

    fprintf(file, "Cache Entries:\n");
    while (current) 
    {
        fprintf(file, "Domain: %s, Value: %s, Type: %s\n", 
                current->domain_name, 
                current->record_value, 
                current->type_value);
        current = current->next;
    }

    fclose(file);
}

void clean_cache() 
{
    DNSCacheEntry *current = dns_cache, *prev = NULL;
    int cache_modified = 0;

    while (current) 
    {
        if ((time(NULL) - current->timestamp) >= current->ttl) 
        {
            log_message("INFO", "Inregistrarea %s - %s a expirat si va fi stearsa din cache!", current->domain_name, current->type_value);
            cache_modified = 1;

            if (prev) 
            {
                prev->next = current->next;
            } 
            else 
            {
                dns_cache = current->next;
            }

            free(current->domain_name);
            free(current->record_value);
            free(current);

            current = (prev) ? prev->next : dns_cache;
        } 
        else 
        {
            prev = current;
            current = current->next;
        }
    }

    if (cache_modified) 
    {
        print_cache();
    }
}

char* search_cache(const char *domain, const char *type)
{
    DNSCacheEntry *current = dns_cache;
    while (current)
    {
        if (strcmp(current->domain_name, domain) == 0 && strcmp(current->type_value,type) == 0)
        {
            if ((time(NULL) - current->timestamp) < current->ttl)
            {
                return current->record_value;
            } else
            {
                clean_cache();
                return NULL;
            }
        }
        current = current->next;
    }
    return NULL;
}

void submit(Received recv)
{
    pthread_mutex_lock(&mutexQueue);
    recv_queue[queueCount]=recv;
    queueCount++;
    pthread_mutex_unlock(&mutexQueue);
    pthread_cond_signal(&condQueue);
}

char* query_dns_type_A(const char *domain, const char *dns_server) {
    unsigned char query_buf[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    int query_len, i;
    static char ip_str[INET_ADDRSTRLEN];

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, dns_server, &dest.sin_addr);

    query_len = res_query(domain, ns_c_in, ns_t_a, query_buf, sizeof(query_buf));
    if (query_len < 0) {
        perror("res_query failed");
        return NULL;
    }

    if (ns_initparse(query_buf, query_len, &handle) < 0) {
        perror("ns_initparse failed");
        return NULL;
    }

    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr failed");
            return NULL;
        }

        //verifica tipul a
        if (ns_rr_type(rr) == ns_t_a) {
            struct in_addr ip_addr;
            memcpy(&ip_addr, ns_rr_rdata(rr), sizeof(ip_addr));

            // converteste adresa IP
            if (inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)) != NULL) {
                return ip_str;
            }
        }
    }

    return NULL;
}

char* query_dns_type_AAAA(const char *domain, const char *dns_server) {
    unsigned char query_buf[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    int query_len, i;
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, dns_server, &dest.sin_addr);

    query_len = res_query(domain, ns_c_in, ns_t_aaaa, query_buf, sizeof(query_buf));
    if (query_len < 0) {
        perror("res_query failed");
        return NULL;
    }

    if (ns_initparse(query_buf, query_len, &handle) < 0) {
        perror("ns_initparse failed");
        return NULL;
    }

    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr failed");
            return NULL;
        }

        // verifica cerere aaaa
        if (ns_rr_type(rr) == ns_t_aaaa) {
            char *ip_addr = malloc(INET6_ADDRSTRLEN);
            if (ip_addr == NULL) {
                perror("malloc failed");
                return NULL;
            }

            //converteste adresa ip
            struct in6_addr *ipv6_addr = (struct in6_addr *)ns_rr_rdata(rr);
            if (inet_ntop(AF_INET6, ipv6_addr, ip_addr, INET6_ADDRSTRLEN)) {
                return ip_addr;
            } else {
                perror("inet_ntop failed");
                free(ip_addr);
            }
        }
    }

    return NULL;
}

char** query_dns_txt(const char *domain, const char *dns_server) {
    unsigned char query_buf[MAX_DNS_BUFFER];
    ns_msg handle;
    ns_rr rr;
    int query_len, i;

    struct __res_state res;
    memset(&res, 0, sizeof(res));
    if (res_ninit(&res) < 0) {
        perror("res_ninit failed");
        return NULL;
    }

    inet_pton(AF_INET, dns_server, &res.nsaddr_list[0].sin_addr);
    res.nsaddr_list[0].sin_family = AF_INET;
    res.nsaddr_list[0].sin_port = htons(53);
    res.nscount = 1;

    //raspunsuri mari
    res.options |= RES_USE_EDNS0;

    query_len = res_nquery(&res, domain, ns_c_in, ns_t_txt, query_buf, sizeof(query_buf));
    if (query_len < 0) {
        perror("res_nquery failed");
        res_nclose(&res);
        return NULL;
    }

    if (ns_initparse(query_buf, query_len, &handle) < 0) {
        perror("ns_initparse failed");
        res_nclose(&res);
        return NULL;
    }

    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr failed");
            res_nclose(&res);
            return NULL;
        }

        //verifica cerere txt
        if (ns_rr_type(rr) == ns_t_txt) {
            const unsigned char *txt_data = ns_rr_rdata(rr);
            unsigned int txt_len = txt_data[0];

            if (txt_len + 1 > ns_rr_rdlen(rr)) {
                fprintf(stderr, "Invalid TXT record length\n");
                res_nclose(&res);
                return NULL;
            }

            char **result = (char **)malloc(sizeof(char *));
            if (!result) {
                fprintf(stderr, "Memory allocation failed\n");
                res_nclose(&res);
                return NULL;
            }

            *result = (char *)malloc(txt_len + 1);
            if (!(*result)) {
                fprintf(stderr, "Memory allocation failed\n");
                free(result);
                res_nclose(&res);
                return NULL;
            }

            strncpy(*result, (const char *)&txt_data[1], txt_len);
            (*result)[txt_len] = '\0';

            res_nclose(&res);
            return result;
        }
    }

    fprintf(stderr, "No TXT records found\n");
    res_nclose(&res);
    return NULL;
}

void parse_ipv4_address(char *adresa, uint8_t addr[4]) 
{
    int octet;
    const char *ptr = adresa;
    char temp[4];
    int index = 0;

    while (*ptr != '\0' && index < 4) 
    {
        int i = 0;
        while (*ptr != '.' && *ptr != '\0') 
        {
            temp[i++] = *ptr;
            ptr++;
        }
        temp[i] = '\0';


        octet = atoi(temp);
        if (octet < 0 || octet > 255) 
        {
            printf("Adresa IP invalidă!\n");
            return;
        }
        addr[index++] = (uint8_t)octet;

        if (*ptr == '.') 
        {
            ptr++;
        }
    }

    if (index != 4) 
    {
        printf("Adresa IP incompletă!\n");
    }
}

void parse_ipv6_address(const char *ipv6_str, uint8_t addr[16]) 
{
    memset(addr, 0, 16);
    
    const char *ptr = ipv6_str;  
    char block[5] = {0};
    int block_index = 0;
    int addr_index = 0;
    int double_colon = 0;

    while (*ptr && addr_index < 16) 
    {
        if (*ptr == ':' && *(ptr + 1) == ':')
        {
            if (double_colon) 
            {
                printf("Adresă invalidă: secvență :: duplicată!\n");
                return;
            }
            double_colon = 1;
            ptr += 2;
            continue;
        }

        memset(block, 0, 5);
        block_index = 0;

        while (*ptr && *ptr != ':' && block_index < 4) 
        {
            if (isxdigit(*ptr)) 
            { 
                block[block_index++] = *ptr;
            }
            ptr++;
        }

        uint16_t segment = (uint16_t)strtol(block, NULL, 16);

        addr[addr_index++] = (segment >> 8) & 0xFF;
        addr[addr_index++] = segment & 0xFF;

        if (*ptr == ':') 
        {
            ptr++;
        }

        if (double_colon && addr_index < 16) 
        {
            while (addr_index < 16) 
            {
                addr[addr_index++] = 0;
            }
            break;
        }
    }

    printf("%d",addr_index);
}

bool get_A_record_subdomain(uint8_t addr[4], const char domain_name[], const char subdomain_name[])
{
    log_message("INFO", "Se cauta raspunsul in fiserele de zona...");
    char zone_file[30] ="zone_files/";
    strcat(zone_file,domain_name);
    strcat(zone_file,".zone");

    static char record_value[INET_ADDRSTRLEN]; 
    char command[512];

    snprintf(command,sizeof(command),"grep -w \"www  IN    A\" %s | rev | cut -f1 -d' ' | rev",zone_file);

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("Nu s-a putut executa comanda");
        return false;
    }

    if (fgets(record_value, sizeof(record_value), fp)) 
    {
        record_value[strcspn(record_value, "\n")] = '\0';
        pclose(fp);

        log_message("INFO","Raspunsul a fost gasit in zona!");
        log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",subdomain_name, "A");
        add_to_cache(subdomain_name,record_value,"A");

        parse_ipv4_address(record_value,addr);
        return true;
    }
    else
    {
      log_message("ERROR","Raspunsul nu a fost gasit in fisierele de zona!");
      log_message("INFO","Se cauta raspunsul in serverul Google...");
      const char *dns_server = "8.8.8.8";  // google
      char* ip=query_dns_type_A(subdomain_name, dns_server);
      
      if(ip == NULL)
      {
          log_message("ERROR","Adresa nu a fost gasita in serverul Google!");
          return false;
      }
      else
        {
          log_message("INFO","Raspunsul a fost gasit in serverul Google!");
          log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",subdomain_name, "A");
          add_to_cache(subdomain_name,ip,"A");
          parse_ipv4_address(ip,addr);
          return true;
        }
    }

    pclose(fp);
    return false;
}

bool get_AAAA_record_subdomain(uint8_t addr[16], const char domain_name[], const char subdomain_name[])
{
  log_message("INFO", "Se cauta raspunsul in fiserele de zona...");
    char zone_file[30] ="zone_files/";
    strcat(zone_file,domain_name);
    strcat(zone_file,".zone");

    static char record_value[128]; 
    char command[512];

    snprintf(command,sizeof(command),"grep -w \"www  IN    AAAA\" %s | rev | cut -f1 -d' ' | rev",zone_file);

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("Nu s-a putut executa comanda");
        return false;
    }

    if (fgets(record_value, sizeof(record_value), fp)) 
    {
        printf("%s",record_value);
        record_value[strcspn(record_value, "\n")] = '\0';
        pclose(fp);

        log_message("INFO","Raspunsul a fost gasit in zona!");
        log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",subdomain_name, "AAAA");
        add_to_cache(subdomain_name,record_value,"AAAA");

        parse_ipv6_address(record_value,addr);
        return true;
    }
    else
    {
      log_message("ERROR","Raspunsul nu a fost gasit in fisierele de zona!");
      log_message("INFO","Se cauta raspunsul in serverul Google...");

      const char *dns_server = "8.8.8.8";  // google
      char* ip=query_dns_type_AAAA(subdomain_name, dns_server);

      if(ip == NULL)
      {
          log_message("ERROR","Adresa nu a fost gasita in serverul Google!\n");
          return false;
      }
      else
        {
          log_message("INFO","Raspunsul a fost gasit in serverul Google");
          log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",subdomain_name, "AAAA");
          add_to_cache(subdomain_name,ip,"AAAA");

          parse_ipv6_address(ip, addr);
          return true;
        }
    }

    pclose(fp);
    return false;
}

bool get_TXT_record_subdomain(char **addr, const char domain_name[], const char subdomain_name[])
{
  log_message("INFO", "Se cauta raspunsul in fiserele de zona...");
    char zone_file[30] ="zone_files/";
    strcat(zone_file,domain_name);
    strcat(zone_file,".zone");

    static char record_value[255]; 
    char command[512];

    snprintf(command,sizeof(command),"grep -w \"www  IN    TXT\" %s | rev | cut -f1 -d' ' | rev",zone_file);

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("Nu s-a putut executa comanda");
        return false;
    }

    if (fgets(record_value, sizeof(record_value), fp)) 
    {
        record_value[strcspn(record_value, "\n")] = '\0';
        pclose(fp);

        *addr = (char *)malloc(strlen(record_value) + 1);  // +1 pentru terminatorul de sir '\0'
        if (*addr != NULL)
        {
          strcpy(*addr, record_value);

          log_message("INFO","Raspunsul a fost gasit in zona");
          log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",subdomain_name, "TXT");
          add_to_cache(subdomain_name,record_value,"TXT");

          return true;
        }
    }
    else
    {
      log_message("ERROR","Raspunsul nu a fost gasit in fisierele de zona!");
      log_message("INFO","Se cauta raspunsul in serverul Google...");

      const char *dns_server = "8.8.8.8";
      
      char **txt_result = query_dns_txt(domain_name, dns_server);
      if (!txt_result) 
      {
        log_message("ERROR", "Adresa nu a fost găsită în serverul Google!\n");
        return false;
      }

      log_message("INFO","Raspunsul a fost gasit in serverul Google");
      log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",subdomain_name, "TXT");
      add_to_cache(subdomain_name,*txt_result,"TXT");


      *addr = *txt_result;
      free(txt_result);
      return true;
    }

    pclose(fp);
    return false;
}

bool get_A_Record(uint8_t addr[4], const char domain_name[])
{
    log_message("INFO", "Se cauta raspunsul in fiserele de zona...");
    char zone_file[30] ="zone_files/";
    strcat(zone_file,domain_name);
    strcat(zone_file,".zone");

    static char record_value[INET_ADDRSTRLEN]; 
    char command[512];

    snprintf(command,sizeof(command),"grep -w \"@    IN    A\" %s | rev | cut -f1 -d' ' | rev ",zone_file);

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("Nu s-a putut executa comanda");
        return false;
    }

    if (fgets(record_value, sizeof(record_value), fp)) 
    {
        record_value[strcspn(record_value, "\n")] = '\0';
        pclose(fp);

        log_message("INFO","Raspunsul a fost gasit in zona!");
        log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",domain_name, "A");
        add_to_cache(domain_name,record_value,"A");

        parse_ipv4_address(record_value,addr);
        return true;
    }
    else
    {
      log_message("ERROR","Raspunsul nu a fost gasit in fisierele de zona!");
      log_message("INFO","Se cauta raspunsul in serverul Google...");
      const char *dns_server = "8.8.8.8";  // google
      char* ip=query_dns_type_A(domain_name, dns_server);
      
      if(ip == NULL)
      {
          log_message("ERROR","Adresa nu a fost gasita in serverul Google!");
          return false;
      }
      else
        {
          log_message("INFO","Raspunsul a fost gasit in serverul Google!");
          log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",domain_name, "A");
          add_to_cache(domain_name,ip,"A");
          parse_ipv4_address(ip,addr);
          return true;
        }
    }

    pclose(fp);
    return false;
}

bool get_AAAA_Record(uint8_t addr[16], const char domain_name[])
{
    log_message("INFO", "Se cauta raspunsul in fiserele de zona...");
    char zone_file[30] ="zone_files/";
    strcat(zone_file,domain_name);
    strcat(zone_file,".zone");

    static char record_value[128]; 
    char command[512];

    snprintf(command,sizeof(command),"grep -w \"^@    IN    AAAA\" %s | rev | cut -f1 -d' ' | rev",zone_file);

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("Nu s-a putut executa comanda");
        return false;
    }

    if (fgets(record_value, sizeof(record_value), fp)) 
    {
        printf("%s",record_value);
        record_value[strcspn(record_value, "\n")] = '\0';
        pclose(fp);

        log_message("INFO","Raspunsul a fost gasit in zona!");
        log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",domain_name, "AAAA");
        add_to_cache(domain_name,record_value,"AAAA");

        parse_ipv6_address(record_value,addr);
        return true;
    }
    else
    {
      log_message("ERROR","Raspunsul nu a fost gasit in fisierele de zona!");
      log_message("INFO","Se cauta raspunsul in serverul Google...");

      const char *dns_server = "8.8.8.8";  // google
      char* ip=query_dns_type_AAAA(domain_name, dns_server);

      if(ip == NULL)
      {
          log_message("ERROR","Adresa nu a fost gasita in serverul Google!\n");
          return false;
      }
      else
        {
          log_message("INFO","Raspunsul a fost gasit in serverul Google");
          log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",domain_name, "AAAA");
          add_to_cache(domain_name,ip,"AAAA");

          parse_ipv6_address(ip, addr);
          return true;
        }
    }

    pclose(fp);
    return false;
}

bool get_TXT_Record(char **addr, const char domain_name[])
{
    log_message("INFO", "Se cauta raspunsul in fiserele de zona...");
    char zone_file[30] ="zone_files/";
    strcat(zone_file,domain_name);
    strcat(zone_file,".zone");

    static char record_value[255]; 
    char command[512];

    snprintf(command,sizeof(command),"grep -w \"@    IN    TXT\" %s | rev | cut -f1 -d' ' | cut -f2 -d'\"' | rev",zone_file);

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("Nu s-a putut executa comanda");
        return false;
    }

    if (fgets(record_value, sizeof(record_value), fp)) 
    {
        record_value[strcspn(record_value, "\n")] = '\0';
        pclose(fp);

        *addr = (char *)malloc(strlen(record_value) + 1);  // +1 pentru terminatorul de șir '\0'
        if (*addr != NULL)
        {
          strcpy(*addr, record_value);

          log_message("INFO","Raspunsul a fost gasit in zona");
          log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",domain_name, "TXT");
          add_to_cache(domain_name,record_value,"TXT");

          return true;
        }
    }
    else
    {
      log_message("ERROR","Raspunsul nu a fost gasit in fisierele de zona!");
      log_message("INFO","Se cauta raspunsul in serverul Google...");

      const char *dns_server = "8.8.8.8";
      
      char **txt_result = query_dns_txt(domain_name, dns_server);
      if (!txt_result) 
      {
        log_message("ERROR", "Adresa nu a fost găsită în serverul Google!\n");
        return false;
      }

      log_message("INFO","Raspunsul a fost gasit in serverul Google");
      log_message("INFO","Se adauga domeniul %s - \"%s\" in cache...",domain_name, "TXT");
      add_to_cache(domain_name,*txt_result,"TXT");


      *addr = *txt_result;
      free(txt_result);
      return true;
    }

    pclose(fp);
    return false;
}

void print_hex(uint8_t *buf, size_t len)
{
  int i;
  printf("%zu bytes:\n", len);
  for (i = 0; i < len; i += 1)
    printf("%02x ", buf[i]);
  printf("\n");
}

void print_resource_record(struct Record *rr)
{
  int i;
  while (rr) {
    printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
      rr->name,
      rr->type,
      rr->Aclass,
      rr->ttl,
      rr->data_len
   );

    union ResourceData *rd = &rr->rd_data;
    switch (rr->type) {
      case A_Resource_RecordType:
        printf("Address Resource Record { address ");
        log_message("INFO", "Adresa gasita: %d.%d.%d.%d \n",rd->a_record.addr[0],rd->a_record.addr[1],rd->a_record.addr[2],rd->a_record.addr[3]);

        for (i = 0; i < 4; i += 1){
          printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);
        }

        printf(" }");
        break;
      case AAAA_Resource_RecordType:
        printf("AAAA Resource Record { address ");
        log_message("INFO","Adresa gasita: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
        rd->aaaa_record.addr[0],
        rd->aaaa_record.addr[1],
        rd->aaaa_record.addr[2],
        rd->aaaa_record.addr[3],
        rd->aaaa_record.addr[4],
        rd->aaaa_record.addr[5],
        rd->aaaa_record.addr[6],
        rd->aaaa_record.addr[7],
        rd->aaaa_record.addr[8],
        rd->aaaa_record.addr[9],
        rd->aaaa_record.addr[10],
        rd->aaaa_record.addr[11],
        rd->aaaa_record.addr[12],
        rd->aaaa_record.addr[13],
        rd->aaaa_record.addr[14],
        rd->aaaa_record.addr[15]);

        for (i = 0; i < 16; i += 1)
          printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);
          

        printf(" }");
        break;
      case TXT_Resource_RecordType:
        printf("Text Resource Record { txt_data '%s' }",
          rd->txt_record.txt_data
        );
        log_message("INFO","Adresa gasita: '%s'\n", rd->txt_record.txt_data);
        break;
      default:
        printf("Unknown Resource Record { ??? }");
        log_message("ERROR","Tip de cerere necunoscut: ???? ");
    }
    printf("}\n");
    rr = rr->next;
  }
}

void print_message(struct dns_Message *msg)
{
  struct Question *q;

  printf("QUERY { ID: %02x", msg->header.id);
  printf(". FIELDS: [ QR: %u, OpCode: %u ]", msg->header.flags.qr, msg->header.flags.opcode);
  printf(", QDcount: %u", msg->header.qdcount);
  printf(", ANcount: %u", msg->header.ancount);
  printf(", NScount: %u", msg->header.nscount);
  printf(", ARcount: %u,\n", msg->header.arcount);

  q = msg->questions;

  while (q) {
    printf("  Question { qName '%s', qType %u, qClass %u }\n",
      q->qname,
      q->qtype,
      q->qclass
    );
    q = q->next;
  }

  print_resource_record(msg->answers);
  print_resource_record(msg->authority_ans);
  print_resource_record(msg->additional_ans);


  printf("}\n");
}

size_t get16bits(const uint8_t **buffer)
{
  uint16_t value;

  memcpy(&value, *buffer, 2);
  *buffer += 2;

  return ntohs(value);
}

void put8bits(uint8_t **buffer, uint8_t value)
{
  memcpy(*buffer, &value, 1);
  *buffer += 1;
}

void put16bits(uint8_t **buffer, uint16_t value)
{
  value = htons(value);
  memcpy(*buffer, &value, 2);
  *buffer += 2;
}

void put32bits(uint8_t **buffer, uint32_t value)
{
  value = htonl(value);
  memcpy(*buffer, &value, 4);
  *buffer += 4;
}

// 3foo3bar3com0 => foo.bar.com (No full validation is done!)
char *decode_domain_name(const uint8_t **buf, size_t len)
{
  char domain[256];
  for (int i = 1; i < MIN(256, len); i += 1) {
    uint8_t c = (*buf)[i];
    if (c == 0) {
      domain[i - 1] = 0;
      *buf += i + 1;
      return strdup(domain);
    } 
    else if ((c >= 'a' && c <= 'z') || c == '-' || (c >= '0' && c <= '9'))
    {
      domain[i - 1] = c;
    } 
    else 
    {
      domain[i - 1] = '.';
    }
  }

  return NULL;
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uint8_t **buffer, const char *domain)
{
  uint8_t *buf = *buffer;
  const char *beg = domain;
  const char *pos;
  int len = 0;
  int i = 0;

  while ((pos = strchr(beg, '.'))) {
    len = pos - beg;
    buf[i] = len;
    i += 1;
    memcpy(buf+i, beg, len);
    i += len;

    beg = pos + 1;
  }

  len = strlen(domain) - (beg - domain);

  buf[i] = len;
  i += 1;

  memcpy(buf + i, beg, len);
  i += len;

  buf[i] = 0;
  i += 1;

  *buffer += i;
}

void decode_header(struct dns_Message *msg, const uint8_t **buffer)
{
  msg->header.id= get16bits(buffer);

  uint32_t fields = get16bits(buffer);
  msg->header.flags.qr = (fields & QR_MASK) >> 15;
  msg->header.flags.opcode= (fields & OPCODE_MASK) >> 11;
  msg->header.flags.aa = (fields & AA_MASK) >> 10;
  msg->header.flags.tc= (fields & TC_MASK) >> 9;
  msg->header.flags.rd = (fields & RD_MASK) >> 8;
  msg->header.flags.ra = (fields & RA_MASK) >> 7;
  msg->header.flags.rCode = (fields & RCODE_MASK) >> 0;

  msg->header.qdcount = get16bits(buffer);
  msg->header.ancount = get16bits(buffer);
  msg->header.nscount = get16bits(buffer);
  msg->header.arcount = get16bits(buffer);
}

void encode_header(struct dns_Message *msg, uint8_t **buffer)
{
  put16bits(buffer, msg->header.id);

  int fields = 0;
  fields |= (msg->header.flags.qr << 15) & QR_MASK;
  fields |= (msg->header.flags.rCode << 0) & RCODE_MASK;
  // TODO: insert the rest of the fields
  put16bits(buffer, fields);

  put16bits(buffer, msg->header.qdcount);
  put16bits(buffer, msg->header.ancount);
  put16bits(buffer, msg->header.nscount);
  put16bits(buffer, msg->header.arcount);
}

bool decode_msg(struct dns_Message *msg, const uint8_t *buffer, size_t size)
{
  int i;

  if (size < 12)
    return false;

  decode_header(msg, &buffer);

  if (msg->header.ancount != 0 || msg->header.nscount != 0) {
    printf("Only questions expected!\n");
    return false;
  }

  // parse questions
  uint32_t qcount = msg->header.qdcount;
  for (i = 0; i < qcount; i += 1) {
    struct Question *q = calloc(1, sizeof(struct Question));

    q->qname = decode_domain_name(&buffer, size);
    q->qtype = get16bits(&buffer);
    q->qclass = get16bits(&buffer);

    if (q->qname == NULL) {
      printf("Failed to decode domain name!\n");
      return false;
    }

    // prepend question to questions list
    q->next = msg->questions;
    msg->questions = q;
  }

  return true;
}

bool is_subdomain(const char *domain)
{
    int count = 0;
    while (*domain) {
        if (*domain == '.') {
            count++;
        }
        domain++;
    }
    if(count==1)
        return false;
    else
        return true;
}

void extract_main_domain(const char *subdomain, char *main_domain)
{
    const char *last_dot = strchr(subdomain, '.');
    if (last_dot != NULL) 
    {
        strcpy(main_domain, last_dot + 1);
    }
}

void resolve_query(struct dns_Message *msg) {
    struct Record *beg;
    struct Record *rr;
    struct Question *q;

    //valorile pentru răspuns
    msg->header.flags.qr = 1;  //este un răspuns
    msg->header.flags.aa = 1;  //server autoritar
    msg->header.flags.ra = 0;  //fara recursivitate
    msg->header.flags.rCode = R_CODE_NO_ERROR;

    //initializare campuri raspuns
    msg->header.ancount = 0;
    msg->header.nscount = 0;
    msg->header.arcount = 0;

    q = msg->questions;
    while (q) {
        rr = calloc(1, sizeof(struct Record));
        rr->name = strdup(q->qname);
        rr->type = q->qtype;
        rr->Aclass = q->qclass;
        rr->ttl = 60 * 60;

        printf("Query for '%s'\n", q->qname);

      if (is_subdomain(q->qname))
      {
        log_message("INFO", "Cererea %s este un subdomeniu", q->qname);
        log_message("INFO", "Se cauta adresa IP pentru subdomeniul: %s", q->qname);

        
        if (q->qtype == A_Resource_RecordType)
        {
            rr->data_len = 4;

            // Caută în cache
            log_message("INFO", "Se cauta raspunsul in cache...");
            char *cached_value_a = search_cache(q->qname, "A");
            if (cached_value_a) {
                log_message("INFO", "Raspuns gasit in cache pentru subdomeniul %s", q->qname);
                inet_pton(AF_INET, cached_value_a, rr->rd_data.a_record.addr);
                msg->header.ancount++;
                beg = msg->answers;
                msg->answers = rr;
                rr->next = beg;
                goto next;
            }
            else {
              log_message("ERROR", "Raspunsul nu a fost gasit in cache!");
            }

            // Caută în fișierul de zonă
            char main_domain[256];
            extract_main_domain(q->qname, main_domain);
            log_message("INFO", "Domeniul principal este %s", main_domain);

            if (!get_A_record_subdomain(rr->rd_data.a_record.addr,main_domain, q->qname)) {
                log_message("ERROR", "Nu s-a găsit înregistrarea A pentru subdomeniu");
                free(rr->name);
                free(rr);
                goto next;
            }

        } else if (q->qtype == AAAA_Resource_RecordType)
          {
            rr->data_len = 16;

            // Caută în cache
            log_message("INFO", "Se caută raspunsul in cache");
            char *cached_value_aaaa = search_cache(q->qname, "AAAA");
            if (cached_value_aaaa)
            {
                log_message("INFO", "Raspuns gasit in cache pentru subdomeniul %s", q->qname);
                inet_pton(AF_INET6, cached_value_aaaa, rr->rd_data.aaaa_record.addr);
                msg->header.ancount++;
                beg = msg->answers;
                msg->answers = rr;
                rr->next = beg;
                goto next;
            }

            // Caută în fișierul de zonă
            char main_domain[256];
            extract_main_domain(q->qname, main_domain);
            log_message("INFO", "Domeniul principal este %s", main_domain);

            if (!get_AAAA_record_subdomain(rr->rd_data.aaaa_record.addr,main_domain,q->qname)) {
                log_message("ERROR", "Nu s-a găsit înregistrarea AAAA pentru subdomeniu");
                free(rr->name);
                free(rr);
                goto next;
            }

        } else if (q->qtype == TXT_Resource_RecordType)
        {
            log_message("INFO", "Se caută raspunsul in cache");

            // Caută în cache
            char *cached_value_txt = search_cache(q->qname, "TXT");
            if (cached_value_txt)
            {
                log_message("INFO", "Răspuns găsit în cache pentru subdomeniul: %s", q->qname);
                rr->data_len = strlen(cached_value_txt) + 1;
                rr->rd_data.txt_record.txt_data = strdup(cached_value_txt);
                rr->rd_data.txt_record.txt_data_len = strlen(cached_value_txt);
                msg->header.ancount++;
                beg = msg->answers;
                msg->answers = rr;
                rr->next = beg;
                goto next;
            }

            // Caută în fișierul de zonă
            char main_domain[256];
            extract_main_domain(q->qname, main_domain);
            log_message("INFO", "Domeniul principal este %s", main_domain);

            if (!get_TXT_record_subdomain(&(rr->rd_data.txt_record.txt_data), main_domain, q->qname))
            {
                log_message("ERROR", "Nu s-a găsit înregistrarea TXT pentru subdomeniu");
                free(rr->name);
                free(rr);
                goto next;
            }

        } else {
            log_message("ERROR", "Tipul de cerere nu este suportat pentru subdomenii.");
            free(rr->name);
            free(rr);
            msg->header.flags.rCode = R_CODE_NOT_IMPLEMENTED;
            return;
        }

    } else 
        {
            //domeniul principal
            log_message("INFO", "Se cauta adresa IP pentru domeniul: %s", q->qname);

            // cauta in cache
            log_message("INFO", "Se cauta raspunsul in cache...");
            switch (q->qtype) {
                case A_Resource_RecordType:
                    rr->data_len = 4;
                    // cache pentru A
                    char *cached_value_a = search_cache(q->qname, "A");
                    if (cached_value_a) {
                        log_message("INFO", "Raspuns gasit in cache pentru domeniul %s", q->qname);
                        inet_pton(AF_INET, cached_value_a, rr->rd_data.a_record.addr);
                        msg->header.ancount++;
                        beg = msg->answers;
                        msg->answers = rr;
                        rr->next = beg;
                        goto next;
                    } else {
                        log_message("ERROR", "Raspunsul nu a fost gasit in cache!");
                    }
                    //zona pentru A
                    if (!get_A_Record(rr->rd_data.a_record.addr, q->qname)) {
                        free(rr->name);
                        free(rr);
                        goto next;
                    }
                    break;
                case AAAA_Resource_RecordType:
                    rr->data_len = 16;
                    //cache pentru AAAA
                    char *cached_value_aaaa = search_cache(q->qname, "AAAA");
                    if (cached_value_aaaa) {
                        log_message("INFO", "Raspuns gasit in cache pentru domeniul %s", q->qname);
                        inet_pton(AF_INET6, cached_value_aaaa, rr->rd_data.aaaa_record.addr);
                        msg->header.ancount++;
                        beg = msg->answers;
                        msg->answers = rr;
                        rr->next = beg;
                        goto next;
                    } else {
                        log_message("ERROR", "Raspunsul nu a fost gasit in cache!");
                    }
                    //zona pentru AAAA
                    if (!get_AAAA_Record(rr->rd_data.aaaa_record.addr, q->qname)) {
                        free(rr->name);
                        free(rr);
                        goto next;
                    }
                    break;
                case TXT_Resource_RecordType:
                    // cache pentru TXT
                    char *cached_value_txt = search_cache(q->qname, "TXT");
                    if (cached_value_txt) {
                        log_message("INFO", "Raspuns gasit in cache pentru domeniul %s", q->qname);
                        rr->data_len = strlen(cached_value_txt) + 1;
                        rr->rd_data.txt_record.txt_data = strdup(cached_value_txt);
                        rr->rd_data.txt_record.txt_data_len = strlen(cached_value_txt);
                        msg->header.ancount++;
                        beg = msg->answers;
                        msg->answers = rr;
                        rr->next = beg;
                        goto next;
                    } else {
                        log_message("ERROR", "Raspunsul nu a fost gasit in cache!");
                    }
                    //zona pentru TXT
                    if (!get_TXT_Record(&(rr->rd_data.txt_record.txt_data), q->qname)) {
                        free(rr->name);
                        free(rr);
                        goto next;
                    }
                    int txt_data_len = strlen(rr->rd_data.txt_record.txt_data);
                    rr->data_len = txt_data_len + 1;
                    rr->rd_data.txt_record.txt_data_len = txt_data_len;
                    break;
                default:
                    free(rr->name);
                    free(rr);
                    msg->header.flags.rCode = R_CODE_NOT_IMPLEMENTED;
                    printf("Cannot answer question of type %d.\n", q->qtype);
                    log_message("ERROR", "Nu se poate răspunde la tipul de cerere %d", q->qtype);
                    goto next;
            }
        }

        msg->header.ancount++;
        beg = msg->answers;
        msg->answers = rr;
        rr->next = beg;

        next:
        q = q->next;  //urmatoarea intrebare
    }
}

/* @return false upon failure, true upon success */
bool encode_resource_records(struct Record *rr, uint8_t **buffer)
{
  int i;

  while (rr) {
    // Answer questions by attaching resource sections.
    encode_domain_name(buffer, rr->name);
    put16bits(buffer, rr->type);
    put16bits(buffer, rr->Aclass);
    put32bits(buffer, rr->ttl);
    put16bits(buffer, rr->data_len);

    

    switch (rr->type) {
      case A_Resource_RecordType:
        for (i = 0; i < 4; i += 1)
          put8bits(buffer, rr->rd_data.a_record.addr[i]);
        break;
      case AAAA_Resource_RecordType:
        for (i = 0; i < 16; i += 1)
          put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
        break;
      case TXT_Resource_RecordType:
        put8bits(buffer, rr->rd_data.txt_record.txt_data_len);
        for (i = 0; i < rr->rd_data.txt_record.txt_data_len; i++)
          put8bits(buffer, rr->rd_data.txt_record.txt_data[i]);
        break;
      default:
        fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
        return false;
    }

    rr = rr->next;
  }

  return true;
}

/* @return false upon failure, true upon success */
bool encode_msg(struct  dns_Message *msg, uint8_t **buffer)
{
  encode_header(msg, buffer);

  struct Question *q = msg->questions;
  while (q) {
    encode_domain_name(buffer, q->qname);
    put16bits(buffer, q->qtype);
    put16bits(buffer, q->qclass);

    q = q->next;
  }

  if (!encode_resource_records(msg->answers, buffer)) {
    return false;
  }

  if (!encode_resource_records(msg->authority_ans, buffer)) {
    return false;
  }

  if (!encode_resource_records(msg->additional_ans, buffer)) {
    return false;
  }

  return true;
}

void free_resource_records(struct Record *rr)
{
  struct Record *next;

  while (rr) {
    free(rr->name);
    next = rr->next;
    free(rr);
    rr = next;
  }
}

void free_questions(struct Question *qq)
{
  struct Question *next;

  while (qq) {
    free(qq->qname);
    next = qq->next;
    free(qq);
    qq = next;
  }
}

void handle_connection(Received * recv)
{
   
    if (recv->len < 0) 
    {
      return;
    }
    struct dns_Message msg;
    memset(&msg, 0, sizeof(struct dns_Message));
    free_questions(msg.questions);
    free_resource_records(msg.answers);
    free_resource_records(msg.authority_ans);
    free_resource_records(msg.additional_ans);

    if (!decode_msg(&msg, recv->buffer, recv->len)) 
    {
      return;
    }

    log_message("INFO", "Cererea '%02x' a fost procesta!", msg.header.id);
  
    print_message(&msg);
  
    resolve_query(&msg);
  
    print_message(&msg);


    print_cache();

    uint8_t *p = recv->buffer;
    if (!encode_msg(&msg, &p)) 
    {
      return;
    }

    size_t buflen = p - recv->buffer;
    sendto(recv->sock, recv->buffer, buflen, 0, (struct sockaddr*) &(recv->client_addr), recv->addr_len);
    printf("%d----------------------------------------------\n",number);
    number++;
}

void * thread_function(void *args)
{
  while(1)
  {
    Received recv;
    pthread_mutex_lock(&mutexQueue);
    while(queueCount==0)
    {
      pthread_cond_wait(&condQueue,&mutexQueue);
    }

    recv=recv_queue[0];
  
    for(int i = 0; i < queueCount-1; i++)
    {
      recv_queue[i] = recv_queue[i+1];
    }

    queueCount--;
        
    pthread_mutex_unlock(&mutexQueue);
    handle_connection(&recv);

  }
}

int main()
{
  init_logging("aplicatie.log");

  log_message("INFO", "Serverul este deschis!");


  pthread_t thread_pool[THREAD_NUM];
  pthread_mutex_init(&mutexQueue,NULL);
  pthread_cond_init(&condQueue,NULL);

  // buffer for input/output binary packet
  uint8_t buffer[BUFFER_SIZE];
  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in addr;
  int rc;
  ssize_t nbytes;
  int sock;
  int port = 8080;

  
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  sock = socket(AF_INET, SOCK_DGRAM, 0);

  rc = bind(sock, (struct sockaddr*) &addr, addr_len);

  if (rc != 0) {
    printf("Could not bind: %s\n", strerror(errno));
    log_message("ERROR","Could not bind: %s",strerror(errno));
    return 1;
  }

  printf("Listening on port %u.\n", port);
  log_message("INFO","Listening on port %u\n",port);

  for(int i=0;i<THREAD_NUM;i++)
  {
    if(pthread_create(&thread_pool[i],NULL,&thread_function,NULL)!=0)
    {
      perror("Failed to create the thread");
      log_message("ERROR","Failed to create the thread");
    }
  }

  

  while (1) { 
    /* Receive DNS query */
    nbytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &addr_len);
    Received r;
    memcpy(r.buffer, buffer, nbytes);
    r.len = nbytes;
    r.sock = sock;
    r.client_addr = client_addr;
    r.addr_len = addr_len;
    submit(r);

  }
  
  pthread_mutex_destroy(&mutexQueue);
  pthread_cond_destroy(&condQueue);

  log_message("INFO","Serverul este inchis!");
  close_logging();

  return 0;
}