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

#include "dns.h" //header dns 

#define BUFFER_SIZE 1500
#define MAX_PACKET_SIZE 65535


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
    fflush(log_file); // Scrie imediat în fișier
}

void close_logging() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void rotate_logs(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0 && st.st_size > 1024 * 1024) { // 1MB
        char backup_name[256];
        snprintf(backup_name, sizeof(backup_name), "%s.bak", filename);
        rename(filename, backup_name);
    }
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

void parse_ipv4_address(char *adresa, uint8_t addr[4]) 
{
    int octet;
    const char *ptr = adresa; // Pointer la începutul string-ului
    char temp[4]; // Buffer temporar pentru fiecare octet
    int index = 0;

    while (*ptr != '\0' && index < 4) {
        int i = 0;
        // Extrage caracterele până la '.'
        while (*ptr != '.' && *ptr != '\0') {
            temp[i++] = *ptr;
            ptr++;
        }
        temp[i] = '\0'; // Termină bufferul temporar cu NULL

        // Convertim partea curentă în număr și o punem în addr
        octet = atoi(temp);
        if (octet < 0 || octet > 255) {
            printf("Adresa IP invalidă!\n");
            return;
        }
        addr[index++] = (uint8_t)octet;

        // Dacă am ajuns la '.', trecem peste el
        if (*ptr == '.') {
            ptr++;
        }
    }

    // Verificăm dacă am găsit toți cei 4 octeți
    if (index != 4) {
        printf("Adresa IP incompletă!\n");
    }
}

void parse_ipv6_address(const char *ipv6_str, uint8_t addr[16])
{
    // Inițializăm array-ul cu zero
    memset(addr, 0, 16);
    
    const char *ptr = ipv6_str;   // Pointer pentru a parcurge string-ul
    char block[5] = {0};          // Fiecare grup hexa poate avea max 4 cifre + terminator '\0'
    int block_index = 0;          // Index pentru grupuri
    int addr_index = 0;           // Index în array-ul addr

    while (*ptr && addr_index < 16) {
        // Resetăm blocul
        memset(block, 0, 5);

        // Construim un grup de maxim 4 caractere hexadecimale
        int i = 0;
        while (*ptr && *ptr != ':' && i < 4) {
            block[i++] = *ptr;
            ptr++;
        }

        // Convertim grupul într-un uint16_t
        uint16_t segment = (uint16_t)strtol(block, NULL, 16);

        // Descompunem segmentul în 2 octeți
        addr[addr_index++] = (segment >> 8) & 0xFF;  // Octetul superior
        addr[addr_index++] = segment & 0xFF;         // Octetul inferior

        // Dacă am ajuns la un separator ':', trecem la următorul grup
        if (*ptr == ':') {
            ptr++;
        }
    }

    if (addr_index != 16) {
        printf("Adresa IP incompletă!\n");
    }
}

bool get_A_Record(uint8_t addr[4], const char domain_name[])
{
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

        parse_ipv4_address(record_value,addr);
        return true;
    }
    else
    {
      const char *dns_server = "8.8.8.8";  // google
      char* ip=query_dns_type_A(domain_name, dns_server);
      
      if(ip == NULL)
        return false;
      else
        {
          parse_ipv4_address(ip,addr);
          return true;
        }
    }

    pclose(fp);
    return false;
}

bool get_AAAA_Record(uint8_t addr[16], const char domain_name[])
{
  char zone_file[30] ="zone_files/";
    strcat(zone_file,domain_name);
    strcat(zone_file,".zone");

    static char record_value[INET_ADDRSTRLEN]; 
    char command[512];

    snprintf(command,sizeof(command),"grep -w \"@    IN    AAAA\" %s | rev | cut -f1 -d' ' | rev",zone_file);

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("Nu s-a putut executa comanda");
        return false;
    }

    if (fgets(record_value, sizeof(record_value), fp)) 
    {
        record_value[strcspn(record_value, "\n")] = '\0';
        pclose(fp);

        parse_ipv6_address(record_value,addr);
        return true;
    }
    else
    {
      const char *dns_server = "8.8.8.8";  // google
      //query_dns(domain_name, dns_server, ns_t_aaaa);
    }

    pclose(fp);
    return false;
}

bool get_TXT_Record(char **addr, const char domain_name[])
{
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
          //printf("%s",record_value);
          return true;
        }
    }
    else
    {
      const char *dns_server = "8.8.8.8";  // google
      //query_dns(domain_name, dns_server,ns_t_txt);
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

        for (i = 0; i < 4; i += 1){
          printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);
        }

        printf(" }");
        break;
      case AAAA_Resource_RecordType:
        printf("AAAA Resource Record { address ");

        for (i = 0; i < 16; i += 1)
          printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);

        printf(" }");
        break;
      case TXT_Resource_RecordType:
        printf("Text Resource Record { txt_data '%s' }",
          rd->txt_record.txt_data
        );
        break;
      default:
        printf("Unknown Resource Record { ??? }");
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


void resolve_query(struct dns_Message *msg)
{
  struct Record *beg;
  struct Record *rr;
  struct Question *q;

  // leave most values intact for response
  msg->header.flags.qr = 1; // this is a response
  msg->header.flags.aa = 1; // this server is authoritative
  msg->header.flags.ra = 0; // no recursion available
  msg->header.flags.rCode= R_CODE_NO_ERROR;

  // should already be 0
  msg->header.ancount = 0;
  msg->header.nscount = 0;
  msg->header.arcount = 0;

  q = msg->questions;
  while (q) {
    rr = calloc(1, sizeof(struct Record));

    rr->name = strdup(q->qname);
    rr->type = q->qtype;
    rr->Aclass = q->qclass;
    rr->ttl = 60*60; // in seconds; 0 means no caching

    printf("Query for '%s'\n", q->qname);

    switch (q->qtype) {
      case A_Resource_RecordType:
        rr->data_len = 4;
        if(!get_A_Record(rr->rd_data.a_record.addr, q->qname)){
          free(rr->name);
          free(rr);
          goto next;
          }
        break;
      case AAAA_Resource_RecordType:
        rr->data_len = 16;
        if (!get_AAAA_Record(rr->rd_data.aaaa_record.addr, q->qname)) {
          free(rr->name);
          free(rr);
          goto next;
        }
        break;
      case TXT_Resource_RecordType:
        if (!get_TXT_Record(&(rr->rd_data.txt_record.txt_data), q->qname)) {
          free(rr->name);
          free(rr);
          goto next;
        }
        int txt_data_len = strlen(rr->rd_data.txt_record.txt_data);
        rr->data_len = txt_data_len + 1;
        rr->rd_data.txt_record.txt_data_len = txt_data_len;
        break;
      /*
      case NS_Resource_RecordType:
      case CNAME_Resource_RecordType:
      case SOA_Resource_RecordType:
      case PTR_Resource_RecordType:
      case MX_Resource_RecordType:
      case TXT_Resource_RecordType:
      */
      default:
        free(rr->name);
        free(rr);
        msg->header.flags.rCode = R_CODE_NOT_IMPLEMENTED;
        printf("Cannot answer question of type %d.\n", q->qtype);
        goto next;
    }

    msg->header.ancount++;

    // prepend resource record to answers list
    beg = msg->answers;
    msg->answers = rr;
    rr->next = beg;

    // jump here to omit question
    next:

    // process next question
    q = q->next;
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
  
    print_message(&msg);
  
    resolve_query(&msg);
  
    print_message(&msg);


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

  log_message("INFO", "Aplicația a început");

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
    return 1;
  }

  printf("Listening on port %u.\n", port);

  for(int i=0;i<THREAD_NUM;i++)
  {
    if(pthread_create(&thread_pool[i],NULL,&thread_function,NULL)!=0)
    {
      perror("Failed to create the thread");
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

  close_logging();

  return 0;
}