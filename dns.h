// struct pt : header, question, answer, authority, additional
#include <stdint.h>



/* Resource Record Types */
enum {
  A_Resource_RecordType = 1,
  NS_Resource_RecordType = 2,
  CNAME_Resource_RecordType = 5,
  SOA_Resource_RecordType = 6,
  PTR_Resource_RecordType = 12,
  MX_Resource_RecordType = 15,
  TXT_Resource_RecordType = 16,
  AAAA_Resource_RecordType = 28,
  SRV_Resource_RecordType = 33
};

/* Response codes*/
enum{
    R_CODE_NO_ERROR=0,
    R_CODE_FORMAT_ERROR=1,
    R_CODE_SERVER_FAILURE=2,
    R_CODE_NAME_ERROR=3,
    R_CODE_NOT_IMPLEMENTED=4,
    R_CODE_REFUSED=5
};

/* Operation Code */
enum {
  QUERY_OperationCode = 0, /* standard query */
  IQUERY_OperationCode = 1, /* inverse query */
  STATUS_OperationCode = 2, /* server status request */
  NOTIFY_OperationCode = 4, /* request zone transfer */
  UPDATE_OperationCode = 5 /* change resource records */
};

/* Query Type */
enum {
  IXFR_QueryType = 251,
  AXFR_QueryType = 252,
  MAILB_QueryType = 253,
  MAILA_QueryType = 254,
  STAR_QueryType = 255
};


typedef struct Flags
{
    uint16_t qr; /* query/response 0=request sau 1=answer */
    uint16_t opcode; /* 0=standard query, 1=inverse query, 2=server status server, 3=status reserved */
    uint16_t aa; /* authority answer 1=authoritative, 0=non-authoritative */
    uint16_t tc; /* truncation */
    uint16_t rd; /* recursion desired 1= server needs to answer the query recursively*/
    uint16_t ra; /* recursion available */
    uint16_t zero; 
    uint16_t rCode; /* response code 0= no error, 
                    1=problem,
                    2=server failure,
                    3=name error,
                    4=request type not suppported by the server,
                    5=nonexecution of queries*/
};



typedef struct Header
{
    uint16_t id;
    struct Flags flags;
    uint16_t qdcount;/* Question Count */
    uint16_t ancount;/* Answer Record Count */
    uint16_t nscount;/* Authority Record Count */
    uint16_t arcount;/* Additional Record Count */
};

typedef struct Question
{
    char *qname;       
    uint16_t qtype;  
    uint16_t qclass;
    struct Question *next;
};

/* Data part of a Resource Record */
union ResourceData {
  struct {
    uint8_t txt_data_len;
    char *txt_data;
  } txt_record;
  struct {
    uint8_t addr[4];
  } a_record;
  struct {
    uint8_t addr[16];
  } aaaa_record;
};

typedef struct Record // answer, authority, additional 
{
    char *name;        // Numele domeniului (format DNS sau pointer)
    uint16_t type;     // Tipul răspunsului (A, CNAME, etc.)
    uint16_t Aclass;    // Clasa răspunsului (de obicei, IN)
    uint32_t ttl;      // Time-to-Live
    uint16_t data_len; // Lungimea câmpului de date
    union ResourceData rd_data;   // Datele efective (ex. adresa IP)
    struct Record * next;
};

typedef struct dns_Message
{
    struct Header header;
    struct Question * questions;
    struct Record * answers;
    struct Record* authority_ans;
    struct Record* additional_ans;
};


