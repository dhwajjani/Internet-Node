
// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------



//to know which current port we are using
uint16_t currTcpPortNum;
uint8_t data[1536],htmlMessage[1536];
uint16_t htmlIndex;
uint8_t ipv4Address[4], destIPAdd[4];
uint8_t DNS1[4],DNS2[4];
uint32_t sequenceId;
uint32_t acknowledgementId;
uint32_t tempAcknowledgementId;
uint16_t httpLen;
uint32_t totlen;    //to calculate seqid
uint32_t change_count, last_change;
uint16_t time_transmit;
uint8_t macAddress[6];
uint8_t destAddress[6];
uint8_t Query_Size;
uint16_t IPseqId;
bool chunked,stuck,timeup;;
typedef enum {CLOSED, SYN_SENT, ESTAB, httpReqSent, FIN_ACK,LAST_ACK}tcpStates;
enum dhcpStates{Discover, AwaitOffer, Request, AwaitAck, GotIP}DhcpState;
tcpStates tcpState;
tcpStates lastState;
// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

// This M4F is little endian
// Network byte order is big endian
// Must interpret uint16_ts in reverse order

struct enc28j60Frame // 4-bytes
{
  uint16_t size;
  uint16_t status;
  uint8_t data;
} *enc28j60;

struct etherFrame // 14-bytes
{
  uint8_t destAddress[6];
  uint8_t sourceAddress[6];
  uint16_t frameType;
  uint8_t data;
} *ether;

struct _ip // minimum 20 bytes
{
  uint8_t rev_size;
  uint8_t typeOfService;
  uint16_t length;
  uint16_t id;
  uint16_t flagsAndOffset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t headerChecksum;
  uint8_t sourceIp[4];
  uint8_t destIp[4];
} *ip;

struct _icmp
{
  uint8_t type;
  uint8_t code;
  uint16_t check;
  uint16_t id;
  uint16_t seq_no;
  uint8_t data;
} *icmp;

struct _arp
{
  uint16_t hardwareType;
  uint16_t protocolType;
  uint8_t hardwareSize;
  uint8_t protocolSize;
  uint16_t op;
  uint8_t sourceAddress[6];
  uint8_t sourceIp[4];
  uint8_t destAddress[6];
  uint8_t destIp[4];
} *arp;

struct _udp // 8 bytes
{
  uint16_t sourcePort;
  uint16_t destPort;
  uint16_t length;
  uint16_t check;
  uint8_t  data;
} *udp;

typedef struct
{
  uint8_t opcode;
  uint8_t length;
  uint8_t value[20];
}dhcp_option;

struct _dhcp
{
uint8_t opcode;
uint8_t  HWType;
uint8_t HWAddLength;
uint8_t  hops;
uint32_t ID;
uint16_t elapsed_seconds;
uint16_t flags;
uint32_t ClientIP;
uint32_t YourIP;
uint32_t ServerIP;
uint32_t GatewayIP;
uint8_t ClientHWAdd[16];
uint8_t ServerName[64];
uint8_t BootFileName[128];
uint32_t Magic_Cookie;
uint8_t options;
} *dhcp;

struct _dns
{
  uint16_t ID;
  uint16_t flags;
  uint16_t No_Of_Q;
  uint16_t N0_Of_A;
  uint16_t No_Of_AuR;
  uint16_t No_Of_AdR;
  uint8_t Queries[100];
} *dns;

struct _dnsans
{
  uint16_t name_offset;
  uint16_t type;
  uint16_t class;
  uint8_t ttl[4];
  uint16_t length;
  uint8_t value[15];
} *dnsans;

struct _tcp // 20 bytes
{
  uint16_t sourcePort;
  uint16_t destPort;
  uint32_t seqNum;
  uint32_t ackNum;
  uint16_t hlengthf;
  uint16_t windowSize;
  uint16_t check;
  uint16_t UrgentPointer;
  uint8_t data[1536];
} *tcp;

void waitMicrosecond(uint32_t us);
uint8_t etherIsIp(uint8_t data[]);
bool etherIsIpUnicast(uint8_t data[]);
bool etherIsValidIp();
void etherSetIpAddress(uint8_t a, uint8_t b,  uint8_t c, uint8_t d);

uint8_t etherIsPingReq(uint8_t data[]);
void etherSendPingResp(uint8_t data[]);

#define ARP_INVALID 0
#define ARP_REQUEST 1
#define ARP_RESPONSE 2
uint8_t etherIsArp(uint8_t data[]);
void etherSendArpResp(uint8_t data[]);
void etherSendArpReq(uint8_t data[], uint8_t ip[]);

uint8_t etherIsUdp(uint8_t data[]);
uint8_t* etherGetUdpData(uint8_t data[]);
void etherSendUdpData(uint8_t data[], uint8_t* udp_data, uint8_t udp_size);

uint32_t etherSendDhcpMessage();
uint16_t DnsQuery(char str[],uint8_t dns_server[]);

uint8_t* etherGetTcpData(uint8_t data[]);
uint8_t etherIsTcp(uint8_t data[]);
bool etherIsTcpSynAck(uint8_t data[]);
void ethersendTcpSyn();
void etherSendTcpAckback(uint8_t data[]);
void etherSendhttpget(uint8_t data[]);
void etherSendTcpAckhttp(uint8_t data[]);
void etherSendTcpFinAck(uint8_t data[]);
void handle_packet();

uint16_t htons(uint16_t value);
#define ntohs htons
uint32_t htons32(uint32_t value);

