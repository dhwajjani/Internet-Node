/*
 * ether.c
 *
 * Author: Dhwaj
 */
#include <stdint.h>
#include <stdbool.h>
#include "tm4c123gh6pm.h"
#include <string.h>
#include "enc28j60.h"
#include "ether.h"
uint32_t sum;

// Approximate busy waiting (in units of microseconds), given a 40 MHz system clock
void waitMicrosecond(uint32_t us)
{
	__asm("WMS_LOOP0:   MOV  R1, #6");          // 1
    __asm("WMS_LOOP1:   SUB  R1, #1");          // 6
    __asm("             CBZ  R1, WMS_DONE1");   // 5+1*3
    __asm("             NOP");                  // 5
    __asm("             NOP");                  // 5
    __asm("             B    WMS_LOOP1");       // 5*2 (speculative, so P=1)
    __asm("WMS_DONE1:   SUB  R0, #1");          // 1
    __asm("             CBZ  R0, WMS_DONE0");   // 1
	__asm("             NOP");                  // 1
    __asm("             B    WMS_LOOP0");       // 1*2 (speculative, so P=1)
    __asm("WMS_DONE0:");                        // ---
                                                // 40 clocks/us + error
}

// Calculate sum of words
// Must use getEtherChecksum to complete 1's compliment addition
void etherSumWords(void* data, uint16_t size_in_bytes)
{
    uint8_t* pData = (uint8_t*)data;
    uint16_t i;
    uint8_t phase = 0;
    uint16_t data_temp;
    for (i = 0; i < size_in_bytes; i++)
    {
        if (phase)
        {
            data_temp = *pData;
            sum += data_temp << 8;
        }
        else
          sum += *pData;
        phase = 1 - phase;
        pData++;
    }
}

// Completes 1's compliment addition by folding carries back uint8_to field
uint16_t getEtherChecksum()
{
    uint16_t result;
    // this is based on rfc1071
    while ((sum >> 16) > 0)
      sum = (sum & 0xFFFF) + (sum >> 16);
    result = sum & 0xFFFF;
    return ~result;
}

// Converts from host to network order and vice versa
uint16_t htons(uint16_t value)
{
    return ((value & 0xFF00) >> 8) + ((value & 0x00FF) << 8);
}

#define ntohs htons

uint32_t htons32(uint32_t value)
{
	uint16_t valueL,valueR;
	valueL = (value>>16);
	valueR = (0xffff&value);
	valueL = ((valueL & 0xFF00) >> 8) + ((valueL & 0x00FF) << 8);
	valueR = ((valueR & 0xFF00) >> 8) + ((valueR & 0x00FF) << 8);
	value = valueL;
	value |= valueR<<16;
	return value;
}

// Determines whether packet is IP datagram
uint8_t etherIsIp(uint8_t data[])
{
    uint8_t ok;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    ok = (ether->frameType == 0x0008);
    if (ok)
    {
        sum = 0;
        etherSumWords(&ip->rev_size, (ip->rev_size & 0xF) * 4);
        ok = (getEtherChecksum() == 0);
    }
    return ok;
}

// Determines whether packet is unicast to this ip
// Must be an IP packet
bool etherIsIpUnicast(uint8_t data[])
{
    uint8_t i = 0;
    bool ok = true;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    while (ok && (i < 4))
    {
        ok = (ip->destIp[i] == ipv4Address[i]);
        i++;
    }
    return ok;
}

// Determines whether packet is ping request
// Must be an IP packet
uint8_t etherIsPingReq(uint8_t data[])
{
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    icmp = (void*)((uint8_t*)ip + ((ip->rev_size & 0xF) * 4));
    return (ip->protocol == 0x01 && icmp->type == 8);
}

// Sends a ping response given the request data
void etherSendPingResp(uint8_t data[])
{
    uint8_t i, tmp;
    uint16_t icmp_size;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    icmp = (void*)((uint8_t*)ip + ((ip->rev_size & 0xF) * 4));
    // swap source and destination fields
    for (i = 0; i < 6; i++)
    {
        tmp = ether->destAddress[i];
        ether->destAddress[i] = ether->sourceAddress[i];
        ether->sourceAddress[i] = tmp;
    }
    for (i = 0; i < 4; i++)
    {
        tmp = ip->destIp[i];
        ip->destIp[i] = ip ->sourceIp[i];
        ip->sourceIp[i] = tmp;
    }
    // this is a response
    icmp->type = 0;
    // calc icmp checksum
    sum = 0;
    etherSumWords(&icmp->type, 2);
    icmp_size = ntohs(ip->length);
    icmp_size -= 24; // sub ip header and icmp code, type, and check
    etherSumWords(&icmp->id, icmp_size);
    icmp->check = getEtherChecksum();
    // send packet
    etherPutPacket((uint8_t*)ether, 14 + ntohs(ip->length));
}

// Determines whether packet is ARP
uint8_t etherIsArp(uint8_t data[])
{
    uint8_t ok;
    uint8_t i = 0;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    arp = (void*)&ether->data;
    ok = (ether->frameType == 0x0608);
    while (ok && (i < 4))
    {
        ok = (arp->destIp[i] == ipv4Address[i]);
        i++;
    }
    return ok;
}

// Sends an ARP response given the request data
void etherSendArpResp(uint8_t data[])
{
    uint8_t i, tmp;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    arp = (void*)&ether->data;
    // set op to response
    arp->op = 0x0200;
    // swap source and destination fields
    for (i = 0; i < 6; i++)
    {
        arp->destAddress[i] = arp->sourceAddress[i];
        ether->destAddress[i] = ether->sourceAddress[i];
        ether->sourceAddress[i] = arp->sourceAddress[i] = macAddress[i];
    }
    for (i = 0; i < 4; i++)
    {
        tmp = arp->destIp[i];
        arp->destIp[i] = arp->sourceIp[i];
        arp->sourceIp[i] = tmp;
    }
    // send packet
    etherPutPacket((uint8_t*)ether, 42);
}

// Sends an ARP request
void etherSendArpReq(uint8_t data[], uint8_t ip[])
{
    uint8_t i;
    ether = (void*)data;
    arp = (void*)&ether->data;
    // fill ethernet frame
    for (i = 0; i < 6; i++)
    {
        ether->destAddress[i] = 0xFF;
        ether->sourceAddress[i] = macAddress[i];
    }
    ether->frameType = 0x0608;
    // fill arp frame
    arp->hardwareType = 0x0100;
    arp->protocolType = 0x0008;
    arp->hardwareSize = 6;
    arp->protocolSize = 4;
    arp->op = 0x0100;
    for (i = 0; i < 6; i++)
    {
        arp->sourceAddress[i] = macAddress[i];
        arp->destAddress[i] = 0xFF;
    }
    for (i = 0; i < 4; i++)
    {
        arp->sourceIp[i] = ipv4Address[i];
        arp->destIp[i] = ip[i];
    }
    // send packet
    etherPutPacket(data, 42);
}

// Determines whether packet is UDP datagram
// Must be an IP packet
uint8_t etherIsUdp(uint8_t data[])
{
    uint8_t ok;
    uint16_t tmp_int;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    udp = (void*)((uint8_t*)ip + ((ip->rev_size & 0xF) * 4));
    ok = (ip->protocol == 0x11);
    if (ok)
    {
        // 32-bit sum over pseudo-header
        sum = 0;
        etherSumWords(ip->sourceIp, 8);
        tmp_int = ip->protocol;
        sum += (tmp_int & 0xff) << 8;
        etherSumWords(&udp->length, 2);
        // add udp header and data
        etherSumWords(udp, ntohs(udp->length));
        ok = (getEtherChecksum() == 0);
    }
    return ok;
}

// Gets pointer to UDP payload of frame
uint8_t* etherGetUdpData(uint8_t data[])
{
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    udp = (void*)((uint8_t*)ip + ((ip->rev_size & 0xF) * 4));
    return &udp->data;
}

void etherCalcIpChecksum()
{
    // 32-bit sum over ip header
    sum = 0;
    etherSumWords(&ip->rev_size, 10);
    etherSumWords(ip->sourceIp, ((ip->rev_size & 0xF) * 4) - 12);
    ip->headerChecksum = getEtherChecksum();
}

// Send responses to a udp datagram
// destination port, ip, and hardware address are extracted from provided data
// uses destination port of received packet as destination of this packet
void etherSendUdpData(uint8_t data[], uint8_t* udp_data, uint8_t udp_size)
{
    uint8_t *copy_data;
    uint8_t i, tmp;
    uint16_t tmp_int;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    udp = (void*)((uint8_t*)&ether->data + ((ip->rev_size & 0xF) * 4));
    // swap source and destination fields
    for (i = 0; i < 6; i++)
    {
        tmp = ether->destAddress[i];
        ether->destAddress[i] = ether->sourceAddress[i];
        ether->sourceAddress[i] = tmp;
    }
    for (i = 0; i < 4; i++)
    {
        tmp = ip->destIp[i];
        ip->destIp[i] = ip->sourceIp[i];
        ip->sourceIp[i] = tmp;
    }
    // set source port of resp will be dest port of req
    // dest port of resp will be left at source port of req
    // unusual nomenclature, but this allows a different tx
    // and rx port on other machine
    udp->sourcePort = udp->destPort;
    // adjust lengths
    ip->length = htons(((ip->rev_size & 0xF) * 4) + 8 + udp_size);
    // 32-bit sum over ip header
    sum = 0;
    etherSumWords(&ip->rev_size, 10);
    etherSumWords(ip->sourceIp, ((ip->rev_size & 0xF) * 4) - 12);
    ip->headerChecksum = getEtherChecksum();
    udp->length = htons(8 + udp_size);
    // copy data
    copy_data = &udp->data;
    for (i = 0; i < udp_size; i++)
        copy_data[i] = udp_data[i];
        // 32-bit sum over pseudo-header
    sum = 0;
    etherSumWords(ip->sourceIp, 8);
    tmp_int = ip->protocol;
    sum += (tmp_int & 0xff) << 8;
    etherSumWords(&udp->length, 2);
    // add udp header except crc
    etherSumWords(udp, 6);
    etherSumWords(&udp->data, udp_size);
    udp->check = getEtherChecksum();

    // send packet with size = ether + udp hdr + ip header + udp_size
    etherPutPacket((uint8_t*)ether, 22 + ((ip->rev_size & 0xF) * 4) + udp_size);
}


uint32_t etherSendDhcpMessage()
{
  uint8_t i, option_size = 38;
  uint16_t tmp_int;
  if(DhcpState == Request)
	  option_size = 44;
  enc28j60 = (void*)data;
  ether = (void*)&enc28j60->data;
  ip = (void*)&ether->data;
  udp = (void*)((uint8_t*)&ether->data + 20);
  dhcp = (void*)&udp->data;
  for (i = 0; i < 6; i++)
      {
	      ether->sourceAddress[i] = macAddress[i];
          ether->destAddress[i] = 255;
      }
  ether->frameType=0x0008;
 //IP Header
  for (i = 0; i < 4; i++)
     {
	  ip->sourceIp[i] = 0;
      ip->destIp[i] = 255;
     }
  ip->rev_size=0x45;
  ip->typeOfService=0x00;
  ip->length = htons(((ip->rev_size & 0xF) * 4) + 8 + (236+ option_size));
  ip->id=0xd631;
  ip->flagsAndOffset=0x0040;
  ip->ttl=0x80;
  ip->protocol=0x11;
  sum = 0;
  etherSumWords(&ip->rev_size, 10);
  etherSumWords(ip->sourceIp, ((ip->rev_size & 0xF) * 4) - 12);
  ip->headerChecksum = getEtherChecksum();
  //UDP Header
  udp->sourcePort = 0x4400;
  udp->destPort   = 0x4300;
  udp->length = htons(8 + 236 + option_size);
  dhcp->opcode = 0x01;
  dhcp->HWType = 0x01;
  dhcp->HWAddLength = 6;
  dhcp->hops = 0;
  dhcp->ID = 0x12345678;
  dhcp->elapsed_seconds = 0;
  dhcp->flags = 0;
  dhcp->ClientIP = 0;
  dhcp->YourIP = 0;
  dhcp->ServerIP = 0;
  dhcp->GatewayIP =  0;
  for( i=0; i<16;i++)
  {
	if(i<6)
    dhcp->ClientHWAdd[i] = macAddress[i];
	else
		dhcp->ClientHWAdd[i] = 0;
  }
  for(i=0; i<64; i++)
	  dhcp->ServerName[i] = 0;
  for(i=0; i<128; i++)
  	  dhcp->BootFileName[i] = 0;
  dhcp->Magic_Cookie = 0x63538263;
  dhcp_option* option1,*option2,*option3, *request, *option4, *option5;
  option1 = &dhcp->options;
  option1->opcode = 53; //Message Type
  option1->length = 1;
  if(DhcpState == Discover)
  option1->value[0] = 1;
  if(DhcpState == Request)
   option1->value[0] = 3;
  option2 = &option1->value[1];
  option2->opcode = 61; //Client Identifier
  option2->length = 7;
  option2->value[0] = 1;//type Ethernet
  for(i=1; i<=6; i++)
       option2->value[i] = macAddress[i-1];
  if(DhcpState == Request)
  {
	  request = &option2->value[7];
	  request->opcode = 50;
	  request->length = 4;
	  *((uint32_t*)request->value) = *((uint32_t*)ipv4Address);
	  option3 = &request->value[4];
  }
  else
  option3 = &option2->value[7];
  option3->opcode = 12; //Host name
  option3->length = 2;
  option3->value[0] = 'D';
  option3->value[1] = 'J';
  option4 = &option3->value[2];
  option4->opcode = 81; //Client Fully Qualified Domain Name
  option4->length = 5;
  option4->value[0] = 0; //flags
  option4->value[1] = 0; //A-RR Result
  option4->value[2] = 0; //PTR-RR Result
  option4->value[3] = 'D';
  option4->value[4] = 'J';
  option5 = &option4->value[5];
  option5->opcode = 60; //Vendor Class Identifier
  option5->length = 8;
  for(i=0;i<8;i++)
  option5->value[i] = *((uint8_t*)"MSFT 5.0" + i);
  option5->value[8] = 255;//option end
  //UDP Checksum
  sum = 0;
  etherSumWords(ip->sourceIp, 8);
  tmp_int = ip->protocol;
  sum += (tmp_int & 0xff) << 8;
  etherSumWords(&udp->length, 2);
  // add udp header except crc
    etherSumWords(udp, 6);
    etherSumWords(&udp->data, 236+option_size);
    udp->check = getEtherChecksum();
    etherPutPacket((uint8_t*)ether, 22 + ((ip->rev_size & 0xF) * 4) + 236 + option_size);
    return  dhcp->ID;
}

uint16_t DnsQuery(char str[],uint8_t dns_server[])
{
	  uint8_t i = 0, labels = 0, label_size[10], j=0;
	  while(str[i] != '\0')
	  {
        if(str[i] == '.')
        {
        	label_size[labels] = j;
        	labels++;
        	j = 0;
        }
        else
        {
            j++;
        }
        i++;
	  }
	  label_size[labels++] = j;
	  Query_Size = i + 6;;
	  enc28j60 = (void*)data;
	  ether = (void*)&enc28j60->data;
	  ip = (void*)&ether->data;
	  udp = (void*)((uint8_t*)&ether->data + 20);
	  dns = (void*)&udp->data;
	  for (i = 0; i < 6; i++)
	      {
		      ether->sourceAddress[i] = macAddress[i];
	          ether->destAddress[i] = destAddress[i];
	      }
	  ether->frameType=0x0008;
	 //IP Header
	  for (i = 0; i < 4; i++)
	     {
		  ip->sourceIp[i] = ipv4Address[i];
	      ip->destIp[i] = dns_server[i];
	     }
	  ip->rev_size=0x45;
	  ip->typeOfService=0x00;
	  ip->length = htons(((ip->rev_size & 0xF) * 4) + 8 + (12+ Query_Size));
	  ip->id=0xd631;
	  ip->flagsAndOffset=0x0040;
	  ip->ttl=0x80;
	  ip->protocol=0x11;
	  sum = 0;
	  etherSumWords(&ip->rev_size, 10);
	  etherSumWords(ip->sourceIp, ((ip->rev_size & 0xF) * 4) - 12);
	  ip->headerChecksum = getEtherChecksum();
	  //UDP Header
	  udp->sourcePort = 0xC6C6;
	  udp->destPort   = 0x3500;
	  udp->length = htons(8 + 12 + Query_Size);
	  //DNS
      dns->ID = 0x3456;
      dns->flags = 0x0001;
      dns->No_Of_Q = 0x0100;
      dns->N0_Of_A = 0;
      dns->No_Of_AuR = 0;
      dns->No_Of_AdR = 0;
      dns->Queries[0] = label_size[0];
      for(j=1,i=1; i<Query_Size-5; i++)
      {
    	if(str[i-1] == '.')
          dns->Queries[i] = label_size[j++];
    	else
    	 dns->Queries[i] = str[i-1];
      }
      dns->Queries[i++] = 0;
      *((uint16_t*)&dns->Queries[i]) = 0x0100;
      *((uint16_t*)&dns->Queries[i+2]) = 0x0100;
      //UDP Checksum
        sum = 0;
        etherSumWords(ip->sourceIp, 8);
        uint16_t tmp_int = ip->protocol;
        sum += (tmp_int & 0xff) << 8;
        etherSumWords(&udp->length, 2);
        // add udp header except crc
	  etherSumWords(udp, 6);
	  etherSumWords(&udp->data, 16+Query_Size);
	  udp->check = getEtherChecksum();
	  etherPutPacket((uint8_t*)ether, 22 + ((ip->rev_size & 0xF) * 4) + 12 + Query_Size);
	  return  dns->ID;
}


// Determines if the IP address is valid
bool etherIsValidIp()
{
    return ipv4Address[0] || ipv4Address[1] || ipv4Address[2] || ipv4Address[3];
}

// Sets IP address
void etherSetIpAddress(uint8_t a, uint8_t b,  uint8_t c, uint8_t d)
{
    ipv4Address[0] = a;
    ipv4Address[1] = b;
    ipv4Address[2] = c;
    ipv4Address[3] = d;
}

// Gets pointer to TCP payload of frame
uint8_t* etherGetTcpData(uint8_t data[])
{
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    tcp = (void*)((uint8_t*)ip + ((ip->rev_size & 0xF) * 4));
    return &tcp->data;
}

// Determines whether packet is TCP datagram
// Must be an IP packet
uint8_t etherIsTcp(uint8_t data[])
{
    uint8_t ok;
    uint16_t tmp_int,length;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    tcp = (void*)((uint8_t*)ip + ((ip->rev_size & 0xF) * 4));
    ok = (ip->protocol == 0x06);
    if (ok)
    {
        // 32-bit sum over pseudo-header
        sum = 0;
        etherSumWords(ip->sourceIp, 8);
        tmp_int = ip->protocol;
        sum += (tmp_int & 0xff) << 8;
        length = (htons(ip->length)) - ((ip->rev_size & 0x0F)*4);
        sum += htons(length);
        // add tcp header and data
        etherSumWords(tcp, length);
        ok = (getEtherChecksum() == 0);
    }
    return ok;
}



void ethersendTcpSyn()
{
    uint8_t i, tmp;
    uint16_t tmp_int;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    enc28j60->size=0x0046;
    enc28j60->status=0x00C0;
    enc28j60->data=0x02;

    for(i=0; i<6; i++)
       {
       ether->sourceAddress[i]= macAddress[i];
       ether->destAddress[i]= destAddress[i];  //98-40-BB-33-DA-76  //FA-06-69-B7-A2-8C
       }

    ether->frameType=0x0008;

    for(i=0; i<4; i++)
    {
    ip->sourceIp[i]= ipv4Address[i];   //obtained by dhcp
	ip->destIp[i]= destIPAdd[i]; //clocktab.com
    }
    ip->rev_size=0x45;
    ip->typeOfService=0x00;
    ip->id=0xd631;
    ip->flagsAndOffset=0x0040;
    ip->ttl=0x80;
    ip->protocol=0x06;
    sum = 0;
    ip->length = htons(((ip->rev_size & 0xF) * 4) + 20 + 12); //IP header size(5*4) + TCPheaderSize(20) + TCP data(12)
    etherSumWords(&ip->rev_size, 10);
    etherSumWords(ip->sourceIp, ((ip->rev_size & 0xF) * 4) - 12);
    ip->headerChecksum = getEtherChecksum();
    tcp = (void*)((uint8_t*)&ether->data + ((ip->rev_size & 0xF) * 4));
    tcp->sourcePort = currTcpPortNum;
    tcp->destPort = 0x5000;

        tcp->ackNum= 0;
        tcp->seqNum=0x0;
        sequenceId = tcp->seqNum + 1;
        acknowledgementId = 0;
        httpLen = 0;
        tcp->hlengthf=0x0280;
        tcp->windowSize=0x0201;
        tcp->UrgentPointer=0x0000;
        tcp->data[0] = 0x02;
        tcp->data[1] = 0x04;
        tcp->data[2] = 0x00;
        tcp->data[3] = 0x80;
        tcp->data[4] = 0x01;
        tcp->data[5] = 0x03;
        tcp->data[6] = 0x03;
        tcp->data[7] = 0x08;
        tcp->data[8] = 0x01;
        tcp->data[9] = 0x01;
        tcp->data[10] = 0x04;
        tcp->data[11] = 0x02;

        // 32-bit sum over pseudo-header
        sum = 0;
        etherSumWords(ip->sourceIp, 8);
        tmp_int = (ip->protocol & 0xff) << 8;
        sum += tmp_int + 0x2000;
        // add udp header except crc
        etherSumWords(tcp, 16);
        etherSumWords(&tcp->UrgentPointer, 14);
        tcp->check = getEtherChecksum();

        // send packet with size = ether + udp hdr + ip header + udp_size
        etherPutPacket((uint8_t*)ether, 22 + ((ip->rev_size & 0xF) * 4) + 24 + httpLen);
}


void etherSendTcpAckback(uint8_t data[])
{
    uint8_t i, tmp;
    uint16_t tmp_int;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    tcp = (void*)((uint8_t*)&ether->data + ((ip->rev_size & 0xF) * 4));
    // swap source and destination fields



    for (i = 0; i < 6; i++)
    {
        tmp = ether->destAddress[i];
        ether->destAddress[i] = ether->sourceAddress[i];
        ether->sourceAddress[i] = tmp;
    }


    for (i = 0; i < 4; i++)
    {
        tmp = ip->destIp[i];
        ip->destIp[i] = ip->sourceIp[i];
        ip->sourceIp[i] = tmp;
    }

    ip->id=0x8344;
    ip->ttl=0x80;
    // set source port of resp will be dest port of req
    // dest port of resp will be left at source port of req
    // unusual nomenclature, but this allows a different tx
    // and rx port on other machine
    tmp_int=tcp->sourcePort;
    tcp->sourcePort = tcp->destPort;
    tcp->destPort=tmp_int;
    tcp->seqNum= sequenceId;
    httpLen = 0;
    tcp->hlengthf = 0x1050;
    // adjust lengths
    ip->length = htons(((ip->rev_size & 0xF) * 4) + 8 + 12);

    tcp->windowSize=0x0201;
    // 32-bit sum over ip header
    sum = 0;
    etherSumWords(&ip->rev_size, 10);
    etherSumWords(ip->sourceIp, ((ip->rev_size & 0xF) * 4) - 12);
    ip->headerChecksum = getEtherChecksum();

    sum = 0;
    etherSumWords(ip->sourceIp, 8);
    tmp_int = ip->protocol;
    sum += ((tmp_int & 0xff) << 8) + 0x1400;
    // add udp header except crc
    etherSumWords(tcp, 16);
    etherSumWords(&tcp->UrgentPointer, 2);
    tcp->check = getEtherChecksum();

    // send packet with size = ether hdr + ip header + tcp hdr
    etherPutPacket((uint8_t*)ether, 14 + ((ip->rev_size & 0xF) * 4) + 20);
}

void etherSendhttpget(uint8_t data[])
{
    //char message[325] = "GET / HTTP/1.1\r\nAccept: text/html, */*\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299\r\nAccept-Encoding: gzip, deflate\r\nHost: www.clocktab.com\r\nConnection: Keep-Alive\r\n\r\n";
    char message[325] = "GET / HTTP/1.1\r\nAccept: text/plain, */*\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept-Encoding: gzip, deflate\r\nHost: www.clocktab.com\r\nConnection: Keep-Alive\r\n\r\n";
    httpLen = strlen(message);
    uint16_t i, tmp;
    uint16_t tmp_int;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    tcp = (void*)((uint8_t*)&ether->data + ((ip->rev_size & 0xF) * 4));
    char* ptr = (void*)&tcp->data;
    for(i=0;i<httpLen;i++){
        ptr[i] = message[i];
    }

    for(i=0; i<6; i++)
    {
    ether->sourceAddress[i]= macAddress[i];
    ether->destAddress[i]= destAddress[i];  //98-40-BB-33-DA-76  //FA-06-69-B7-A2-8C
    }
    ether->frameType=0x0008;
    for(i=0; i<4; i++)
       {
       ip->sourceIp[i]= ipv4Address[i];   //obtained by dhcp
   	     ip->destIp[i]= destIPAdd[i];    //clocktab.com
       }

    ip->rev_size=0x45;
    ip->typeOfService=0x00;
    ip->id=0x8344;
    ip->ttl=0x80;
    ip->flagsAndOffset=0x0040;
    ip->protocol=0x06;
    // set source port of resp will be dest port of req
    // dest port of resp will be left at source port of req
    // unusual nomenclature, but this allows a different tx
    // and rx port on other machine
    tcp->sourcePort = currTcpPortNum;
    tcp->destPort = 0x5000;
    tcp->seqNum= sequenceId;
    tcp->ackNum = htons32(tempAcknowledgementId);
    tcp->hlengthf = 0x1850;     //psh ack
    ip->length = htons(((ip->rev_size & 0xF) * 4) + 8 + 12 + httpLen);

    tcp->windowSize=0x0201;
    // 32-bit sum over ip header
    sum = 0;
    etherSumWords(&ip->rev_size, 10);
    etherSumWords(ip->sourceIp, ((ip->rev_size & 0xF) * 4) - 12);
    ip->headerChecksum = getEtherChecksum();

    sum = 0;
    etherSumWords(ip->sourceIp, 8);
    tmp_int = ip->protocol;
    sum += ((tmp_int & 0xff) << 8) + htons(20+httpLen);
    // add udp header except crc
    etherSumWords(tcp, 16);
    etherSumWords(&tcp->UrgentPointer, 2);
    etherSumWords(tcp->data, httpLen);
    tcp->check = getEtherChecksum();

    // send packet with size = ether + udp hdr + ip header + udp_size
    etherPutPacket((uint8_t*)ether, 14 + ((ip->rev_size & 0xF) * 4) + 20 + httpLen);
}



void etherSendTcpFinAck(uint8_t data[])
{
    uint8_t i, tmp;
    uint16_t tmp_int;
    enc28j60 = (void*)data;
    ether = (void*)&enc28j60->data;
    ip = (void*)&ether->data;
    for(i=0; i<6; i++)
   {
   ether->sourceAddress[i]= macAddress[i];
   ether->destAddress[i]= destAddress[i];  //98-40-BB-33-DA-76  //FA-06-69-B7-A2-8C
   }
   ether->frameType=0x0008;
   for(i=0; i<4; i++)
	  {
	  ip->sourceIp[i]= ipv4Address[i];   //obtained by dhcp
		 ip->destIp[i]= destIPAdd[i];    //clocktab.com
	  }
    tcp = (void*)((uint8_t*)&ether->data + ((ip->rev_size & 0xF) * 4));
    // swap source and destination fields
    tcp->hlengthf = 0x1150;
    ip->length = htons(((ip->rev_size & 0xF) * 4) + 8 + 12);
    tcp->sourcePort = currTcpPortNum;
    tcp->destPort = 0x5000;
    tcp->seqNum = sequenceId;
    //sequenceId++;
    tcp->windowSize=0x0201;
    // 32-bit sum over ip header
    sum = 0;
    etherSumWords(&ip->rev_size, 10);
    etherSumWords(ip->sourceIp, ((ip->rev_size & 0xF) * 4) - 12);
    ip->headerChecksum = getEtherChecksum();

    sum = 0;
       etherSumWords(ip->sourceIp, 8);
       tmp_int = ip->protocol;
       sum += ((tmp_int & 0xff) << 8) + 0x1400;
       // add udp header except crc
       etherSumWords(tcp, 16);
       etherSumWords(&tcp->UrgentPointer, 2);
       tcp->check = getEtherChecksum();
    // send packet with size = ether hdr + ip header + tcp hdr
    etherPutPacket((uint8_t*)ether, 14 + ((ip->rev_size & 0xF) * 4) + 20);
}

