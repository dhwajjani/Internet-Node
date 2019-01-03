


// Internet Node
// DHWAJ VANDANKUMAR JANI

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: EK-TM4C123GXL Evaluation Board
// Target uC:       TM4C123GH6PM
// System Clock:    40 MHz

// Hardware configuration:
// Red LED:
//   PF1 drives an NPN transistor that powers the red LED
// Blue LED:
//   PF2 drives an NPN transistor that powers the Blue LED
// Green LED:
//   PF3 drives an NPN transistor that powers the green LED
// Pushbutton:
//   SW1 pulls pin PF4 low (internal pull-up is used)

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#include <stdint.h>
#include <stdbool.h>
#include "tm4c123gh6pm.h"
#include <string.h>
#include "enc28j60.h"
#include "ether.h"

#define RED_LED      (*((volatile uint32_t *)(0x42000000 + (0x400253FC-0x40000000)*32 + 1*4)))
#define BLUE_LED    (*((volatile uint32_t *)(0x42000000 + (0x400253FC-0x40000000)*32 + 2*4)))
#define GREEN_LED    (*((volatile uint32_t *)(0x42000000 + (0x400253FC-0x40000000)*32 + 3*4)))
#define PUSH_BUTTON  (*((volatile uint32_t *)(0x42000000 + (0x400253FC-0x40000000)*32 + 4*4)))
#define RESET        (*((volatile uint32_t *)(0x42000000 + (0x400043FC-0x40000000)*32 + 2*4))) // A2


/////////////////////////////////////////////////////////////////////////////

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------


// Initialize Hardware
void initHw()
{
    // Configure HW to work with 16 MHz XTAL, PLL enabled, system clock of 40 MHz
    SYSCTL_RCC_R = SYSCTL_RCC_XTAL_16MHZ | SYSCTL_RCC_OSCSRC_MAIN | SYSCTL_RCC_USESYSDIV | (4 << SYSCTL_RCC_SYSDIV_S);

    // Set GPIO ports to use APB (not needed since default configuration -- for clarity)
    SYSCTL_GPIOHBCTL_R = 0;

    // Enable GPIO port A,B,C,D,F peripherals
    SYSCTL_RCGC2_R = SYSCTL_RCGC2_GPIOF | SYSCTL_RCGC2_GPIOC | SYSCTL_RCGC2_GPIOA | SYSCTL_RCGC2_GPIOB | SYSCTL_RCGC2_GPIOD;

    // Configure LED and pushbutton pins
    GPIO_PORTF_DIR_R = 0x0E;  // bits 1,2 & 3 are outputs, other pins are inputs
    GPIO_PORTF_DR2R_R = 0x0E; // set drive strength to 2mA (not needed since default configuration -- for clarity)
    GPIO_PORTF_DEN_R = 0x1E;  // enable LEDs and pushbuttons
    GPIO_PORTF_PUR_R = 0x1E;  // enable internal pull-up for push button

    GPIO_PORTD_DIR_R = 0x0;  // bits 1-3 are outputs, other pins are inputs
    GPIO_PORTD_DEN_R = 0x0;  // enable LEDs and pushbuttons

    // Configure RESET for ENC28J60
    GPIO_PORTA_DIR_R = 0x04;  // make bit 1 an output
    GPIO_PORTA_DR2R_R = 0x04; // set drive strength to 2mA
    GPIO_PORTA_DEN_R = 0x04;  // enable bits 1 for digital

    // Configure ~CS for ENC28J60
    GPIO_PORTB_DIR_R = 0x02;  // make bit 1 an output
    GPIO_PORTB_DR2R_R = 0x02; // set drive strength to 2mA
    GPIO_PORTB_DEN_R = 0x02;  // enable bits 1 for digital

    // Configure SSI2 pins for SPI configuration
    SYSCTL_RCGCSSI_R |= SYSCTL_RCGCSSI_R2;           // turn-on SSI2 clocking
    GPIO_PORTB_DIR_R |= 0x90;                        // make bits 4 and 7 outputs
    GPIO_PORTB_DR2R_R |= 0x90;                       // set drive strength to 2mA
    GPIO_PORTB_AFSEL_R |= 0xD0;                      // select alternative functions for MOSI, MISO, SCLK pins
    GPIO_PORTB_PCTL_R = GPIO_PCTL_PB7_SSI2TX | GPIO_PCTL_PB6_SSI2RX | GPIO_PCTL_PB4_SSI2CLK; // map alt fns to SSI2
    GPIO_PORTB_DEN_R |= 0xD0;                        // enable digital operation on TX, RX, CLK pins

    // Configure the SSI2 as a SPI master, mode 3, 8bit operation, 1 MHz bit rate
    SSI2_CR1_R &= ~SSI_CR1_SSE;                      // turn off SSI2 to allow re-configuration
    SSI2_CR1_R = 0;                                  // select master mode
    SSI2_CC_R = 0;                                   // select system clock as the clock source
    SSI2_CPSR_R = 40;                                // set bit rate to 1 MHz (if SR=0 in CR0)
    SSI2_CR0_R = SSI_CR0_FRF_MOTO | SSI_CR0_DSS_8;   // set SR=0, mode 0 (SPH=0, SPO=0), 8-bit
    SSI2_CR1_R |= SSI_CR1_SSE;                       // turn on SSI2
    //


    SYSCTL_RCGCUART_R |= SYSCTL_RCGCUART_R0;                           // turn-on UART0, leave other uarts in same status
    GPIO_PORTA_DEN_R |= 3;                                             // default, added for clarity
    GPIO_PORTA_AFSEL_R |= 3;                                           // default, added for clarity
    GPIO_PORTA_PCTL_R = GPIO_PCTL_PA1_U0TX | GPIO_PCTL_PA0_U0RX;       // define peripheral control for TX and RX of UART0

    // Configure UART0 to 115200 baud, 8N1 format (must be 3 clocks from clock enable and config writes)
    UART0_CTL_R = 0;                                                   // turn-off UART0 to allow safe programming
    UART0_CC_R = UART_CC_CS_SYSCLK;                                    // use system clock (40 MHz)
    UART0_IBRD_R = 21;                                                 // r = 40 MHz / (Nx115.2kHz), set floor(r)=21, where N=16
    UART0_FBRD_R = 45;                                                 // round(fract(r)*64)=45
    UART0_LCRH_R = UART_LCRH_WLEN_8 | UART_LCRH_FEN;                   // configure for 8N1 w/ 16-level FIFO
    UART0_CTL_R = UART_CTL_TXE | UART_CTL_RXE | UART_CTL_UARTEN;

}


void initTimer1()
{
    SYSCTL_RCGCTIMER_R |= SYSCTL_RCGCTIMER_R1;       // turn-on timer
    TIMER1_CTL_R &= ~TIMER_CTL_TAEN;                 // turn-off timer before reconfiguring
    TIMER1_CFG_R = TIMER_CFG_32_BIT_TIMER;           // configure as 32-bit timer (A+B)
    TIMER1_TAMR_R = TIMER_TAMR_TAMR_PERIOD;          // configure for periodic mode (count down)
    TIMER1_TAILR_R = 0x2625A00;                       //Time period 1 Second
    TIMER1_IMR_R = TIMER_IMR_TATOIM;                 // turn-on interrupts
    NVIC_EN0_R |= 1 << (INT_TIMER1A-16);             // turn-on interrupt 37 (TIMER1A)
    TIMER1_CTL_R |= TIMER_CTL_TAEN;                  // turn-on timer

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void putcUart0(char c)
{
    while (UART0_FR_R & UART_FR_TXFF);     // wait till the TX FIFO is empty
    UART0_DR_R = c;                        // put the character in the FIFO
}

//
void nextLine()
{
    putcUart0('\n');
    putcUart0('\r');
}

void putsUart0(char* str)
{
    uint8_t i;                            // define a counter
    uint8_t s;
    s = strlen(str);
    for (i = 0; i < s; i++)               // increment the counter till the end of the string
      putcUart0(str[i]);                  // put individual characters on the FIFO
}


// Blocking function that writes a number when the UART buffer is not full
void putnUart0(uint8_t c)
{
    char snum[10];
    uint8_t a = c;
    uint8_t n,i = 0,j = 0;
    while(a!=0)
    {
        //a = a%10;
        a = a/10;
        i++;
    }
    snum[i] = 0;
    a = c;
    if(c == 0)
    putsUart0("0");
    while(a != 0)
    {
        n = a%10;
        a = a/10;
        snum[i-1-j] = n+48;
        j++;
    }
    putsUart0(snum);                   //prints a number after convertig it to ASCII
}


// Blocking function that returns with serial data once the buffer is not empty
char getcUart0()
{
    while (UART0_FR_R & UART_FR_RXFE);    // wait till the RX FIFO is full
    return UART0_DR_R & 0xFF;             // return the received character after masking the control information
}


uint16_t getNumber(char str[])
{
    uint16_t number;
    char* c;
	c = &str[0];                                         // obtain the position of the number if valid
	number = atoi(c);                                    // convert the string to an integer
	return number;
}




void timer1Isr()
{
    if((change_count == last_change) && (tcpState == httpReqSent))
    {
    	        tcpState = ESTAB;
    }
    last_change = change_count;
	timeup = true;
    TIMER1_ICR_R = TIMER_ICR_TATOCINT;               // clear interrupt flag
}


void showtime(uint8_t* ptr)
{
  uint8_t* end_point;
  end_point = strstr(ptr,(char*)"\r\n");
  putcUart0('\r');
  while(ptr<end_point)
  {
  putcUart0(*ptr);
  ptr++;
  }
}

uint16_t getNextIndex(uint16_t index)
{
	uint16_t offset = 0;
    while(true)
    {
    	if(htmlMessage[index]>= '0' && htmlMessage[index]<= '9')
    		offset = (htmlMessage[index++] - '0') + (offset*16);
    	else if(htmlMessage[index]>= 'a' && htmlMessage[index]<= 'f')
    		offset = (htmlMessage[index++] - 'a' + 10) + (offset*16);
	    else
	       break;
    }
  return (index+offset+4);
}

uint8_t* FindString(uint8_t* ptr,char str[])
{
	bool ok;
	uint32_t i,start_index,j,length;
	length = strlen(str);
	start_index = ptr - htmlMessage;
   for(i=start_index;i<htmlIndex-length;i++)
   {
	   ok = true;
	   for(j=0;j<length;j++)
	   {
          ok &= (htmlMessage[i+j] == str[j]);
          if(!ok)
        	  break;
	   }
	   if(ok)
		  return (&htmlMessage[i]);
   }
   return 0;
}

void GetIP()
{
	 bool ok; uint8_t i;
	 struct _dhcp* dhcpData;
	 uint16_t SourcePort, DestPort;
	 uint32_t Xact_ID, *ptr;
   while(DhcpState != GotIP)
   {
	 Xact_ID = etherSendDhcpMessage();
	 if(DhcpState == Discover)
		 DhcpState = AwaitOffer;
	 else if(DhcpState == Request)
		    DhcpState = AwaitAck;
	 waitMicrosecond(100000);
	 while(DhcpState == AwaitOffer || DhcpState == AwaitAck)
	 {
	 if(etherKbhit())
	 {
	 if (etherIsOverflow())
	 {
		 RED_LED = 1;
		 waitMicrosecond(100000);
		 RED_LED = 0;
	 }

	 // get packet
	 etherGetPacket(data, 1536);
	 if (etherIsIp(data))
	    {
		 if (etherIsUdp(data))
			{
				dhcpData = etherGetUdpData(data);
				SourcePort = ntohs(*((uint16_t*)dhcpData - 4));
				DestPort  = ntohs(*((uint16_t*)dhcpData - 3));
				ok = true;
                for(i=0; i<6; i++)
                {
                  ok &= (dhcpData->ClientHWAdd[i] == macAddress[i]);
                }
				if(SourcePort == 67 && DestPort == 68 && dhcpData->ID == Xact_ID && ok)
				{
					if(dhcpData->Magic_Cookie ==  0x63538263)
					{
					 if((dhcpData->options == 53) && (*((uint8_t*)&dhcpData->options + 2) == 2) && (DhcpState == AwaitOffer))
					 {
						 for(i = 0; i<6; i++)
							 destAddress[i] =  ether->sourceAddress[i];
						 *((uint32_t*)ipv4Address) = dhcpData->YourIP;
					     i = 0;
					     while( *((uint8_t*)&dhcpData->options + i) !=  6 && *((uint8_t*)&dhcpData->options + i) !=  255)
							{
								i += *((uint8_t*)&dhcpData->options + i + 1) + 2;
							}
						  ptr =  (uint8_t*)&dhcpData->options + i + 2;
						  *((uint32_t*)DNS1) =  *(ptr);
					      *((uint32_t*)DNS2) =  0x08080808;
						  DhcpState = Request;
					 }
					 if((dhcpData->options == 53) && (*((uint8_t*)&dhcpData->options + 2) == 5) && (DhcpState == AwaitAck))
					 {
                         DhcpState = GotIP;
					 }
					 if((dhcpData->options == 53) && ((*((uint8_t*)&dhcpData->options + 2) == 4) || (*((uint8_t*)&dhcpData->options + 2) == 6)))
					 {
						 DhcpState = Discover;
					 }
					}
				}
			  }
	      }
	 }
    }
   }
}
//-----------------------------------------------------------------------------
// Main
//-----------------------------------------------------------------------------

int main(void)
{
    uint8_t *udpData,*p,*Date;
    struct _dns *dnsData;
    uint16_t i,DNS_ID1,DNS_ID2;
    IPseqId = 0; sequenceId = 0;
    bool DNS_Resolved = false,found,server_end = false,User_terminated = false;
    tcpState=CLOSED;
    stuck = false;
    currTcpPortNum = 0x40D4;
    macAddress[0] = 0;macAddress[1] = 1;
    macAddress[2] = 2;macAddress[3] = 3;
    macAddress[4] = 4;macAddress[5] = 6;

    initHw();
    RED_LED = 1;
        GREEN_LED=1;
        RESET=0;
        waitMicrosecond(500000);
        RESET=1;
        waitMicrosecond(5000000);
        GREEN_LED=0;
        // init ethernet interface
        etherInit(ETHER_UNICAST | ETHER_BROADCAST | ETHER_HALFDUPLEX);

        // flash phy leds
        etherWritePhy(PHLCON, 0x0880);
        RED_LED = 1;
        waitMicrosecond(500000);
        etherWritePhy(PHLCON, 0x0990);
        RED_LED = 0;
        waitMicrosecond(5000000);
        DhcpState = Discover;
        GetIP();
        RED_LED = 1;
        GREEN_LED = 1;
        BLUE_LED = 1;
        waitMicrosecond(1000000);
        RED_LED = 0;
	   GREEN_LED = 0;
	   BLUE_LED = 0;
        while(true)
        {
        	if((PUSH_BUTTON == 0)&&(!DNS_Resolved))
        	{
        	  waitMicrosecond(500000);
  			  DNS_ID1 = DnsQuery("www.clocktab.com",DNS1); //send dns query to 2 dhcp servers
  			  DNS_ID2 = DnsQuery("www.clocktab.com",DNS2);
        	}
        	if(DNS_Resolved)
        	{
        		switch(tcpState)                   //TCP transmit section
        		{
        		case CLOSED:if(User_terminated)
        		            {
                               if(PUSH_BUTTON == 0)
                               {
                            	   while(PUSH_BUTTON == 0);
                            	   User_terminated = false;
                               }
        		            }
        		            if(!User_terminated)
        		            {
        			        GREEN_LED = 1;
        		            if(server_end)
        		            {
        		            currTcpPortNum += 0x0100;
        		            server_end = false;
        		            }
							ethersendTcpSyn();
							initTimer1();
							change_count = 0;
							last_change = 65537;
							timeup = 0;
							tcpState=SYN_SENT;
							GREEN_LED = 0;
							waitMicrosecond(100000);
        		            }
							break;
        		case ESTAB: if(PUSH_BUTTON == 0)
        				    {
        			          while(PUSH_BUTTON == 0);
        				      tcpState = FIN_ACK;
        				      User_terminated = true;
        				    }
        		            else if(timeup)
        		            {
        			        etherSendhttpget(data);
							tcpState = httpReqSent;
							timeup = false;
							waitMicrosecond(100000);
							BLUE_LED = 0;
							change_count++;
							htmlIndex = 0;
							found = false;
							chunked = false;
							totlen = 0;
        		            }
							break;
        	  case FIN_ACK: if(server_end)
							{
							  tempAcknowledgementId = htons32(tcp->seqNum);
							  sequenceId = tcp->ackNum;
							  tcp->ackNum = htons32(tempAcknowledgementId+1);
							  tcpState = CLOSED;
							}
							else
							  tcpState = LAST_ACK;
							 BLUE_LED = 1;
							 etherSendTcpFinAck(data);
							 waitMicrosecond(100000);
							 BLUE_LED=0;
							 break;
        	      default:   i =i;
        		}
        	}
          if (etherKbhit())
          {
            if (etherIsOverflow())
            {
                RED_LED = 1;
                waitMicrosecond(100000);
                RED_LED = 0;
            }

            // get packet
            etherGetPacket(data, 1536);

            // handle ip datagram
            if (etherIsIp(data))
            {
                if (etherIsIpUnicast(data))
                {
                    // handle icmp ping request
                    if (etherIsPingReq(data))
                    {
                        etherSendPingResp(data);
                        RED_LED = 1;
                        BLUE_LED = 1;
                        waitMicrosecond(50000);
                        RED_LED = 0;
                        BLUE_LED = 0;
                    }
                    // handle udp datagram
                    else if (etherIsUdp(data))
                    {
                    	if(!DNS_Resolved && udp->sourcePort == 0x3500)
                    	{
                          dnsData = etherGetUdpData(data);
                          if((dnsData->ID == DNS_ID1) || (dnsData->ID == DNS_ID2))
                          {
                        	 dnsans = &dnsData->Queries[Query_Size];
                        	for(i=0; i<ntohs(dnsData->N0_Of_A) ; i++)
                        	{
                        	       if(dnsans->type != 0x0100)
                        	       {
                        	    	   dnsans =  (uint8_t*)dnsans  + ntohs(dnsans->length) + 12; //12 bytes of Question which we sent in DNS Query
                        	       }
                        	       else
                        	       {
                        	    	   *((uint32_t*)destIPAdd) = *((uint32_t*)dnsans->value);
                        	    	    DNS_Resolved = true;
                                        break;
                        	       }
                        	}
                          }
                    	}
                    }
                    ////////////////////////////////////////////////////////////////////////////////////////////////////
                    else if (etherIsTcp(data))
                    {
                      if((tcp->destPort == currTcpPortNum) && (*((uint32_t*)ip->sourceIp) == *((uint32_t*)destIPAdd)))
                      {
                        if(((tcp->hlengthf & 0x1100) == 0x1100) && (tcpState != LAST_ACK)) //If server wants to end TCP connection
                        {
                        	              tcpState = FIN_ACK;
                        	              server_end = true;
                        }
                      switch(tcpState)                         //TCP recieve Section
                      {
                         case SYN_SENT: if((tcp->hlengthf & 0x1200) == 0x1200) //if its syn+ack
                                        {
										BLUE_LED = 1;
										sequenceId = tcp->ackNum;
										tempAcknowledgementId = htons32(tcp->seqNum) + 1;
                                        tcp->ackNum= htons32(tempAcknowledgementId);
										etherSendTcpAckback(data);
										tcpState = ESTAB;
										timeup = true;
                                        }
                                        break;
                      case httpReqSent:change_count++;
                    	               totlen = (htons(ip->length)) - ((ip->rev_size & 0x0F)*4) - (((tcp->hlengthf>>4)&0x0F)*4); //get tcp data length
									   if((totlen > 0))
									  {
										 if(tcp->seqNum >= htons32(tempAcknowledgementId))
										 {
										  for(i=htmlIndex; i<(htmlIndex+totlen);i++)
										  {
											  htmlMessage[i] = tcp->data[i-htmlIndex];
										  }
										  htmlIndex += totlen;
										  if(!found)
										  {
										  p = FindString(htmlMessage,(char*)"\r\n\r\n");
										  if(p)
										  {
											  found = true;
                                             Date = FindString(htmlMessage,(char*)"Date");
                                             p = FindString(htmlMessage,(char*)"Transfer-Encoding");
                                             if(p)
                                             {
                                            	 p = FindString(p,(char*)"chunked");
                                                 if(p)
                                                 {
                                                    chunked = true;
                                                 }
                                             }

										  }
										  }
										 }
										  tempAcknowledgementId = htons32(tcp->seqNum) + totlen;
									      tcp->data[totlen] = '\0';
										  p = strstr(&tcp->data[totlen-5],(char*)"0\r\n\r\n");
										  sequenceId = tcp->ackNum;
										  tcp->ackNum = htons32(tempAcknowledgementId);
										  etherSendTcpAckback(data);
										  if(Date)
										  {
										  showtime(Date);
										  Date = 0;
										  }
										  if(p)
										  {
										   tcpState = ESTAB;
                                          }
									      }
                                         break;
                        case LAST_ACK:   tempAcknowledgementId = htons32(tcp->seqNum);              //relative  //40 = ip and tcp heade
                                         sequenceId = tcp->ackNum;
                        		         tcp->ackNum = htons32(tempAcknowledgementId + 1);
                        	             etherSendTcpAckback(data);
									     tcpState = CLOSED;
                                         break;
                              default:   i = i;
						}

                      }
                    }
                }
            }

                       // handle arp request
            else if (etherIsArp(data))
                       {
                           etherSendArpResp(data);
                           RED_LED = 1;
                           GREEN_LED = 1;
                           waitMicrosecond(50000);
                           RED_LED = 0;
                           GREEN_LED = 0;
                       }
          }

    }

}

