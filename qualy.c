#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <arpa/inet.h>           // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>    //Provides declarations for icmp header
#include <netinet/udp.h>        //Provides declarations for udp header
#include <netinet/tcp.h>        //Provides declarations for tcp header
#include <netinet/ip.h>         //Provides declarations for ip header

/*
   @author Gonzalo Gasca Meza
   Oxford University
   Department of Computer Science, Wolfson Building,  
   Parks Rd, Oxford OX1, United Kingdom
   +44 1865 273838
   gonzalo.gasca.meza@cs.ox.ac.uk

   Open packet capture using libpcap library in order to analyze
   RTP streams in detail.
   Analyze H.264 streams
   Convert RTP H.264 stream to video 
   Generate Report
*/


// tcpdump -qns 0 -X -r <filename.pcap>

//defines for the packet type code in an ETHERNET header

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

#define PT_PCMU         0       /* RFC 1890 */
#define PT_1016         1       /* RFC 1890 */
#define PT_G721         2       /* RFC 1890 */
#define PT_GSM          3       /* RFC 1890 */
#define PT_G723         4       /* From Vineet Kumar of Intel; see the Web page */
#define PT_DVI4_8000    5       /* RFC 1890 */
#define PT_DVI4_16000   6       /* RFC 1890 */
#define PT_LPC          7       /* RFC 1890 */
#define PT_PCMA         8       /* RFC 1890 */
#define PT_G722         9       /* RFC 1890 */
#define PT_L16_STEREO   10      /* RFC 1890 */
#define PT_L16_MONO     11      /* RFC 1890 */
#define PT_QCELP        12      /* Qualcomm Code Excited Linear Predictive coding? */
#define PT_CN           13      /* RFC 3389 */
#define PT_MPA          14      /* RFC 1890, RFC 2250 */
#define PT_G728         15      /* RFC 1890 */
#define PT_DVI4_11025   16      /* from Joseph Di Pol of Sun; see the Web page */
#define PT_DVI4_22050   17      /* from Joseph Di Pol of Sun; see the Web page */
#define PT_G729         18
#define PT_CN_OLD       19      /* Payload type reserved (old version Comfort Noise) */
#define PT_CELB         25      /* RFC 2029 */
#define PT_JPEG         26      /* RFC 2435 */
#define PT_NV           28      /* RFC 1890 */
#define PT_H261         31      /* RFC 2032 */
#define PT_MPV          32      /* RFC 2250 */
#define PT_MP2T         33      /* RFC 2250 */
#define PT_H263         34      /* from Chunrong Zhu of Intel; see the Web page */
#define PT_H2641         96      /* Video*/
#define PT_H2642         112
#define PT_H2643         126

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_ip_header(const u_char * , int );
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void print_rtp_packet(const u_char *, int);
char* print_payload(u_int8_t);
int dissect_rtp (const u_char * , int );
void PrintData (const u_char * , int);


FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,rtp=0,others=0,igmp=0,total=0;

//------------------------------------------------------------------- 
int main(int argc, char **argv) { 
  //Temporary packet buffers 
  struct pcap_pkthdr header;      // The header that pcap gives us
  const u_char* packet;           // The actual packet 
  
   logfile=fopen("log.txt","w");
   if(logfile==NULL) {
      printf("Unable to create file.");
    }

  //check command line arguments 
  if (argc < 2) { 
    fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]); 
    exit(1); 
  } 
  
  //-------- Begin Main Packet Processing Loop ------------------- 
  //loop through each pcap file in command line args 
  for (int fnum=1; fnum < argc; fnum++) {  
    //----------------- 

    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    //open the pcap file 
    handle = pcap_open_offline(argv[fnum], errbuf);   //call pcap library function to read existing file
 
    if (handle == NULL) { 
      fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[fnum], errbuf); 
      return(2); 
    }
 
    //Put the device in loop
    pcap_loop(handle , -1 , process_packet , NULL);
 
  } //end for loop through each command line argument 
  //---------- Done with Main Packet Processing Loop --------------  
 
  //output some statistics about the whole trace 
  printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   RTP: %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , rtp, others , total);
 
  return 0; //done

} //end of main() function


void PrintData (const u_char * data , int Size) {

    int i , j;
  
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        } 
         
        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(logfile , "   "); //extra spaces
            }
             
            fprintf(logfile , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }
             
            fprintf(logfile ,  "\n" );
        }
    }
}


void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    fprintf(logfile , "\n\n***********************ICMP Packet*************************\n"); 
     
    print_ip_header(Buffer , Size);
             
    fprintf(logfile , "\n");
         
    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }
     
    fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile , "\n");
 
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(logfile , "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
     
    fprintf(logfile , "\n###########################################################");
}
 
void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );

    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
         
    print_ip_header(Buffer,Size);
         
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");
         
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer + iphdrlen,tcph->doff*4);
         
    fprintf(logfile , "Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size );
                         
    fprintf(logfile , "\n###########################################################");
}

void print_udp_packet(const u_char *Buffer , int Size) {

    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     

    
    
    /*Verify if UDP packet is RTP packet and print it*/
    if (dissect_rtp(Buffer,Size) == 1) {
      print_rtp_packet(Buffer,Size);
      ++rtp;
    }
    /*Not an RTP packet*/
    else {

      fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
     
      print_ip_header(Buffer,Size);           
     
      fprintf(logfile , "\nUDP Header\n");
      fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
      fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
      fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
      fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
      fprintf(logfile , "\n");
      fprintf(logfile , "IP Header\n");
    
      PrintData(Buffer , iphdrlen);
         
      fprintf(logfile , "UDP Header\n");
    
      PrintData(Buffer + iphdrlen , sizeof udph);
         
      fprintf(logfile , "Data Payload\n");    
     
      /*Move the pointer ahead and reduce the size of string*/
      PrintData(Buffer + header_size , Size - header_size);

      fprintf(logfile , "\n###########################################################");
      ++udp;
    }

    
}

int dissect_rtp (const u_char *Buffer , int Size) {

/*
  0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

udp[1] & 1 != 1 && udp[3] & 1 != 1 && udp[8] & 0x80 == 0x80 && length < 250

*/


  typedef struct {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t cc:4;       /* CSRC count */
    u_int8_t x:1;        /* header extension flag */
    u_int8_t p:1;        /* padding flag */
    u_int8_t v:2;        /* protocol version */
    u_int8_t pt:7;       /* payload type */
    u_int8_t m:1;        /* marker bit */
    #elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t v:2;        /* protocol version */
    u_int8_t p:1;        /* padding flag */
    u_int8_t x:1;        /* header extension flag */
    u_int8_t cc:4;       /* CSRC count */
    u_int8_t m:1;        /* marker bit */
    u_int8_t pt:7;       /* payload type */
    #else
    # error "Please fix <bits/endian.h>"
    #endif
    u_int16_t seq;             /* sequence number */
    u_int32_t ts;              /* timestamp */
    u_int32_t ssrc;            /* synchronization source */
    u_int32_t csrc[0];         /* optional CSRC list */
  }
  rtp_hdr_t;

  struct pcap_pkt
  {
    struct    pcap_pkthdr hdr;
    u_int8_t *pkt;
    u_int16_t dllength;
    u_int16_t dlltype;
  };

  unsigned short iphdrlen;
  rtp_hdr_t *rtphdr;
  struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;
  struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
  int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
  
  if (ntohs(udph->source) < 1024 || ntohs(udph->dest) < 1024)
    return 0;

  if (ntohs(udph->dest) % 2 != 0)
    return 0;

  rtphdr = (rtp_hdr_t *)(Buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

  if (rtphdr->v == 2) {
    return 1;
  }

  return 0;

}

void print_rtp_packet(const u_char *Buffer , int Size) {

/*
  0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

udp[1] & 1 != 1 && udp[3] & 1 != 1 && udp[8] & 0x80 == 0x80 && length < 250

*/


  typedef struct {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t cc:4;       /* CSRC count */
    u_int8_t x:1;        /* header extension flag */
    u_int8_t p:1;        /* padding flag */
    u_int8_t v:2;        /* protocol version */
    u_int8_t pt:7;       /* payload type */
    u_int8_t m:1;        /* marker bit */
    #elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t v:2;        /* protocol version */
    u_int8_t p:1;        /* padding flag */
    u_int8_t x:1;        /* header extension flag */
    u_int8_t cc:4;       /* CSRC count */
    u_int8_t m:1;        /* marker bit */
    u_int8_t pt:7;       /* payload type */
    #else
    # error "Please fix <bits/endian.h>"
    #endif
    u_int16_t seq;             /* sequence number */
    u_int32_t ts;              /* timestamp */
    u_int32_t ssrc;            /* synchronization source */
    u_int32_t csrc[0];         /* optional CSRC list */
  }
  rtp_hdr_t;

  struct pcap_pkt
  {
    struct    pcap_pkthdr hdr;
    u_int8_t *pkt;
    u_int16_t dllength;
    u_int16_t dlltype;
  };

  typedef struct
  {
    struct pcap_pkt pcap;
    u_int32_t hdroff;       // offset to reach the first udp byte, the rtp header.
    u_int32_t len;          // length of udp payload (rtp header, extension and codec data).
    struct {
        u_int32_t off;
        u_int32_t len;
    }
    payload;
  } pktrtp_t;


  unsigned short iphdrlen;
  pktrtp_t pktrtp;
  rtp_hdr_t *rtphdr;
  struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;
  struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
  int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
  
  if (ntohs(udph->source) < 1024 || ntohs(udph->dest) < 1024)
    return;

  if (ntohs(udph->dest) % 2 != 0)
    return;

  //(iph->ihl << 2) + sizeof(struct ethhdr) + sizeof(struct udphdr)
  //pktrtp.hdroff = (Buffer +  sizeof(struct ethhdr) + iphdrlen + sizeof udph);
  //pktrtp.hdroff = (int *) Buffer + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
  //pktrtp.len = header_size;
  rtphdr = (rtp_hdr_t *)(Buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

  fprintf(logfile , "\n\n***********************RTP Packet*************************\n");
     
  print_ip_header(Buffer,Size);           
     
  fprintf(logfile , "\nUDP Header\n");
  fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
  fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
  fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
  fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
  
  fprintf(logfile , "\nRTP Header\n");
  fprintf(logfile , "   |-RTP Version      : %01x\n" , (rtphdr->v));
  fprintf(logfile , "   |-Sequence Number  : %d\n" , ntohs(rtphdr->seq));
  fprintf(logfile , "   |-RTP timestamp    : %d\n" , ntohl(rtphdr->ts));
  fprintf(logfile , "   |-RTP SSRC         : %08X\n" , ntohl(rtphdr->ssrc));
  fprintf(logfile , "   |-RTP Payload      : %01x \\(%s\\)\n" ,rtphdr->pt, print_payload(rtphdr->pt));

  
  if (rtphdr->m == 1) {
    fprintf(logfile , "   |-RTP Marker bit   : %01X\n" , (rtphdr->m));
  }

  fprintf(logfile , "\n");
  fprintf(logfile , "IP Header\n");
    
  PrintData(Buffer , iphdrlen);
         
  fprintf(logfile , "UDP Header\n");
    
  PrintData(Buffer + iphdrlen , sizeof udph);
         
  fprintf(logfile , "Data Payload\n");    
     
  /*Move the pointer ahead and reduce the size of string*/
  PrintData(Buffer + header_size , Size - header_size);

  fprintf(logfile , "\n###########################################################");


}

char* print_payload(u_int8_t payload) {

typedef struct 
{
    int type;
    char *str;
} value_string;

value_string result;
int payloadtype = (int) payload;

const value_string rtp_payload_type_short_vals[] =
{
  { PT_PCMU,      "g711U" },
  { PT_1016,      "fs-1016" },
  { PT_G721,      "g721" },
  { PT_GSM,       "GSM" },
  { PT_G723,      "g723" },
  { PT_DVI4_8000, "DVI4 8k" },
  { PT_DVI4_16000, "DVI4 16k" },
  { PT_LPC,       "Exp. from Xerox PARC" },
  { PT_PCMA,      "g711A" },
  { PT_G722,      "g722" },
  { PT_L16_STEREO, "16-bit audio, stereo" },
  { PT_L16_MONO,  "16-bit audio, monaural" },
  { PT_QCELP,     "Qualcomm" },
  { PT_CN,        "CN" },
  { PT_MPA,       "MPEG-I/II Audio"},
  { PT_G728,      "g728" },
  { PT_DVI4_11025, "DVI4 11k" },
  { PT_DVI4_22050, "DVI4 22k" },
  { PT_G729,      "g729" },
  { PT_CN_OLD,    "CN(old)" },
  { PT_CELB,      "CellB" },
  { PT_JPEG,      "JPEG" },
  { PT_NV,        "NV" },
  { PT_H261,      "h261" },
  { PT_MPV,       "MPEG-I/II Video"},
  { PT_MP2T,      "MPEG-II streams"},
  { PT_H263,      "h263" },
  { PT_H2641,      "h264" },
  { PT_H2642,      "h264" },
  { PT_H2643,      "h264" },
  { 0,            NULL },
};

result = rtp_payload_type_short_vals[payloadtype];
return result.str;

}

void print_ethernet_header(const u_char *Buffer, int Size)
{
  struct ethhdr *eth = (struct ethhdr *)Buffer;
     
  fprintf(logfile , "\n");
  fprintf(logfile , "Ethernet Header\n");
  fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
  fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

/*Process packet type */

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *Buffer) {

    int size = header->len;

   //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    ++total;

    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet(Buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(Buffer , size);
            break;
         
        case 17: //UDP Protocol
            print_udp_packet(Buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    
}