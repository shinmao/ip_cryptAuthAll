/*
  Reference to divert-loop.c ip_authAll.c by Xinyuan Wang 2/27/2020
*/

#define DEBUG

#include "divertlib.h"
#include <openssl/md5.h>
#include <openssl/rc4.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define maxbuflen 1520

void getrc4(const unsigned char *inputstr, int inputstrlen, unsigned char *keystr, int keystrlen, unsigned char *output){
  RC4_KEY key;
  RC4_set_key(&key, keystrlen, keystr);

  output = (unsigned char *)malloc(inputstrlen + 1);
  memset(output, 0, inputstrlen + 1);
  RC4(&key, inputstrlen, inputstr, output);
}


void getmd5(const unsigned char *inputstr, int inputstrlen, unsigned char *digest)
/* assume digest has at least 16 byte memory allocated
*/
{
	MD5_CTX context;
  MD5_Init(&context);
  MD5_Update(&context, inputstr, inputstrlen);
  MD5_Final(digest, &context);
}

int processInPktPayload(const unsigned char *pktPld, unsigned int pktPldLen, 
			      unsigned char *newpktPld, char *keystr, unsigned int keystrL)
/*
   process incoming packet payload pktPld: checking if it is authenticated with keystr. 
   return: >0: length of the new packet paload, which should be pktPldLen-16
	-1: invalid input parameter
	-2: authentication failed
*/
{
  int newPldL;
  unsigned char md5Str[16];
  unsigned char authmd5Str[pktPldLen];
  unsigned char rc4Str[pktPldLen - 16];

  if (pktPld == NULL || newpktPld == NULL || keystr == NULL || pktPldLen <=16 || keystrL == 0){
	  return -1;
  }
    
  // md5
  newPldL = pktPldLen - 16;
  memcpy(authmd5Str, pktPld, newPldL);
  memcpy(&authmd5Str[newPldL], keystr, keystrL);
  getmd5(authmd5Str, newPldL+keystrL, md5Str);
  if (memcmp(&pktPld[newPldL], md5Str, 16) != 0){	// authentication failed
	 printf("processInPktPayload(payload of length %d bytes) failed authentication\n", pktPldLen);
	 return -2;
  }
  // rc4
  memcpy(rc4Str, pktPld, newPldL);
  getrc4(rc4Str, pktPldLen-16, keystr, keystrL, newpktPld);  // newpktPld = rc4-decrypted packet 
  printf("*** processInPktPayload(payload of len %d bytes) generated decrypted payload of length:%d bytes\n", pktPldLen, newPldL);
  return newPldL;
}

int processOutPktPayload(const unsigned char *pktPld, unsigned int pktPldLen, 
			      unsigned char *newpktPld, char *keystr, unsigned int keystrL)
/*
   process outgoing packet payload pktPld, adding MAC and generate new packet payload in newpktPld
   return: >0: length of the new packet paload, which should be pktPldLen+16
	-1: invalid input parameter
*/
{
  int newPldL;
  unsigned char rc4Str[pktPldLen];
  unsigned char md5Str[16];

  if (pktPld == NULL || newpktPld == NULL || keystr == NULL || pktPldLen ==0 || keystrL == 0){
	 return -1;
  }
  // rc4
  getrc4(pktPld, pktPldLen, keystr, keystrL, rc4Str);
  // md5
  newPldL = pktPldLen + 16;
  memcpy(newpktPld, rc4Str, pktPldLen);
  memcpy(&newpktPld[pktPldLen], keystr, keystrL);
  getmd5(newpktPld, pktPldLen+keystrL, md5Str);
  memcpy(&newpktPld[pktPldLen], md5Str, 16);
  printf("*** processOutPktPayload(payload of len %d bytes) generated encrypted payload of length:%d bytes\n", pktPldLen, newPldL);
  return newPldL;
}

int SumWords(u_int16_t *buf, int nwords)
{
  register u_int32_t  sum = 0;

  while (nwords >= 16){
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    sum += (u_int16_t) ntohs(*buf++);
    nwords -= 16;
  }
  while (nwords--)
    sum += (u_int16_t) ntohs(*buf++);
  return(sum);
}

/*
 * ip_checksum()
 *
 * Recompute an IP header checksum
 */
void ip_checksum(struct ip *ip)
{
  register u_int32_t	sum;

/* Sum up IP header words */

  ip->ip_sum = 0;
  sum = SumWords((u_int16_t *) ip, ip->ip_hl << 1);

/* Flip it & stick it */

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  sum = ~sum;

  ip->ip_sum = htons(sum);
}

int main(int argc, char *argv[]){ 
  int i, len, payloadL, nPldL, keyl, divsock;
  u_short iphlen, tcphlen;
  int udpsock, DivPort;
  struct sockaddr_in sin, sin1;
  struct in_addr ipaddr;
  struct ip *iph, *iph2;
  struct tcphdr *tcph;
  struct udphdr *udph;
  unsigned char buf[maxbuflen+1], buf2[maxbuflen+1];
  int addrsize=sizeof (struct sockaddr);

  if (argc!=4){ 
    puts("usage : ip_cryptAuthAll [divert port] [remote IP] [key phrase]");
    return -1;
  }

  DivPort=atoi(argv[1]);
  printf("DivPort=%d\n", DivPort);

  if (inet_aton(argv[2], &ipaddr) == 0)	// invalid remote IP address
  {
      printf("*** invalid remote IP '%s'\n", argv[2]);
      return -1;
  }
  keyl = strlen(argv[3]);

  if ((divsock=initDivSock(DivPort))<=0)
  { 
    printf("can not get divert socket for port %d, divsock=%d\n", DivPort, divsock);
    exit(1);
  }

  for (i=1; ;i++)
  {
/* if ((len=readDiv(divsock, buf, maxbuflen, (struct sockaddr *) &sin))>0)
 */
    if ((len=recvfrom(divsock, buf, maxbuflen, 0, (struct sockaddr *) &sin, &addrsize))>0)
    {
      iph=(struct ip *) buf;
      iphlen=iph->ip_hl<<2;
      payloadL = len - iphlen;
      printf("packet len: %d; iphlen: %d, payloadL: %d\n", len, iphlen, payloadL);
      iph2=(struct ip *) buf2;
      if (sin.sin_addr.s_addr==INADDR_ANY) /* outgoing */
      {
	      printf("\n%d: Out\t==>\n", i);
      	if (ipaddr.s_addr == iph->ip_dst.s_addr)
      	{
    	    printf("packet (proto no: %d) to %s needs to be authenticated\n", 
    		    iph->ip_p, argv[2]);
    	    nPldL = processOutPktPayload(&buf[iphlen], payloadL, &buf2[iphlen], argv[3], keyl);
    	    if (nPldL == payloadL + 16)
    	    {
        		memcpy(buf2, buf, iphlen);
        		iph2->ip_len = htons(ntohs(iph2->ip_len) + 16);
        		len += 16;
        		ip_checksum(iph2);
    	    }
    	    else	
    	    {
    		    continue;
    	    }
      	}
      }
      else /* incoming */
      {
	       printf("\n%d: In from %s:%d\t<==\n", i, inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
        	if (ipaddr.s_addr == iph->ip_src.s_addr)
        	{
        	    printf("packet (proto no: %d) from %s needs to be authenticated\n", iph->ip_p, argv[2]);
        	    nPldL = processInPktPayload(&buf[iphlen], payloadL, &buf2[iphlen], argv[3], keyl);
        	    if (nPldL == payloadL - 16)
        	    {
            		memcpy(buf2, buf, iphlen);
            		iph2->ip_len = htons(ntohs(iph2->ip_len) - 16);
            		len -= 16;
            		ip_checksum(iph2);
        	    }
        	    else
        	    {
        		    continue;
        	    }
        	}	
      }
      printf("\tsrc IP:%s\n", inet_ntoa(iph->ip_src));
      printf("\tdst IP:%s\n", inet_ntoa(iph->ip_dst));
      printf("\tproto :%d\n", iph->ip_p);

      sendto(divsock, buf2, len, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr));
    }
  }
  return 0;
}
