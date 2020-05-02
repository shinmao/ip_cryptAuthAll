/*
    convenient library header file for FreeBSD divert socket
    xwang, 07/27/01
*/

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>

int initDivSock(u_short divport);
int readDiv(int sockd, u_char *buf, int buflen, struct sockaddr *saddr);
int writeDiv(int sockd, u_char *buf, int buflen, struct sockaddr *saddr);