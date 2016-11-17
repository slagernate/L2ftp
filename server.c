#include <stdio.h>
#if WIN32
#include <ws2tcpip.h>
#include <winsock.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#endif

#include <stdlib.h>
#include "dieWithError.h"

#define IFRAME                  (128)
#define HEADER_LEN              (1)
#define PACKET_COUNTER_LEN      (1)
#define CRC_LEN                 (1)
#define FOOTER_LEN              ((PACKET_COUNTER_LEN) + (CRC_LEN))
#define OVERHEAD_LEN            ((HEADER_LEN) + (FOOTER_LEN))
#define MESSAGE_LEN             ((IFRAME) - (OVERHEAD_LEN))
#define RESPONSE_LEN            (1)

#define MAX_PACKET_COUNT        (64)
#define ERR_REQ                 (65)

typedef struct {
	unsigned int packet_counter	: 12;
	unsigned int crc			: 4;
} packet_footer;

typedef struct {
	unsigned int c0 : 1;
	unsigned int c1 : 1;
	unsigned int c2 : 1;
	unsigned int c3 : 1; // MSB
} crc_st;

char verifyCRC(char *frame, const unsigned int totalBytes);

int main(int argc, char *argv[])
{
	int sock; 
	struct sockaddr_in receiverAddr;
	struct sockaddr_in senderAddr; 
	char frame[IFRAME];
	unsigned char responseFrame[RESPONSE_LEN];
    const char header[] = {0x7E};
	unsigned short serverPort; 
	unsigned int senderAddrLen; 
    struct timeval timeout;

	int recvMsgSize;
	char crcRemainder;

	unsigned int currentPacketCount;
	unsigned int prevPacketCount;

    int enable = 1;
	int first = 1;
    int transmissionSuccessful = 1;
	int i;

    FILE *fp;

    timeout.tv_usec = 0;
    timeout.tv_sec = 5;

    if (argc != 2) 
	{
		fprintf(stderr,"Usage: %s <UDP SERVER PORT>\n", argv[0]);
		exit(1);
	}

	serverPort = atoi(argv[1]); 

#ifdef WIN32
	WSADATA wsaData; 
	
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) 
	{
		fprintf(stderr, "WSAStartup() failed");
		exit(1);
	}
    // Windows equivalent fopen here
#else
    fp = fopen("received_file", "wb");
#endif

	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		DieWithError("socket() failed");

    /* Set recvfrom timeout */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        DieWithError("setsockopt() timeout failed\n");

    /* allow socket reuse */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        DieWithError("setsockopt() reuseaddr failed\n");

	/* construct local address structure */
	memset(&receiverAddr, 0, sizeof(receiverAddr)); 
	receiverAddr.sin_family = AF_INET; /* address family : IPv4 */
	receiverAddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	receiverAddr.sin_port = htons(serverPort); 
    senderAddrLen = sizeof(senderAddr);

	if (bind(sock, (struct sockaddr *) &receiverAddr, sizeof(receiverAddr)) < 0) {
        printf("bind error: %s\n", strerror(errno));
		DieWithError("bind() failed");
    }

 printf("Server listening on port %u\n", serverPort);

 for (;;) 
	{
		memset(frame, 0, sizeof(frame));
        memset(responseFrame, 0, sizeof(responseFrame));

        transmissionSuccessful = 1; 

        /* wait to receive a packet */
		recvMsgSize = recvfrom(sock, frame, IFRAME, 0, (struct sockaddr *) &senderAddr, &senderAddrLen);
        if (recvMsgSize < OVERHEAD_LEN) {
            if (errno == EWOULDBLOCK) {
                printf("File transmission stopped. Quitting...\n");
                break;
            }
            printf("recvfrom() returned value < OVERHEAD_LEN\n"); // (%u)", (unsigned int) OVERHEAD_LEN);
            transmissionSuccessful = 0;
        } 

		crcRemainder = verifyCRC(frame, recvMsgSize);	

		if (crcRemainder) {
			printf("Incorrect packet recieved, (CRC crcRemainder = %02X)\n", crcRemainder);
            transmissionSuccessful = 0;
        } else if (!first) { /* check packet sequence */
            prevPacketCount = currentPacketCount;	
			currentPacketCount = (unsigned int) frame[recvMsgSize - FOOTER_LEN];
			
			if (currentPacketCount == 0) {
                if (prevPacketCount != (MAX_PACKET_COUNT-1)) 
                    transmissionSuccessful = 0;
			} else if ((currentPacketCount - prevPacketCount) != 1) {
                transmissionSuccessful = 0;
            }

            if (!transmissionSuccessful) {
                printf("Current packet count: %u, previous packet count: %u\n"
                       "Current packet count is not 1 greater than previous mod 63\n."
                       "Requesting retransmission...\n",
                       currentPacketCount, prevPacketCount);
            }

		} else {
            first = 0;
			currentPacketCount = (unsigned int) frame[recvMsgSize - FOOTER_LEN];
		}

		if ((memcmp(frame, header, HEADER_LEN) != 0) && transmissionSuccessful) {
			printf("Header not found\n");
            transmissionSuccessful = 0;
		} 
        
        if (transmissionSuccessful) {
            printf("Received correct packet\n");
            fwrite(&frame[HEADER_LEN], (recvMsgSize - OVERHEAD_LEN), 1, fp);
            responseFrame[0] = (currentPacketCount) % (MAX_PACKET_COUNT);
        } else {
            printf("Requesting retransmission\n"); 
            responseFrame[0] = (unsigned char) ERR_REQ;
        }

        if (!(sendto(sock, responseFrame, RESPONSE_LEN, 0, (struct sockaddr *)
            &senderAddr,
            sizeof(senderAddr)) != recvMsgSize))
            DieWithError("sendto() sent a different number of bytes than expected");

	}

#ifdef WIN32
        closesocket(sock);
        WSACleanup();
#else 
        close(sock);
#endif

    return 0;
}

char verifyCRC(char *frame, const unsigned int totalBytes)
{
	char ans = 0;
	crc_st crc;
	unsigned int byte = 0;
	unsigned int bit;
	unsigned int i;
	int leadingZeros = 1;

	memset(&crc, 0, sizeof(crc_st));
	while(byte < totalBytes)
	{
		i = 0;
		while(i < 8) {
			bit = (frame[byte] >> (7-i)) & 0x1;
			if (byte || bit || !leadingZeros) { /* Ignore leading zeros */
				if ((byte != (IFRAME-1)) || (i < 4)) { /* Ignore last 4 padding bits */
					bit = crc.c3 ^ bit;
					crc.c3 = bit ^ crc.c2;
					crc.c2 = bit ^ crc.c1;
					crc.c1 = crc.c0;
					crc.c0 = bit;
					leadingZeros = 0;
				}
			}
			i++;
		}
		byte++;
	}
	
	ans |= (((char) crc.c3) << 3);
	ans |= (((char) crc.c2) << 2); 
	ans |= (((char) crc.c1) << 1);
	ans |= (char) crc.c0;

	return ans;
} 

