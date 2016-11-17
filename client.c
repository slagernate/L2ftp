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
#include <stdlib.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#endif 

#include <stdio.h> 
#include "dieWithError.h"

#define IFRAME                  (128)
#define HEADER_LEN              (1)
#define PACKET_COUNTER_LEN      (1)
#define CRC_LEN                 (1)
#define FOOTER_LEN              ((PACKET_COUNTER_LEN) + (CRC_LEN))
#define OVERHEAD_LEN            ((HEADER_LEN) + (FOOTER_LEN))
#define MESSAGE_LEN             ((IFRAME) - (OVERHEAD_LEN))
#define RESPONSE_LEN            (1)
#define NO_ERR                  (false)
#define MAX_TX_ATTEMPTS         (10)

#define MAX_PACKET_COUNT        (64)
#define ERR_REQ                 (65)
#define ARQ_TIMEOUT             (1)

typedef struct {
	unsigned int packetCounter	: 12;
	unsigned int crc			: 4;
} packetFooter;

typedef struct {
	unsigned int c0 : 1;
	unsigned int c1 : 1;
	unsigned int c2 : 1;
	unsigned int c3 : 1; // MSB
} crc_st;


void encapsulate(char* frame, const unsigned int count, const unsigned int bytes, const bool shouldCorrupt);
char calculateCRC(char *frame, const unsigned int totalBytes);

int main(int argc, char *argv[])
{
	int sock; 
	struct sockaddr_in serverAddr; /* server address */
	struct sockaddr_in fromAddr; /* Source address */
	unsigned short serverPort; /* server port */
	unsigned int fromSize; 
	char *serverIP; /* IP address of server */
	char frame[IFRAME]; 
	char spareFrame[IFRAME]; 
	char recvFrame[RESPONSE_LEN]; 
	size_t bytesRead = 0; // from file
    size_t bytesSent = 0;
	int bytesReceived;

    struct timeval timeout;
    unsigned int packetCount = 0;
    unsigned int retransmissionAttempts = 0;
    bool sendErrors = false;
	int r;

    timeout.tv_usec = 0;
    timeout.tv_sec = ARQ_TIMEOUT;

    srand(time(NULL)); 

#ifdef WIN32
	WSADATA wsaData;
	HANDLE hFile;
	LPCWSTR fileName = L"bugsbunny1.wav";
#else	
    FILE *fp;
#endif

	if ((argc !=  5)) 
	{
		fprintf(stderr,"Usage: %s <filename> <send errors(0 or 1)> <Server IP> <Echo Port>\n", argv[0]);
		return -1;
	}

    if (!strcmp(argv[2], "1")) {
        sendErrors = true;
    } else if (strcmp(argv[2], "0")) {
        printf("Arg two != 1 or 0. Assuming 0\n");
    }

	serverIP = argv[3]; 
    serverPort = atoi(argv[4]); 

#ifdef WIN32
	hFile = CreateFile(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error opening file. Last error = %d\n", GetLastError());
		return;
	}

    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) 
	{
		fprintf(stderr, "WSAStartup() failed");
		exit(1);
	}

#else
    fp = fopen(argv[1], "rb");

    if (fp == NULL) {
        printf("fopen() failed with error: %s\n", strerror(errno));
        return -1;
    }
#endif


	/* create a best-effort datagram socket using UDP */
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		DieWithError("socket() failed");

    /* set timeout */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) < 0)
        DieWithError("setsockopt() rcvtimeo failed");

	/* construct the server address structure */
	memset(&serverAddr, 0, sizeof(serverAddr)); 
	serverAddr.sin_family = AF_INET; /* address family: IPv4 */
	serverAddr.sin_addr.s_addr = inet_addr(serverIP); 
	serverAddr.sin_port = htons(serverPort); 
    fromSize = sizeof(fromAddr);

    do {
        bytesRead = 0;
        memset(frame, 0, sizeof(frame));
        memset(spareFrame, 0, sizeof(frame));
        retransmissionAttempts = 0;

#ifdef WIN32
        r = ReadFile(hFile, (LPVOID) &frame[1], (DWORD) IFRAME - 3, (DWORD *) &bytesRead, NULL); 

        if (!r) {
            printf("ReadFile failed. Last error = %d\n", GetLastError());
            return;
        }
#else
        bytesRead = fread(&frame[HEADER_LEN], sizeof(char), MESSAGE_LEN, fp);
#endif

        
        /* save spare in case someone corrupts it :) */
        memcpy(spareFrame, frame, IFRAME);

        encapsulate(frame, packetCount, (bytesRead + OVERHEAD_LEN), sendErrors);

        while (1) { /* keep sending until ack received */

            if (retransmissionAttempts > MAX_TX_ATTEMPTS) {
                printf("Exceeded max retransmission attempts (%d)! Quitting...\n", (unsigned int) MAX_TX_ATTEMPTS);
                return -1;
            }
            
            /* send packet */
            bytesSent = sendto(sock, frame, (bytesRead + OVERHEAD_LEN), 0, 
            (struct sockaddr *) &serverAddr, sizeof(serverAddr));

            if (bytesSent != (bytesRead + OVERHEAD_LEN))
                DieWithError("sendto() sent a different number of bytes than expected");

            /* wait for ACK */
            bytesReceived = recvfrom(sock, &recvFrame, RESPONSE_LEN, 0, 
                (struct sockaddr*) &fromAddr, &fromSize);

            if (bytesReceived < RESPONSE_LEN)  {
                if (errno == EWOULDBLOCK) {
                    printf("Recipient didn't respond within %u second(s), resending packet\n", ARQ_TIMEOUT);
                } else {
                    printf("Recvfrom() returned less than RESPONSE_LEN bytes (%d)\n", RESPONSE_LEN);
                }
            } else if ((bytesReceived == RESPONSE_LEN) && (recvFrame[0] == packetCount)) {
                printf("Packet number %u sent\n", packetCount);
                if (serverAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr)
                {
                    fprintf(stderr,"Error: received a packet from unknown source.\n");
                    exit(1);
                }
                break;
            } else if ((bytesReceived == RESPONSE_LEN) && (recvFrame[0] == (unsigned char) ERR_REQ)) {
                printf("Retransmisison request received. Resending...\n");
                memcpy(frame, spareFrame, IFRAME);
                encapsulate(frame, packetCount, (bytesRead + OVERHEAD_LEN), NO_ERR);
            } else {
                printf("Incorrect response: %02X, resending packet\n", recvFrame[0]);
            }

        retransmissionAttempts++;
        }

        packetCount++;

        if (packetCount >= MAX_PACKET_COUNT) {
            packetCount = 0;
        }
    } while (bytesRead > 0);

    printf("EOF reached!\n");

#ifdef WIN32
	CloseHandle(hFile);
	closesocket(sock);
	WSACleanup(); 
#else
    close(sock);
    fclose(fp);
	exit(0);
#endif
}

char calculateCRC(char *frame, const unsigned int totalBytes)
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
			if (byte || bit || !leadingZeros) {
				bit = crc.c3 ^ bit;
				crc.c3 = bit ^ crc.c2;
				crc.c2 = bit ^ crc.c1;
				crc.c1 = crc.c0;
				crc.c0 = bit;
				leadingZeros = 0;
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

void encapsulate(char* frame, const unsigned int count, const unsigned int bytes, const bool shouldCorrupt) {
	char crc;
	packetFooter footer;
    unsigned int footerIndex;
	static const char* header = "\x7E";
    unsigned int corruptBit;

    footerIndex = bytes - (unsigned int) FOOTER_LEN;

	memcpy(frame, header, (const char) HEADER_LEN);

	memset(&footer, 0, sizeof(packetFooter));
    if (count >= MAX_PACKET_COUNT) {
        printf("Warning: packet count > %u\n", (unsigned int) MAX_PACKET_COUNT);
        exit(1);
    }
	footer.packetCounter = count;
	memcpy(&frame[footerIndex], &footer, sizeof(packetFooter));

	crc = calculateCRC(frame, bytes - 1); /* exclude crc byte */
	footer.crc = crc & 0xF;
	memcpy(&frame[bytes - 2], &footer, sizeof(packetFooter));

    if (shouldCorrupt) {
        printf("Corrupting frame\n");
        corruptBit = (rand() % (bytes * 8));
        frame[corruptBit/8] ^= (0x80 >> (corruptBit % 8));
    }
}
