#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define TCPHEADERSIZE 6*4
FILE* ip = fopen("input_mul", "r");
char mal_url[1001];

unsigned char* MY_IP = (unsigned char*)malloc(sizeof(char) * 4);
unsigned char* gw_mac = (unsigned char*)malloc(sizeof(char) * 6);
unsigned char* gw_IP = (unsigned char*)malloc(sizeof(char) * 4);
unsigned char* MY_mac = (unsigned char*)malloc(sizeof(char) * 6);
unsigned char* h_dest = (unsigned char*)malloc(sizeof(char) * 6);
unsigned char* h_source = (unsigned char*)malloc(sizeof(char) * 6);
unsigned char* ar_sha = (unsigned char*)malloc(sizeof(char) * 6);       //sender mac
unsigned char* ar_sip = (unsigned char*)malloc(sizeof(char) * 4);       //sender IP
unsigned char* ar_tha = (unsigned char*)malloc(sizeof(char) * 6);       //Target mac (my)
unsigned char* ar_tip = (unsigned char*)malloc(sizeof(char) * 4);

int flag = 0;
struct ip *iph;
struct tcphdr *tcph;
struct eth_hdr {
	unsigned char h_dest[6];        //destination ether addr
	unsigned char h_source[6];      //source ether addr
	unsigned short h_proto;         //packet type id filed
} __attribute__((packed));

struct arp_hdr {
	unsigned short ar_hrd;          //hardware type : ethernet
	unsigned short ar_pro;          //protocol      : ip
	unsigned char  ar_hln;          //hardware size
	unsigned char  ar_pln;          //protocal size
	unsigned short ar_op;           //opcode request or reply
	unsigned char  ar_sha[6];       //sender mac
	unsigned char  ar_sip[4];       //sender IP
	unsigned char  ar_tha[6];       //Target mac (my)
	unsigned char  ar_tip[4];       //Target IP  (my)
} __attribute__((packed));

static unsigned char g_buf[sizeof(struct eth_hdr) + sizeof(struct arp_hdr)];
static unsigned char sendig_buf[66] = { 0, };
static int g_sock;


void string_copy(unsigned char* a, unsigned char* b, int c)
{
	for (int i = 0; i<c; i++)
	{
		*(a + i) = *(b + i);
	}
}

void string_change(unsigned char* a, unsigned char* b, int c)
{
	char tmp[100];
	for (int i = 0; i<c; i++)
	{
		*(tmp + i) = *(a + i);
	}
	for (int i = 0; i<c; i++)
	{
		*(a + i) = *(b + i);
	}
	for (int i = 0; i<c; i++)
	{
		*(b + i) = *(tmp + i);
	}
}

int string_same(unsigned char* a, unsigned char* b, int c)
{
	int check_same = 1;
	for (int i = 0; i<c; i++)
	{
		if (*(a + i) != *(b + i))
		{
			check_same = 0;
			break;
		}
	}
	return check_same;
}


int gw_IP_Parsing() {
	char pipe_buf[100];
	system("netstat -n -r | grep UG | grep ens33 | awk '{print $2}'>1.txt");
	FILE *ip = fopen("1.txt", "r");
	fscanf(ip, "%s", pipe_buf);
	inet_aton((const char*)pipe_buf, (in_addr*)gw_IP);
	return 0;
}

int MY_IP_Parsing() {
	char pipe_buf[100];
	system("ifconfig | grep Bcast | awk '{printf $2}' | awk -F\":\" '{printf $2}'>2.txt");
	FILE *ip = fopen("2.txt", "r");
	fscanf(ip, "%s", pipe_buf);
	inet_aton((const char*)pipe_buf, (in_addr*)MY_IP);
	return 0;
}

int MY_MAC_Parsing() {
	system("ifconfig | grep HWaddr | awk '{printf $5}' | tr ':' ' '>3.txt");
	FILE *ip = fopen("3.txt", "r");
	for (int i = 0; i<6; i++)
	{
		fscanf(ip, "%x", (unsigned int*)&MY_mac[i]);
	}
	return 0;
}

void send_arp_packet(pcap_t* pcd, int a)
{
	struct eth_hdr ether;
	struct arp_hdr arp;

	for (int i = 0; i<6; i++)
	{
		ether.h_dest[i] = *(h_dest + i);
		ether.h_source[i] = *(h_source + i);
		arp.ar_sha[i] = *(ar_sha + i);
		arp.ar_tha[i] = *(ar_tha + i);
	}
	ether.h_proto = htons(0x0806);  //htons -> host endian change

	arp.ar_hrd = htons(0x0001);
	arp.ar_pro = htons(0x0800);
	arp.ar_hln = 0x06;
	arp.ar_pln = 0x04;
	arp.ar_op = htons(0x0000 + a);
	string_copy(arp.ar_sip, ar_sip, 4);
	string_copy(arp.ar_tip, ar_tip, 4);

	memcpy(g_buf, &ether, sizeof(struct eth_hdr));
	memcpy(g_buf + 14, &arp, sizeof(struct arp_hdr));

	pcap_inject(pcd, (const void*)g_buf, sizeof(g_buf));
}


void receive_mac(u_char *useless, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	if (*(packet + 12) == 0x08 && *(packet + 13) == 0x06 && string_same((unsigned char*)(packet + 38), (unsigned char*)ar_sip, 4) && *(packet + 21) == 2 && string_same((unsigned char*)(packet + 28), (unsigned char*)gw_IP, 4))
	{
		flag = 1;
		for (int i = 0; i <= 5; i++)
		{
			gw_mac[i] = *(packet + 22 + i);
		}
		//printf("%2x:%2x:%2x:%2x:%2x:%2x\n",*(sender_mac),*(packet+23),*(packet+24),*(packet+25),*(packet+26),*(packet+27));
	}
}


void having_gw_mac(unsigned char* gw_ip)
{
	for (int i = 0; i<6; i++)
	{
		h_dest[i] = 0xff;
		ar_tha[i] = 0x00;
	}
	string_copy(h_source, MY_mac, 6);
	string_copy(ar_sha, MY_mac, 6);
	string_copy((unsigned char*)ar_sip, (unsigned char*)MY_IP, 4);
	string_copy((unsigned char*)ar_tip, (unsigned char*)gw_IP, 4);
	char *dev;
	char *net;
	char *mask;
	const u_char *packet;

	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	struct pcap_pkthdr hdr;
	struct in_addr net_addr, mask_addr;
	struct bpf_program fp;
	pcap_t *pcd;
	dev = pcap_lookupdev(errbuf);
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);

	send_arp_packet(pcd, 1);

	while (flag == 0)
	{
		pcap_loop(pcd, 1, receive_mac, NULL);
	}
	pcap_close(pcd);
}


int packet_filter(char* packet, char* str)
{
	for (int i = 0; i <= 1500; )
	{
		if (*(packet + i) == NULL)
		{
			i++;
			continue;
		}
		if (strstr((const char*)(packet + i), str) != NULL)
			return 1;
		else
			i += strlen(packet + i);
	}
	return 0;
}
int sequence = 0;

void ip_checksum(unsigned char* packet)
{
	int checksum = 0;
	for (int i = 14; i<34; i = i + 2)
	{
		if (i != 24)
		{
			checksum += ((*(sendig_buf + i)) << 8) + (*(sendig_buf + i + 1));
			//printf("\nchecksum = %x\n",((*(sendig_buf+i))<<8)+(*(sendig_buf+i+1)));
		}
	}
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum = checksum ^ 0xffff;
	*(packet) = checksum >> 8;
	*(packet + 1) = checksum & 0xff;
	return;
}

void tcp_checksum(unsigned char* packet)
{
	int checksum = 0;
	for (int i = 26; i<66; i = i + 2)
	{
		if (i != 50)
		{
			checksum += ((*(sendig_buf + i)) << 8) + (*(sendig_buf + i + 1));
			//printf("\nchecksum = %x\n",checksum);
		}
	}
	checksum += 0x26;
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum = checksum ^ 0xffff;
	//printf("\nchecksum = %x\n",checksum);
	*(packet) = checksum >> 8;
	*(packet + 1) = checksum & 0xff;
	return;
}
int identifier = 0;
void block_packet(u_char *useless, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{

	if (string_same((unsigned char*)packet, MY_mac, 6) && packet_filter((char*)packet, "HTTP") != NULL&& *(packet + 23) == 6)
	{
		if ((*(packet + 47) & 1) == 1) printf("\nFIN--------\n");
		//if(((*(packet+47)>>4)&1)==1) printf("\nACK------------\n");
		while (!feof(ip))
		{
			fgets(mal_url, 1000, ip);
			if (packet_filter((char*)packet, mal_url) != NULL)
			{
				rewind(ip);
				flag = 1;
				string_copy(sendig_buf, (unsigned char*)packet, 66);

				for (int i = 0; i<54; i++)
				{
					// printf("%2x ",*(sendig_buf+i));
					if (i % 16 == 15)
					{
						// printf("\n");
					}
				}
				string_copy(sendig_buf, gw_mac, 6);
				string_copy(sendig_buf + 6, MY_mac, 6);
				*(sendig_buf + 16) = 0x0;
				*(sendig_buf + 17) = 0x34;
				*(sendig_buf + 18) = identifier >> 8;
				*(sendig_buf + 19) = identifier & 0xff;
				identifier++;
				*(sendig_buf + 22) = 0x40;
				ip_checksum(sendig_buf + 24);
				string_change(sendig_buf + 26, sendig_buf + 30, 4);
				string_change(sendig_buf + 34, sendig_buf + 36, 2);
				string_change(sendig_buf + 38, sendig_buf + 42, 4);
				*(sendig_buf + 46) = *(sendig_buf + 46) + 1;
				*(sendig_buf + 47) = 0x4;
				*(sendig_buf + 52) = 0x0;
				*(sendig_buf + 53) = 0x0;
				tcp_checksum(sendig_buf + 50);

				printf("you connect mal url\n");
				return;
			}
		}
	}

}

void packet_capture()
{
	char *dev;
	char *net;
	char *mask;

	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	struct pcap_pkthdr hdr;
	struct in_addr net_addr, mask_addr;

	struct bpf_program fp;

	pcap_t *pcd;
	dev = pcap_lookupdev(errbuf);
	printf("DEV : %s\n", dev);
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	printf("NET : %s\n", net);
	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	printf("MSK : %s\n", mask);
	printf("=======================\n");
	pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
	flag = 0;
	while (1)
	{
		pcap_loop(pcd, 1, block_packet, NULL);
		if (flag == 1)
		{
			pcap_inject(pcd, (const void*)sendig_buf, sizeof(sendig_buf));

			//printf("changed packet\n");
			for (int i = 0; i<54; i++)
			{
				//printf("%2x ",*(sendig_buf+i));
				if (i % 16 == 15)
				{
					//printf("\n");
				}
			}
			flag = 0;
		}
	}
	pcap_close(pcd);
}

int main()
{
	MY_IP_Parsing();
	MY_MAC_Parsing();
	gw_IP_Parsing();
	for (int i = 0; i <= 3; i++)
	{
		printf("%d ", *(gw_IP + i));
	}
	having_gw_mac(gw_IP);
	packet_capture();
	return 0;
}