#include <libnet.h>
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>
#include <pthread.h> 

struct _DataInfo_
{
	libnet_t *l;
	unsigned short src_prt;
	unsigned short dst_prt;
	unsigned long src_ip; 
	unsigned long dst_ip;
};

void 
recv_packet(void* ptr);

void
my_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packer);

libnet_t* 
datagram(libnet_t * l, unsigned short src_prt, unsigned short dsc_prt, unsigned long src_ip, unsigned long dst_ip, unsigned short control);

char* 
itoa(int val, int base);

int 
main(int argc, char **argv)
{
	if(argc != 4)
	{
		printf("usage:%s dst_ip dst_port src_ip\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	const char *src_ip = libnet_get_prand(LIBNET_PRu32);
	libnet_t *l;
	libnet_ptag_t t;
	char errbuf[LIBNET_ERRBUF_SIZE];

	unsigned short src_prt;
	unsigned long dst_ip = inet_addr(argv[1]);//libnet_name2addr4(l, ARGV[1], LIBNET_RESOLVE);
	unsigned short dst_prt = atoi(argv[2]);
	l = libnet_init(LIBNET_RAW4,
			NULL,
			errbuf);
	if (l == NULL)
	{
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(EXIT_FAILURE);
	}

	libnet_seed_prand(l);

	datagram(l, src_prt = libnet_get_prand(LIBNET_PRu16), dst_prt, src_ip= inet_addr(argv[3]), dst_ip, TH_SYN);
	
	struct _DataInfo_ *para = (struct _DataInfo_*)malloc(sizeof(struct _DataInfo_));
	para->l = l;
	para->src_prt = src_prt;
	para->dst_prt = dst_prt;
	para->src_ip = src_ip;
	para->dst_ip = dst_ip;
	
	pthread_t recv;
	if(pthread_create(&recv, NULL, recv_packet, (void*)para) == -1)
	{
		fprintf(stderr, "pthread_create() error\n");
		exit(EXIT_FAILURE);
	}

	int res = libnet_write(l);
	if(res == -1)
	{
		fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		exit(EXIT_FAILURE);
	}

	pthread_join(recv, NULL);

        printf("%15s:%5d ------> %15s:%5d\n", 
	libnet_addr2name4(src_ip, 1),
     	ntohs(src_prt),
     	libnet_addr2name4(dst_ip, 1),
     	dst_prt);

	//sleep(2);
}

void 
recv_packet(void* ptr)
{
	struct _DataInfo_* st = (struct _DataInfo_*)ptr;
	
       	char * srcP = itoa(ntohs(st->src_prt), 10);
	char *dev = "eth0";
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char *filter_exp = "tcp";

	//printf("srcP: %s\n", srcP);
	//char *filter_exp = (char*)malloc(strlen(exp) + strlen(srcP)); /*"tcp port xxxx"*/

	//sprintf(filter_exp, "%s%s", exp, srcP);
	//printf("filter_exp: %s\nsizeof(filter_exp): %d\n", filter_exp, strlen(filter_exp));
	  

	bpf_u_int32 subnet_mask, ip;

	if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1)
       	{
		fprintf(stderr, "could not get information for device: %s\n", dev);
		ip = 0;
		subnet_mask = 0;
		exit(EXIT_FAILURE);
	}
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
	if(handle == NULL)
	{
		fprintf(stderr, "could not open %s - %s\n", dev, error_buffer);
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(handle, &filter, filter_exp, 0, ip) == -1)
	{
		fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(handle, &filter) == -1)
	{
		fprintf(stderr, "setting filter - %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, 1, my_handler, (u_char*)st);

}

void
my_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	printf("Packet capture length: %d\n", header->caplen);
	printf("Packet total length: %d\n", header->len);

	void** arg_arr = (void**)args;
	struct _DataInfo_ * para = (struct _DataInfo_ *)arg_arr;
	
	libnet_t *l = para->l;
	datagram(l, para->src_prt, para->dst_prt, para->src_ip, para->dst_ip, TH_ACK);

	int res = libnet_write(l);
	if(res == -1)
	{
		fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		exit(EXIT_FAILURE);
	}
	
	printf("ack send\n");
}

libnet_t* 
datagram(libnet_t * l, unsigned short src_prt, unsigned short dst_prt, unsigned long src_ip, unsigned long dst_ip, unsigned short control)
{
	libnet_ptag_t t;
	
	t = libnet_build_tcp(
			src_prt,				 	/* source port */ 
			dst_prt,					/* destination port */
			libnet_get_prand(LIBNET_PRu32),			/* sequence number */
			0,						/* acknowledgement num */
			control,					/* control flags */
			libnet_get_prand(LIBNET_PRu16),			/* window size */
			0,						/* checksum */
			0,						/* urgent pointer */
			LIBNET_TCP_H,					/* TCP packet size */
			NULL,						/* payload */
			0,						/* payload size */
			l,						/* libnet handle */
			0);						/* libnet id */

	if(t == -1)
	{
		fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
		exit(EXIT_FAILURE);
	}

	t = libnet_build_ipv4(
			LIBNET_TCP_H + LIBNET_IPV4_H, 			/* length */
			0,						/* TOS */
			libnet_get_prand(LIBNET_PRu16),			/* IP ID */
			0,						/* IP Frag */
			libnet_get_prand(LIBNET_PR8),			/* TTL */
			IPPROTO_TCP,					/* protocol */
			0,						/* checksum */
			src_ip,						/* source IP */
			dst_ip,						/* destination IP */
			NULL,						/* payload */
			0,						/* payload size */
			l,						/* libnet handle */
			0);						/* libnet id */

	if(t == -1)
	{
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		exit(EXIT_FAILURE);
	}

	return l;	
}

char* 
itoa(int val, int base){

	static char buf[32] = {0};

	int i = 30;

	for(; val && i ; --i, val /= base)

		buf[i] = "0123456789abcdef"[val % base];

	return &buf[i+1];

}
	
