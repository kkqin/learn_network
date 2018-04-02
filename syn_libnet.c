#include <libnet.h>
#include <errno.h>

int 
main(int argc, char **argv)
{
	if(argc != 3)
	{
		printf("usage:%s dst_ip dst_port\n", argv[0]);
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
//	while(1)
//	{

	t = libnet_build_tcp(
			src_prt	= libnet_get_prand(LIBNET_PRu16), 	/* source port */ 
			dst_prt,					/* destination port */
			libnet_get_prand(LIBNET_PRu32),			/* sequence number */
			0,						/* acknowledgement num */
			TH_SYN,						/* control flags */
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
			src_ip = libnet_get_prand(LIBNET_PRu32),	/* source IP */
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


	int res = libnet_write(l);
	if(res == -1)
	{
		fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		exit(EXIT_FAILURE);
	}

        printf("%15s:%5d ------> %15s:%5d\n", 
	libnet_addr2name4(src_ip, 1),
     	ntohs(src_prt),
     	libnet_addr2name4(dst_ip, 1),
     	dst_prt);

	sleep(2);
//	}
}
