#include "pbhead.h"
#include "p1.pb-c.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <malloc.h>

void protocol_send(int sockfd);

int 
main()
{
	struct sockaddr_in servaddr;
	int sockfd;
	char *ser_ip = "192.168.13.32";

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(20011);
	inet_aton(ser_ip, &servaddr.sin_addr);
	
	if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	{
		fprintf(stderr, "connect (%s) error.", ser_ip);
		return -1;
	}

	protocol_send(sockfd);
}


void  
protocol_send(int sockfd)
{
	char *head_ptr;

	struct PBReqHeader_ *p_header = (struct PBReqHeader_ *)malloc(sizeof(struct PBReqHeader_));
	p_header->m_header.m_cmdNum = htons(10000);
	p_header->m_header.m_cmdSeq = 0;
	p_header->m_header.m_reserve = 0;
	p_header->m_srcId = 0;
	p_header->m_session = 0;

	Trans__One *s_data = (Trans__One *)malloc(sizeof(Trans__One));
	s_data->a = 123;
	s_data->b = 345;
	s_data->c = "hi stupid";
	
	size_t pack_size = trans__one__get_packed_size( s_data );
	void * buf;
	buf = malloc(pack_size);
	trans__one__pack( s_data, buf );

	head_ptr = (char *)malloc(sizeof(struct PBReqHeader_) + pack_size);
	memcpy(head_ptr, p_header, sizeof(struct PBReqHeader_));
	memcpy(head_ptr + sizeof(struct PBReqHeader_), buf, pack_size);

	send(sockfd, head_ptr, sizeof(struct PBReqHeader_)+pack_size, 0);
}

