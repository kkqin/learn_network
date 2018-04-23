#include 	<sys/socket.h>
#include 	<arpa/inet.h>
#include 	<strings.h>
#include 	<unistd.h>
#include	<errno.h>
#include 	<string.h>
#include 	<stdio.h>

#define MAXLINE 1000 

ssize_t						/* Write "n" bytes to a descriptor. */
Writen(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}

void 
str_echo(int sockfd);


int 
main(int argc, char **argv)
{
	int listenfd, connfd;
	pid_t childpid;
	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	inet_aton("127.0.0.1", &servaddr.sin_addr);
//	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(6667);

	// 强制类型转换
	if(bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		return -1;
	}

	// number of pending connections to queue	
	if(listen(listenfd, 5) < 0) {
		return -1;
	}

	for(;;) {
		clilen = sizeof(cliaddr);
		connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &clilen);
		if(connfd < 0) 
			continue;

		childpid = fork();
		// if process is child 
		if(childpid == 0)
		{
			close(listenfd);
			str_echo(connfd);
			return -1;
		}
		close(connfd);
	}

}

void 
str_echo(int sockfd)
{
	ssize_t n;
	char buf[MAXLINE];

again:
	while( (n = read(sockfd, buf, MAXLINE)) > 0)
		if(Writen(sockfd, buf, n) < 0) {
			return;
		}

	if( n < 0)
		goto again;
	else if (n < 0)
		printf("str_echo: read error");
}
