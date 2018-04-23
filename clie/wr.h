#include 	<arpa/inet.h>
#include 	<strings.h>
#include 	<netinet/in.h>
#include 	<sys/socket.h>
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
