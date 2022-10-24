#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 4711

char buff[10000];

int main(int argc, char *argv[])
{
	int fd;
	int i,n;
	struct sockaddr_in ib2roce_addr;
       
	memset(&ib2roce_addr, 0, sizeof(ib2roce_addr));

	ib2roce_addr.sin_family = AF_INET;
	ib2roce_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	ib2roce_addr.sin_port = htons(DEFAULT_PORT);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Cannot create socket");
		exit(1);
	}

	if (connect(fd, (struct sockaddr *)&ib2roce_addr, sizeof(ib2roce_addr)) < 0) {
		perror("Unable to connect");
		exit(1);
	}

	if (argc > 1) {
		n = strlen(argv[1]);
		strcpy(buff, argv[1]);
	} else {
		strcpy(buff, "help");
		n = 4;
	}

	for(i = 2; i < argc; i++) {
		buff[n++] = ' ';
		strcpy(buff + n, argv[i]);
		n += strlen(argv[i]);
	}

	buff[n] = '\n';
	if (write(fd, buff, n + 1) < 0) {
		perror("Cannot write to socket");
		return 1;
	}

	while (read(fd, buff, sizeof(buff)) > 0) {
		puts(buff);
	}

	close(fd);
	return 0;
}

