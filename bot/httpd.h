#pragma once

int httpd_getpid(void);
void httpd_stop(void);
void httpd_serve(int, char *);
void httpd_conn(int);
void httpd_start(int);
