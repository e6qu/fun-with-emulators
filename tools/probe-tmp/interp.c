#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
static double us(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e6+t.tv_nsec/1e3;}
static void logf_(const char*what,const char*p,double d){char b[1400];int n=snprintf(b,sizeof b,"[io] %6.0f us %s %s\n",d,what,p);write(2,b,n);}
int my_open(const char*p,int f,...){va_list a;va_start(a,f);int m=va_arg(a,int);va_end(a);double t=us();int r=open(p,f,m);double d=us()-t;if(f&O_CREAT||d>100)logf_(f&O_CREAT?"open+creat":"open",p,d);return r;}
int my_openat(int dfd,const char*p,int f,...){va_list a;va_start(a,f);int m=va_arg(a,int);va_end(a);double t=us();int r=openat(dfd,p,f,m);double d=us()-t;if(f&O_CREAT||d>100)logf_(f&O_CREAT?"openat+creat":"openat",p,d);return r;}
int my_rename(const char*a,const char*b){double t=us();int r=rename(a,b);logf_("rename",b,us()-t);return r;}
int my_unlink(const char*a){double t=us();int r=unlink(a);logf_("unlink",a,us()-t);return r;}
int my_mkdir(const char*a,mode_t m){double t=us();int r=mkdir(a,m);logf_("mkdir",a,us()-t);return r;}
__attribute__((used,section("__DATA,__interpose"))) static struct{const void*n;const void*o;} I[]={
{my_open,open},{my_openat,openat},{my_rename,rename},{my_unlink,unlink},{my_mkdir,mkdir}};
