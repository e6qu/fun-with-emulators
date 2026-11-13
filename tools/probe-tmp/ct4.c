#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
static double us(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e6+t.tv_nsec/1e3;}
int main(int c,char**v){char p[1100];char buf[2000]={1};double a=0,b=0,d=0,e=0;int n=100;
for(int i=0;i<n;i++){snprintf(p,sizeof p,"%s/tr%d-%d",v[1],getpid(),i);
double t=us();int fd=open(p,O_CREAT|O_WRONLY,0600);a+=us()-t;
t=us();pwrite(fd,buf,1500,0);b+=us()-t;
t=us();ftruncate(fd,1500);d+=us()-t;
t=us();pwrite(fd,buf,1400,0);ftruncate(fd,1400);e+=us()-t;
close(fd);unlink(p);}
printf("create %.0f pwrite %.0f ftruncate-same %.0f rewrite-shorter %.0f us\n",a/n,b/n,d/n,e/n);}
