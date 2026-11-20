#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e9+t.tv_nsec;}
int main(int argc,char**argv){ unsigned long h = argc>1 ? strtoul(argv[1],0,16) : 0; double tm=0,tu=0; int n=200000;
  for(int i=0;i<n;i++){ double a=now(); void *p=mmap((void*)h,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0); double b=now(); munmap(p,65536); double c=now(); tm+=b-a; tu+=c-b; }
  printf("hint %#lx: mmap %.0f ns, munmap %.0f ns\n", h, tm/n, tu/n); }
