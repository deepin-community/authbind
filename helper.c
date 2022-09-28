/*
 *  helper.c - setuid helper program for authbind
 *
 *  authbind is Copyright (C) 1998 Ian Jackson
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
 * 
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef CONFIGDIR
# define CONFIGDIR "/etc/authbind"
#endif

static void exiterrno(int e) {
  exit(e>0 && e<128 ? e : ENOSYS);
}

static void perrorfail(const char *m) {
  int e;
  e= errno;
  fprintf(stderr,"libauthbind's helper: %s: %s\n",m,strerror(e));
  exiterrno(e);
}

static void badusage(void) {
  fprintf(stderr,"libauthbind's helper: bad usage\n");
  exit(ENOSYS);
}

static struct sockaddr_in saddr4;
static struct sockaddr_in6 saddr6;

static struct sockaddr *saddr_any;
static const void *addr_any;
static size_t saddrlen_any, addrlen_any;

static void authorised(void) {
  if (bind(0,saddr_any,saddrlen_any)) exiterrno(errno);
  else _exit(0);
}

static void checkexecflagfile(const char *file) {
  if (!access(file,X_OK)) authorised();
  if (errno != ENOENT) exiterrno(errno);
}

static void hex2bytes(const char *string, unsigned char *out, int len) {
  int i;
  for (i=0; i<len; i++) {
    char hex[3], *ep;
    hex[0]= *string++;  if (!hex[0]) badusage();
    hex[1]= *string++;  if (!hex[1]) badusage();
    hex[2]= 0;
    *out++ = strtoul(hex,&ep,16);
    if (ep != &hex[2]) badusage();
  }
}

int main(int argc, const char *const *argv) {
  uid_t uid;
  char fnbuf[300];
  char *ep;
  const char *np;
  const char *tophalfchar="";
  unsigned long port, addr4=0, haddr4=0;
  unsigned int hport;
  int af;
  FILE *file;

  if (argc == 3) {
    af= AF_INET;
    saddr_any= (void*)&saddr4;
    saddrlen_any= sizeof(saddr4);
    addr_any= &saddr4.sin_addr.s_addr;
    addrlen_any= sizeof(saddr4.sin_addr.s_addr);
    addr4= strtoul(argv[1],&ep,16);
    if (*ep || addr4&~0x0ffffffffUL) badusage();
    haddr4= ntohl(addr4);
  } else if (argc == 4 && !strcmp(argv[3],"6")) {
    af= AF_INET6;
    saddr_any= (void*)&saddr6;
    saddrlen_any= sizeof(saddr6);
    addr_any= &saddr6.sin6_addr.s6_addr;
    addrlen_any= sizeof(saddr6.sin6_addr.s6_addr);
    hex2bytes(argv[1], saddr6.sin6_addr.s6_addr,
	      sizeof(saddr6.sin6_addr.s6_addr));
  } else {
    badusage();
    abort();
  }

  port= strtoul(argv[2],&ep,16); if (*ep || port&~0x0ffffUL) badusage();
  hport= htons(port);
  if (hport >= IPPORT_RESERVED/2) tophalfchar= "!";

  if (chdir(CONFIGDIR)) perrorfail("chdir " CONFIGDIR);

  fnbuf[sizeof(fnbuf)-1]= 0;

  switch (af) {
  case AF_INET:
    saddr4.sin_family= af;
    saddr4.sin_port= port;
    saddr4.sin_addr.s_addr= addr4;
    break;
  case AF_INET6:
    saddr6.sin6_family= af;
    saddr6.sin6_port= port;
    break;
  default:
    abort();
  }

  snprintf(fnbuf,sizeof(fnbuf)-1,"byport/%s%u",tophalfchar,hport);
  if (!access(fnbuf,X_OK)) authorised();
  if (errno != ENOENT) exiterrno(errno);

  char npbuf[INET_ADDRSTRLEN + INET6_ADDRSTRLEN];
  np= inet_ntop(af,addr_any,npbuf,sizeof(npbuf));
  assert(np);

  if (af == AF_INET) {
    snprintf(fnbuf,sizeof(fnbuf)-1,"byaddr/%s%s:%u",tophalfchar,np,hport);
    checkexecflagfile(fnbuf);
  }

  snprintf(fnbuf,sizeof(fnbuf)-1,"byaddr/%s%s,%u",tophalfchar,np,hport);
  checkexecflagfile(fnbuf);

  if (af == AF_INET6) {
    char sbuf[addrlen_any*3+1], *sp = sbuf;
    const unsigned char *ip = addr_any;
    int i;
    for (i=0; i<8; i++) {
      unsigned val = 0;
      val |= *ip++;  val <<= 8;
      val |= *ip++;
      if (i) *sp++ = ':';
      sp += sprintf(sp,"%x",val);
    }
    snprintf(fnbuf,sizeof(fnbuf)-1,"byaddr/%s%s,%u",tophalfchar,sbuf,hport);
    checkexecflagfile(fnbuf);
  }

  uid= getuid(); if (uid==(uid_t)-1) perrorfail("getuid");
  snprintf(fnbuf,sizeof(fnbuf)-1,"byuid/%s%lu",tophalfchar,(unsigned long)uid);

  file= fopen(fnbuf,"r");
  if (!file) exiterrno(errno==ENOENT ? EPERM : errno);

  while (fgets(fnbuf,sizeof(fnbuf)-1,file)) {
    unsigned int a1,a2,a3,a4, alen,pmin,pmax;
    int nchar;

    if (af == AF_INET &&
	(nchar = -1,
	 sscanf(fnbuf," %u.%u.%u.%u/%u: %u,%u %n",
		&a1,&a2,&a3,&a4,&alen,&pmin,&pmax,&nchar),
	 nchar == strlen(fnbuf))) {

      if (alen>32 || pmin&~0x0ffff || pmax&~0x0ffff ||
	  a1&~0x0ff || a2&~0xff || a3&~0x0ff || a4&~0x0ff)
	continue;

      unsigned long thaddr, thmask;
      thaddr= (a1<<24)|(a2<<16)|(a3<<8)|(a4);
      thmask= alen ? 0x0ffffffffUL<<(32-alen) : 0;
      if ((haddr4&thmask) != thaddr) continue;

    } else {

      char *comma = strchr(fnbuf,',');
      if (!comma) continue;
      *comma++ = '\0';

      char *slash = strchr(fnbuf,'/');
      char *hyphen = strchr(fnbuf,'-');

      if (slash && hyphen)
	continue;

      if (slash) {
	int alen;
	*slash++ = '\0';
	nchar = -1;
	sscanf(slash," %u %n",&alen,&nchar);
	if (nchar != strlen(slash))
	  continue;
	unsigned char thaddr[addrlen_any];
	if (inet_pton(af,fnbuf,thaddr) != 1)
	  continue;
	int pfxlen_remain = alen;
	int i;
	for (i=0; i<addrlen_any; i++) {
	  int pfxlen_thisbyte = pfxlen_remain < 8 ? pfxlen_remain : 8;
	  pfxlen_remain -= pfxlen_thisbyte;
	  unsigned mask_thisbyte = 0xff ^ (0xff >> pfxlen_thisbyte);
	  unsigned thaddr_thisbyte = thaddr[i];
	  unsigned addr_thisbyte = ((unsigned char*)addr_any)[i];
	  if ((addr_thisbyte & mask_thisbyte) != thaddr_thisbyte)
	    goto badline;
	}
	if (pfxlen_remain) badline: continue;
	/* hooray */
      } else {
	const char *min, *max;
	if (hyphen) {
	  *hyphen++ = '\0';
	  min = fnbuf;
	  max = hyphen;
	} else {
	  min = fnbuf;
	  max = fnbuf;
	}
	unsigned char minaddr[addrlen_any];
	unsigned char maxaddr[addrlen_any];
	if (inet_pton(af,min,minaddr) != 1 ||
	    inet_pton(af,max,maxaddr) != 1)
	  continue;
	if (memcmp(addr_any,minaddr,addrlen_any) < 0 ||
	    memcmp(addr_any,maxaddr,addrlen_any) > 0)
	  continue;
      }

      if (nchar = -1,
	  sscanf(comma," %u-%u %n",
		 &pmin,&pmax,&nchar),
	  nchar == strlen(comma)) {
	/* good */
      } else if (nchar = -1,
		 sscanf(comma," %u %n",
			&pmin,&nchar),
		 nchar == strlen(comma)) {
	pmax = pmin;
      } else {
	continue;
      }

    }
    if (hport<pmin || hport>pmax) continue;

    authorised();
  }
  if (ferror(file)) perrorfail("read per-uid file");
  _exit(ENOENT);
}
