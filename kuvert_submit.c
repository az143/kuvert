/*
 * $Id: uard_mta_wrapper.c,v 2.4 2001/10/07 12:32:28 az Exp az $
 * 
 * this file is part of kuvert, a wrapper around your mta that
 * does pgp/gpg signing/signing+encrypting transparently, based
 * on the content of your public keyring(s) and your preferences.
 *
 * copyright (c) 1999-2001 Alexander Zangerl <az+kuvert@snafu.priv.at>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>

#define CONFFILE "/.kuvert"
#define DEFAULT_QUEUEDIR "/.kuvert_queue"
#define BUFLEN 10240
#define FALLBACKMTA "/usr/lib/sendmail"

#define BAILOUT(a,...) {fprintf(stderr, "argv[0] " ##a "\n",__VA_ARGS__);syslog(LOG_ERR,a,__VA_ARGS__); exit(1);}

int main(int argc,char **argv)
{
  struct passwd *pwentry;
  char filen[256],buffer[BUFLEN],dirn[256];
  int res,c,fallback,spaceleft;
  char *p,*dirnp;
  FILE *out;
  FILE *cf;
  struct stat statbuf;

  /* determine whether to queue stuff or to call sendmail
     directly: if there is a proper config file of kuvert in $HOME,
     and if the flags/args given are "consistent" with a call
     to sendmail for mail submission, do queue stuff;
     otherwise exec sendmail. */

  openlog(argv[0],LOG_NDELAY|LOG_PID,LOG_MAIL);

  /* scan the arguments for options:
     we understand about: no options, non-option-args, --,
     -bm, -f, -i, -t, -v, -m. everything else means some special
     instruction to sendmail, so we exec sendmail. */

  /* no getopt error messages, please! */
  opterr=0;

  while ((c=getopt(argc,argv,"f:itvb:m"))!=-1 && !fallback)
  {
    switch (c)
    {
    case 'v':
    case 'f':
    case 'i':
    case 't':
    case 'm':			/* deprecated option 'metoo',
				   but nmh uses this... */
      break;			/* these options are ok and supported */
    case 'b':
      /* just -bm is ok, other -b* are bad */
      if (!optarg || *optarg != 'm') 
      {
	fallback=1;
	syslog(LOG_INFO,"option '-%c %s' mandates fallback",
	       c,optarg);
      }
      break;
    default:
      /* well, there's an option we do not know, lets bail out */
      fallback=1;
      syslog(LOG_INFO,"option '-%c' mandates fallback",
	     c=='?'?optopt:c);
      break;
    }
  }
  
  if (!fallback)
  {
    /* options seem ok, look for config file in $HOME */
    pwentry=getpwuid(getuid());
    if (!pwentry)
      BAILOUT("getpwuid failed: %s",strerror(errno));
    
    /* open and scan the conffile for an queue-file definition 
       if there is no conffile, kuvert wont work ever  */
    snprintf(filen,sizeof(filen),"%s%s",pwentry->pw_dir,CONFFILE);
    if (!(cf=fopen(filen,"r")))
    {
      /* no config file -> exec sendmail */
      syslog(LOG_INFO,"user has no .kuvert config file, fallback");
      fallback=1;
    }
    
    /* scan the lines for ^QUEUEDIR\s+ */
    dirnp=NULL;
    while(!feof(cf))
    {
      p=fgets(buffer,sizeof(buffer)-1,cf);
      /* empty file? ok, we'll ignore it */
      if (!p)
	break;
      
      if (!strncmp(buffer,"QUEUEDIR",sizeof("QUEUEDIR")-1))
      {
	p=buffer+sizeof("QUEUEDIR")-1;
	for(;*p && isspace(*p);++p)
	  ;
	if (*p)
	{
	  dirnp=p;
	  /* strip the newline from the string */
	  for(;*p && *p != '\n';++p)
	    ;
	  if (*p == '\n')
	    *p=0;
	  /* strip eventual trailing whitespace */
	  for(--p;p>dirnp && isspace(*p);--p)
	    *p=0;
	}
	/* empty dir? ignore it */
	if (strlen(dirnp)<2)
	  dirnp=NULL;
	break;
      }
    }
    fclose(cf);
  }

  /* fallback to sendmail requested? */
  if (fallback)
  {
    /* mangle argv[0], so that it gets recognizeable by sendmail */
    argv[0]=FALLBACKMTA;
    *buffer=0;

    /* bah, c stringhandling is ugly... i just want all args 
       in one string for a nice syslog line... */
    for(c=0,spaceleft=sizeof(buffer);
	c<argc && spaceleft > 0;
	spaceleft-=strlen(argv[c++]))
    {
      strncat(buffer,argv[c],spaceleft);
      --spaceleft && c<argc-1 && strcat(buffer," ");
    }
    
    syslog(LOG_INFO,"will exec MTA as '%s'",buffer);
    execv(FALLBACKMTA,argv);
    /* must not reach here */
    BAILOUT("execv FALLBACKMTA failed: %s",strerror(errno));
  }

  /* otherwise queue the stuff for kuvert,
     first check queuedir and create if missing */
  if (!dirnp)
  {
    snprintf(dirn,sizeof(dirn),"%s%s",pwentry->pw_dir,DEFAULT_QUEUEDIR);
    dirnp=dirn;
  }

  res=stat(dirnp,&statbuf);
  if (res)
  {
    if (errno == ENOENT)
    {
      /* seems to be missing -> try to create it */
      if (mkdir(dirnp,0700))
	BAILOUT("mkdir %s failed: %s\n",dirnp,strerror(errno));
    }
    else 
      BAILOUT("stat %s failed: %s\n",dirnp,strerror(errno));
  }
  else if (!S_ISDIR(statbuf.st_mode))
  {  
    BAILOUT("%s is not a directory",dirnp);
  }
  else if (statbuf.st_uid != getuid())
  {
    BAILOUT("%s is not owned by you - refusing to run",dirnp);
  }
  else if ((statbuf.st_mode & 0777) != 0700)
  {
    BAILOUT("%s does not have mode 0700 - refusing to run",dirnp);
  }
  umask(066);			/* absolutely no access for group/others... */
    
  /* dir does exist now */
  snprintf(filen,sizeof(filen),"%s/%d",dirnp,getpid());
  
  /* file create and lock */
  if (!(out=fopen(filen,"a")))
  {
    BAILOUT("fopen %s failed: %s\n",filen,strerror(errno));
  }
  if (flock(fileno(out),LOCK_EX))
  {
    BAILOUT("flock failed: %s\n",strerror(errno));
  }

  /* and put the data there */
  do 
  {
    res=fread(buffer,1,BUFLEN,stdin);
    fwrite(buffer,1,res,out);
  }
  while (res==BUFLEN);
  
  fflush(out);
  if (flock(fileno(out),LOCK_UN))
  {
    BAILOUT("flock (unlock) failed: %s\n",strerror(errno));
  }
  fclose(out);
  return 0;
}

  


  
  
  
      
      
  
