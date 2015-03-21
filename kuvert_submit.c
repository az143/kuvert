/*
 * 
 * this file is part of kuvert, a wrapper around your mta that
 * does pgp/gpg signing/signing+encrypting transparently, based
 * on the content of your public keyring(s) and your preferences.
 *
 * copyright (c) 1999-2008 Alexander Zangerl <az+kuvert@snafu.priv.at>
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
#include <stdlib.h>

#define CONFFILE "/.kuvert"
#define DEFAULT_QUEUEDIR "/.kuvert_queue"
#define BUFLEN 65536
#define FALLBACKMTA "/usr/sbin/sendmail"

#define BAILOUT(a,...) {fprintf(stderr,"%s: ",argv[0]); fprintf(stderr, a "\n",##__VA_ARGS__);syslog(LOG_ERR,a,##__VA_ARGS__); exit(1);}

int main(int argc,char **argv)
{
   struct passwd *pwentry;
   /* fixme sizes */
   char filen[256],buffer[BUFLEN],dirn[256];
   int res,c,spaceleft;
   char *p,*dirnp;
   FILE *out;
   FILE *cf;
   struct stat statbuf;
   int direct=1,norecips=0,testmode=0,i;

   /* determine whether to queue stuff or to call sendmail
      directly: if there is no proper config file for kuvert in $HOME
      or if given -bv go direct, otherwise we enqueue.  */
   openlog(argv[0],LOG_NDELAY|LOG_PID,LOG_MAIL);

   for(i=1;i<argc;++i)
   {
      if (!strncmp(argv[i],"-bv",3))
      {
	 testmode=1;
	 syslog(LOG_INFO,"-bv argument present, running sendmail.");
	 break;
      }
   }
   
   if (!testmode)
   {
      /* look for config file in $HOME */
      pwentry=getpwuid(getuid());
      if (!pwentry)
	 BAILOUT("getpwuid failed: %s",strerror(errno));
      
      /* open and scan the conffile for an queue-file definition 
	 if there is no conffile, kuvert wont work ever  */
      if (snprintf(filen,sizeof(filen),"%s%s",pwentry->pw_dir,CONFFILE)==-1)
	 BAILOUT("overlong filename, suspicious",NULL);
      if (!(cf=fopen(filen,"r")))	
      {
	 /* no config file -> exec sendmail */
	 syslog(LOG_INFO,"user has no "CONFFILE" config file, running sendmail");
      }
      else
      {
	 direct=0;
	 /* scan the lines for ^QUEUEDIR\s+ */
	 dirnp=NULL;
	 while(!feof(cf))
	 {
	    p=fgets(buffer,sizeof(buffer)-1,cf);
	    /* empty file? ok, we'll ignore it */
	    if (!p)
	       break;
	    
	    if (!strncasecmp(buffer,"QUEUEDIR",sizeof("QUEUEDIR")-1))
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
   }

   /* direct to sendmail requested? */
   if (direct)
   {
      /* mangle argv[0], so that it gets recognizeable by sendmail */
      argv[0]=FALLBACKMTA;
      *buffer=0;

      /* bah, c stringhandling is ugly... i just want all args 
	 in one string for a nice syslog line... */
      for(c=0,spaceleft=sizeof(buffer);
	  c<argc;
	  spaceleft-=strlen(argv[c++]))
      {
	 if (spaceleft <= 0) 
	    BAILOUT("overlong command line, suspicious.",NULL);
	 strncat(buffer,argv[c],spaceleft);
	 --spaceleft && c<argc-1 && strcat(buffer," ");
      }
    
      syslog(LOG_INFO,"executing MTA '%s' directly",buffer);
      execv(FALLBACKMTA,argv);
      /* must not reach here */
      BAILOUT("execv "FALLBACKMTA" failed: %s",strerror(errno));
   }

   /* otherwise queue the stuff for kuvert,
      first check queuedir and create if missing */
   if (!dirnp)
   {
      if(snprintf(dirn,sizeof(dirn),"%s%s",pwentry->pw_dir,DEFAULT_QUEUEDIR)
	 ==-1)
	 BAILOUT("overlong dirname, suspicous.",NULL);
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

   /* scan the arguments for the LSB-mandated options:
      we ignore any options but -f, -t.
   /* no getopt error messages, please! */
   opterr=0;
   while ((c=getopt(argc,argv,"f:t"))!=-1)
   {
      if (c=='?')
	 continue;		/* we simply ignore uninteresting options */
      else if (c=='f')
      {
	 /* pass the intended envelope sender */
	 fprintf(out,"X-Kuvert-From: %s\n",optarg);
      }
      else if (c=='t')
      {
	 /* no recipients given, so we don't need to pass any recips */
	 norecips=1;
      }
   }

   if (!norecips && optind<argc)
   {
      fprintf(out,"X-Kuvert-To: ");
      for(c=optind;c<argc;++c)
      {
	 fprintf(out,"%s%s",argv[c],(c<argc-1?", ":"\n"));
      }
   }
   fflush(out);

   /* now finally put the data in the queuefile */
   do 
   {
      res=fread(buffer,1,BUFLEN,stdin);
      if (!res && ferror(stdin))
	 BAILOUT("fread failure: %s",strerror(errno));
      if (fwrite(buffer,1,res,out)!=res && ferror(out))
	 BAILOUT("fwrite failure: %s",strerror(errno));
   }
   while (res==BUFLEN);
  
   if (fflush(out)==EOF)
      BAILOUT("fflush failed: %s",strerror(errno));
   if (flock(fileno(out),LOCK_UN))
   {
      BAILOUT("flock (unlock) failed: %s",strerror(errno));
   }
   if (fclose(out)==EOF)
      BAILOUT("fclose failed: %s",strerror(errno));
   return 0;
}
