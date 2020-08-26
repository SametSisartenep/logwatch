#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/statvfs.h>
#include "libutf/utf.h"
#include "args.h"

#define nil NULL

typedef unsigned long long uvlong;

enum
{
	Wlogfile,
	Wlogdir,
	NWATCH,

	KB = 1024
};

char *argv0;
int debug;

void
sysfatal(char *s)
{
	perror(s);
	exit(1);
}

void
dprint(char *fmt, ...)
{
	va_list ap;

	if(!debug)
		return;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void*
emalloc(ulong n)
{
	void *p;

	p = malloc(n);
	if(p == nil)
		sysfatal("malloc");
	return p;
}

char*
estrdup(char *s)
{
	char *d;

	d = strdup(s);
	if(d == nil)
		sysfatal("strdup");
	return d;
}

void
lockfile(int fd)
{
	if(flock(fd, LOCK_EX) < 0)
		sysfatal("flock locking");
}

void
unlockfile(int fd)
{
	if(flock(fd, LOCK_UN) < 0)
		sysfatal("flock unlocking");
}

int
checkusage(char *f, struct statvfs *vfs, int thres, ulong *flen)
{
	struct stat st;
	uvlong total, free, barrier;

	total = vfs->f_bsize*vfs->f_blocks;
	free = vfs->f_bsize*vfs->f_bavail;
	barrier = thres*total/100;
	if(stat(f, &st) < 0)
		sysfatal("stat");
	*flen = st.st_size;
	dprint("total %llu\nfree %llu\nbarrier %llu (%d%%)\nlogsize %llu\n",
		total, free, barrier, thres, *flen);
	if(free > barrier)
		return 0;
	return -1;
}

void
defcon1(char *f, ulong flen)
{
	char tmpf[] = "/tmp/logwatch.XXXXXX";
	char buf[128*KB];
	int fd, tfd, n;

	fd = open(f, O_RDWR);
	if(fd < 0)
		sysfatal("open");
	tfd = mkstemp(tmpf);
	if(tfd < 0)
		sysfatal("mkstemp");
	lockfile(fd);
	if(lseek(fd, flen/2, SEEK_SET) < 0)
		sysfatal("lseek [logfile]");
	while((n = read(fd, buf, sizeof buf)) > 0)
		if(write(tfd, buf, n) != n)
			sysfatal("write [tmpfile]");
	if(n < 0)
		sysfatal("read [logfile]");
	if(ftruncate(fd, 0) < 0)
		sysfatal("ftruncate");
	if(lseek(fd, 0, SEEK_SET) < 0)
		sysfatal("lseek [logfile]");
	if(lseek(tfd, 0, SEEK_SET) < 0)
		sysfatal("lseek [tmpfile]");
	while((n = read(tfd, buf, sizeof buf)) > 0)
		if(write(fd, buf, n) != n)
			sysfatal("write [logfile]");
	if(n < 0)
		sysfatal("read [tmpfile]");
	unlockfile(fd);
	close(tfd);
	close(fd);
	unlink(tmpf);
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-d] [-t perc] logfile\n", argv0);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct inotify_event *e;
	struct statvfs vfs;
	char buf[sizeof(struct inotify_event)+NAME_MAX+1], *logfile, *logdir, *p;
	int fd, watches[NWATCH], n, elen;
	int thres;
	ulong cookie, logfilelen;

	thres = 5;
	ARGBEGIN{
	case 'd': debug++; break;
	case 't':
		thres = strtol(EARGF(usage()), nil, 10);
		break;
	default: usage();
	}ARGEND;
	if(argc != 1)
		usage();
	if(thres < 0 || thres > 100)
		thres = 5;
	p = strrchr(argv[0], '/');
	if(p == nil)
		logdir = getcwd(nil, 0);
	else{
		logdir = emalloc(p-argv[0]+1);
		strncpy(logdir, argv[0], p-argv[0]);
		logdir[p-argv[0]] = 0;
	}
	logfile = estrdup(p? p+1: argv[0]);
	fd = inotify_init();
	if(fd < 0)
		sysfatal("inotify_init");
	watches[Wlogfile] = inotify_add_watch(fd, logfile, IN_MODIFY);
	if(watches[Wlogfile] < 0)
		sysfatal("inotify_add_watch [file]");
	watches[Wlogdir] = inotify_add_watch(fd, logdir, IN_MOVE);
	if(watches[Wlogdir] < 0)
		sysfatal("inotify_add_watch [dir]");
	dprint("file: %d\ndir: %d\n", watches[Wlogfile], watches[Wlogdir]);
	cookie = 0;
	while((n = read(fd, buf, sizeof buf)) >= 0){
Decode:
		e = (struct inotify_event*)buf;
		if(e->wd == watches[Wlogfile]){
			if((e->mask & IN_MODIFY) != 0)
				dprint("modified %s\n", logfile);
			if((e->mask & IN_IGNORED) != 0){
				dprint("deleted %s\n", logfile);
				exit(0);
			}
			if(statvfs(logdir, &vfs) < 0)
				sysfatal("statvfs");
			if(checkusage(logfile, &vfs, thres, &logfilelen) < 0)
				defcon1(logfile, logfilelen);
		}else if(e->wd == watches[Wlogdir]){
			if((e->mask & IN_MOVED_FROM) != 0)
				if(e->len > 0 && strcmp(e->name, logfile) == 0)
					cookie = e->cookie;
			if((e->mask & IN_MOVED_TO) != 0)
				if(e->cookie == cookie && e->len > 0){
					dprint("rename from %s", logfile);
					free(logfile);
					logfile = estrdup(e->name);
					dprint(" to %s\n", logfile);
				}
		}
		elen = sizeof(struct inotify_event)+e->len;
		if(n > elen){
			p = buf+elen;
			memmove(buf, p, n-elen);
			n -= elen;
			goto Decode;
		}
	}
	exit(0);
}
