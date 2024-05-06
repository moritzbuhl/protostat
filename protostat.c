/*
 * Copyright (c) 2024 Moritz Buhl <mbuhl@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protostat.h"

#define _PATH	"/tmp/protostat"

#define PROTO_TCP	0x01
#define PROTO_ALL	(PROTO_TCP)

struct stats {
	struct tcpstat tcp;
};

char file[PATH_MAX];
int store, jFlag, lFlag, qFlag, wFlag;
struct stats print;

void
printstat(void *buf, struct stat_field_descr descr[], size_t nfields)
{
	size_t i;
	struct stat_field_descr *n;

	if (qFlag)
		return;

	for (i = 0; i < nfields; i++) {
		n = &descr[i];
		printf("%s: ", descr[i].name);
		switch(n->siz) {
		case 1:
			printf("%hhu\n", ((uint8_t *)(buf + n->off))[0]);
			break;
		case 2:
			printf("%hu\n", ((uint16_t *)(buf + n->off))[0]);
			break;
		case 4:
			printf("%u\n", ((uint32_t *)(buf + n->off))[0]);
			break;
		case 8:
			printf("%llu\n", ((uint64_t *)(buf + n->off))[0]);
			break;
		default:
			errx(1, "unsupported type size");
		}
	}
}

void
diffstat(uint8_t *buf1, uint8_t *buf2, size_t len)
{
	size_t i;
	uint8_t *p = (uint8_t *)&print;

	for (i = 0; i < len; i++)
		p[i] = buf2[i] - buf1[i];
}

void
dumpstat(void *buf, size_t len)
{
	ssize_t r;

	if (!wFlag)
		return;

	if ((r = write(store, buf, len)) == -1)
		err(1, NULL);
	else if (r != len)
		errx(1, "short write");
}

void
loadstat(int fd, void *buf, size_t len)
{
	ssize_t r, l = 0;

	while (len != 0) {
		if ((r = read(fd, buf + l, len)) == -1)
			err(1, NULL);
		len -= r;
		l += r;
	}
}

void
getstats(struct stats *st)
{
	int mib[] = { CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_STATS };
	size_t len = sizeof(struct tcpstat);

	memset(&st->tcp, 0, sizeof(st->tcp));
	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), &st->tcp, &len,
	    NULL, 0) == -1)
		err(1, "sysctl");
}

long long
iter(int print, long long id1, int *fd1, long long id2, int *fd2)
{
	struct tm tm;
	char *usec;
	DIR *dirp;
	struct dirent *dp;
	long long i = 0;
	int r, *fd;

	if (print)
		printf("Id\tTimestamp\n");

	if ((dirp = opendir(_PATH)) != NULL) {
		while ((dp = readdir(dirp)) != NULL) {
			if (dp->d_type != DT_REG)
				continue;
			i++;

			if ((usec = strstr(dp->d_name, ".")) == NULL)
				continue;
			if (strptime(dp->d_name, "%s", &tm) == NULL)
				continue;
			if (i == id1 || i == id2) {
				r = snprintf(file, sizeof(file), _PATH"/%s",
				    dp->d_name);
				if (r < 0 || (size_t)r >= sizeof(file))
					err(1, NULL);
				if (i == id1)
					fd = fd1;
				if (i == id2)
					fd = fd2;
				if ((*fd = open(file, O_RDONLY)) == -1)
					err(1, "mkstemp");
			}

			if (!print)
				continue;
			printf("%lld\t%d-%02d-%02d %02d:%02d:%02d%.7s\n", i,
			    tm.tm_year + 1900, tm.tm_mon, tm.tm_mday,
			    tm.tm_hour, tm.tm_min, tm.tm_sec, usec);
		}

		closedir(dirp);
	}

	return i;
}

void
usage(void)
{
	fprintf(stderr, "usage: protostat [-djlqw] [-D id[,id]] [-I id] "
	    "[-P proto]\n");
	fprintf(stderr, "    -d\t\tprint delta since last invocation\n");
	fprintf(stderr, "    -j\t\twrite output as JSON\n");
	fprintf(stderr, "    -l\t\tlist previously stored data and ids\n");
	fprintf(stderr, "    -q\t\tdo'nt print current state\n");
	fprintf(stderr, "    -w\t\tstore current state\n");
	fprintf(stderr, "    -D id,id\tprint delta since id or between ids\n");
	fprintf(stderr, "    -I id\tprint state of id\n");
	fprintf(stderr, "    -P proto\tonly process the given protocol\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int ch, r;
	long long id1 = 0, id2 = 0, max = 0, IFlag = 0;
	uint32_t protocol = PROTO_ALL;
	char *c;
	const char *errstr;
	struct stat st;
	struct timeval tv;

	if (unveil("/tmp/protostat", "rwc") == -1)
		err(1, NULL);

	if (gettimeofday(&tv, NULL) == -1)
		err(1, NULL);

	max = iter(0, 0, NULL, 0, NULL);

	r = snprintf(file, sizeof(file), _PATH"/%llu.%06ld-XXXXXXXXXX", // XXX
	    tv.tv_sec, tv.tv_usec);
	if (r < 0 || (size_t)r >= sizeof(file))
		err(1, NULL);

	while ((ch = getopt(argc, argv, "D:I:P:djlqw")) != -1) {
		switch (ch) {
		case 'd':
			id1 = max;
			IFlag = 0;
			qFlag = 0;
			break;
		case 'j':
			jFlag = 1;
			break;
		case 'l':
			if (!max)
				errx(1, "no stored data available");
			lFlag = 1;
			break;
		case 'w':
			id1 = 0;
			IFlag = 0;
			wFlag = 1;
			break;
		case 'q':
			id1 = 0;
			IFlag = 0;
			qFlag = 1;
			break;
		case 'D':
			if (!max)
				errx(1, "no stored data available");
			else if ((c = strstr(optarg, ",")) != NULL) {
				*c = '\0';
				id1 = strtonum(optarg, 1, max, &errstr);
				if (errstr != NULL)
					errx(1, "-D id is %s: %s", errstr,
					    optarg);
				id2 = strtonum(++c, id1 + 1, max, &errstr);
				if (errstr != NULL)
					errx(1, "-D %lld,id is %s: %s", id1,
					    errstr, optarg);
			} else
				id1 = max;
			IFlag = 0;
			qFlag = 0;
			break;
		case 'I':
			IFlag = strtonum(optarg, 1, max, &errstr);
			if (errstr != NULL)
				errx(1, "-I id is %s: %s", errstr, optarg);
			id1 = 0;
			wFlag = 0;
			qFlag = 0;
			break;
		case 'P':
			if (protocol == PROTO_ALL)
				protocol = 0;
			if (strcasecmp(optarg, "TCP") == 0)
				protocol |= PROTO_TCP;
			else
				errx(1, "unsupported protocol '%s'", optarg);
			break;
		default:
			usage();
		}
	}

 retry:
	if (stat(_PATH, &st) == 0) {
		if (!S_ISDIR(st.st_mode) || (st.st_mode & 0777) != 0755 /* ||
		    st.st_uid != _UID || st.st_gid != _GID */) /* XXX */
			errx(1, _PATH " has wrong mode/owner");
	} else if (mkdir(_PATH, 0755) == -1) {
		if (errno == EEXIST)
			goto retry;
		else
			err(1, NULL);
	} else if (unveil("/tmp/protostat", "rwc") == -1)
		err(1, NULL);

	if (unveil(file, "rwc") == -1)
		err(1, NULL);

	if (wFlag) {
		if ((store = mkstemp(file)) == -1)
			err(1, "mkstemp");
	}

	if (lFlag || IFlag) {
		iter(lFlag, IFlag, &store, 0, NULL);
	} else if (id1) {
		int fd1, fd2;
		struct stats st1, st2;

		iter(lFlag, id1, &fd1, id2, &fd2);
		loadstat(fd1, &st1, sizeof(st1));
		if (id2)
			loadstat(fd2, &st2, sizeof(st2));
		else
			getstats(&st2);

		diffstat((uint8_t *)&st1, (uint8_t *)&st2, sizeof(st1));
	}

	if (!IFlag && !id1)
		getstats(&print);

	if (lFlag)
		return 0;

	if (protocol & PROTO_TCP)
		printstat(&print.tcp, tcp_descr, sizeof(tcp_descr) /
		    sizeof(tcp_descr[0]));
	dumpstat(&print.tcp, sizeof(print.tcp));
}
