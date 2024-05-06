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
#include <netinet/ip_ah.h>
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

#define PROTO_AH	0x00001
#define PROTO_CARP	0x00002
#define PROTO_DIVERT6	0x00004
#define PROTO_DIVERT	0x00008
#define PROTO_ESP	0x00010
#define PROTO_ETHERIP	0x00020
#define PROTO_ICMP6	0x00040
#define PROTO_ICMP	0x00080
#define PROTO_IGMP	0x00100
#define PROTO_IP6	0x00200
#define PROTO_IP	0x00400
#define PROTO_IPCOMP	0x00800
#define PROTO_IPENCAP	0x01000
#define PROTO_IPSEC	0x02000
#define PROTO_PFLOW	0x04000
#define PROTO_PFSYNC	0x08000
#define PROTO_RIP6	0x10000
#define PROTO_TCP	0x20000
#define PROTO_UDP	0x40000
#define PROTO_ALL	(PROTO_AH | PROTO_CARP | PROTO_DIVERT6 |	\
			PROTO_DIVERT | PROTO_ESP | PROTO_ETHERIP | 	\
			PROTO_ICMP6 | PROTO_ICMP | PROTO_IGMP | 	\
			PROTO_IP6 | PROTO_IP | PROTO_IPCOMP |		\
			PROTO_IPENCAP | PROTO_IPSEC | PROTO_PFLOW |	\
			PROTO_PFSYNC | PROTO_RIP6 | PROTO_TCP | PROTO_UDP)

struct stats {
	struct ahstat ah;
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

#define printproto(p, t, descr)	do {					\
	if (protocol & p)						\
		printstat(&t, descr, sizeof(descr) / sizeof(descr[0]));	\
	} while(0)

void
printstats(struct stats *st, uint32_t protocol)
{
	printproto(PROTO_AH, st->ah, ah_descr);

	printproto(PROTO_TCP, st->tcp, tcp_descr);
}

void
diffstat(void *in1, void *in2, void *out, struct stat_field_descr descr[],
    size_t nfields)
{
	size_t i;
	struct stat_field_descr *n;

	for (i = 0; i < nfields; i++) {
		n = &descr[i];
		switch(n->siz) {
		case 1: {
			uint8_t i1 = ((uint8_t *)(in1 + n->off))[0];
			uint8_t i2 = ((uint8_t *)(in2 + n->off))[0];
			if (i2 < i1)
				errx(1, "field '%s' shrunk from %hhu to %hhu",
				    descr[i].name, i1, i2);
			*((uint8_t *)(out + n->off)) = i2 - i1;
			break;
		}
		case 2: {
			uint16_t i1 = ((uint16_t *)(in1 + n->off))[0];
			uint16_t i2 = ((uint16_t *)(in2 + n->off))[0];
			if (i2 < i1)
				errx(1, "field '%s' shrunk from %hu to %hu",
				    descr[i].name, i1, i2);
			*((uint16_t *)(out + n->off)) = i2 - i1;
			break;
		}
		case 4: {
			uint32_t i1 = ((uint32_t *)(in1 + n->off))[0];
			uint32_t i2 = ((uint32_t *)(in2 + n->off))[0];
			if (i2 < i1)
				errx(1, "field '%s' shrunk from %u to %u",
				    descr[i].name, i1, i2);
			*((uint32_t *)(out + n->off)) = i2 - i1;
			break;
			break;
		}
		case 8: {
			uint64_t i1 = ((uint64_t *)(in1 + n->off))[0];
			uint64_t i2 = ((uint64_t *)(in2 + n->off))[0];
			if (i2 < i1)
				errx(1, "field '%s' shrunk from %llu to %llu",
				    descr[i].name, i1, i2);
			*((uint64_t *)(out + n->off)) = i2 - i1;
			break;
		}
		default:
			errx(1, "unsupported type size");
		}
	}
}

void
diffstats(struct stats *st1, struct stats *st2, struct stats *out)
{
	diffstat(&st1->tcp, &st2->tcp, &out->tcp, tcp_descr, sizeof(tcp_descr) /
		    sizeof(tcp_descr[0]));
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
		if (r == 0)
			errx(1, "stored data too small");
		len -= r;
		l += r;
	}
}

#define	getstat(mib1, mib2, mib3, mib4, type, field)	do {		\
		int mib[] = { mib1, mib2, mib3, mib4 };			\
		size_t len = sizeof(type);				\
		memset(&field, 0, sizeof(field));			\
		if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), &field,	\
		    &len, NULL, 0) == -1)				\
			err(1, NULL);					\
	} while(0)

void
getstats(struct stats *st)
{
/*
	getstat(CTL_NET, PF_INET, IPPROTO_AH, AHCTL_STATS,
	    struct ahstat, st->ah);
*/

	getstat(CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_STATS,
	    struct tcpstat, st->tcp);
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

uint32_t
str2proto(char *optarg)
{
	if (strcasecmp(optarg, "AH") == 0)
		return PROTO_AH;
	if (strcasecmp(optarg, "CARP") == 0)
		return PROTO_CARP;
	if (strcasecmp(optarg, "DIVERT6") == 0)
		return PROTO_DIVERT6;
	if (strcasecmp(optarg, "DIVERT") == 0)
		return PROTO_DIVERT;
	if (strcasecmp(optarg, "ESP") == 0)
		return PROTO_ESP;
	if (strcasecmp(optarg, "ETHERIP") == 0)
		return PROTO_ETHERIP;
	if (strcasecmp(optarg, "ICMP6") == 0)
		return PROTO_ICMP6;
	if (strcasecmp(optarg, "ICMP") == 0)
		return PROTO_ICMP;
	if (strcasecmp(optarg, "IGMP") == 0)
		return PROTO_IGMP;
	if (strcasecmp(optarg, "IP6") == 0)
		return PROTO_IP6;
	if (strcasecmp(optarg, "IP") == 0)
		return PROTO_IP;
	if (strcasecmp(optarg, "IPCOMP") == 0)
		return PROTO_IPCOMP;
	if (strcasecmp(optarg, "IPENCAP") == 0)
		return PROTO_IPENCAP;
	if (strcasecmp(optarg, "IPSEC") == 0)
		return PROTO_IPSEC;
	if (strcasecmp(optarg, "PFLOW") == 0)
		return PROTO_PFLOW;
	if (strcasecmp(optarg, "PFSYNC") == 0)
		return PROTO_PFSYNC;
	if (strcasecmp(optarg, "RIP6") == 0)
		return PROTO_RIP6;
	if (strcasecmp(optarg, "TCP") == 0)
		return PROTO_TCP;
	if (strcasecmp(optarg, "UDP") == 0)
		return PROTO_UDP;
	errx(1, "unsupported protocol '%s'", optarg);
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
			protocol |=  str2proto(optarg);
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

		diffstats(&st1, &st2, &print);
	}

	if (!IFlag && !id1)
		getstats(&print);

	if (lFlag)
		return 0;

	printstats(&print, protocol);
	dumpstat(&print.tcp, sizeof(print.tcp));
}
