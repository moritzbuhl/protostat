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
#include <netinet/ip.h>
#include <netinet6/ip6_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_ah.h>
#include <netinet/ip_carp.h>
#include <netinet/ip_divert.h>
#include <netinet/ip_esp.h>
#include <netinet/ip_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_ipcomp.h>
#include <netinet/ip_ipip.h>
#include <netinet/ip_ipsp.h>
#include <netinet/icmp6.h>
#include <netinet/icmp_var.h>
#include <netinet/igmp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet6/ip6_divert.h>
#include <netinet6/raw_ip6.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <net/if_pflow.h>
#include <net/if_pfsync.h>

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

/* netstat order */
#define PROTO_IP	0x00001
#define PROTO_ICMP	0x00002
#define PROTO_IGMP	0x00004
#define PROTO_IPENCAP	0x00008
#define PROTO_TCP	0x00010
#define PROTO_UDP	0x00020
#define PROTO_IPSEC	0x00040
#define PROTO_ESP	0x00080
#define PROTO_AH	0x00100
#define PROTO_ETHERIP	0x00200
#define PROTO_IPCOMP	0x00400
#define PROTO_CARP	0x00800
#define PROTO_PFSYNC	0x01000
#define PROTO_DIVERT	0x02000
#define PROTO_PFLOW	0x04000
#define PROTO_IP6	0x08000
#define PROTO_DIVERT6	0x10000
#define PROTO_ICMP6	0x20000
#define PROTO_RIP6	0x40000
#define PROTO_ALL	(PROTO_AH | PROTO_CARP | PROTO_DIVERT6 |	\
			PROTO_DIVERT | PROTO_ESP | PROTO_ETHERIP | 	\
			PROTO_ICMP6 | PROTO_ICMP | PROTO_IGMP | 	\
			PROTO_IP6 | PROTO_IP | PROTO_IPCOMP |		\
			PROTO_IPENCAP | PROTO_IPSEC | PROTO_PFLOW |	\
			PROTO_PFSYNC | PROTO_RIP6 | PROTO_TCP | PROTO_UDP)

struct stats {
	struct ahstat ah;
	struct carpstats carp;
	struct divstat divert;
	struct div6stat divert6;
	struct espstat esp;
	struct etheripstat etherip;
	struct icmpstat icmp;
	struct icmp6stat icmp6;
	struct igmpstat igmp;
	struct ipstat ip;
	struct ip6stat ip6;
	struct ipcompstat ipcomp;
	struct ipipstat ipip;
	struct ipsecstat ipsec;
	struct pflowstats pflow;
	struct pfsyncstats pfsync;
	struct rip6stat rip6;
	struct tcpstat tcp;
	struct udpstat udp;
};

char file[PATH_MAX];
int store, jFlag, lFlag, qFlag, wFlag, zFlag;
struct stats print;

void
printstat(void *buf, struct stat_field_descr descr[], size_t nfields)
{
	size_t i;
	struct stat_field_descr *n;

	for (i = 0; i < nfields; i++) {
		n = &descr[i];
		switch(n->siz) {
		case 1: {
			uint8_t v = ((uint8_t *)(buf + n->off))[0];
			if (zFlag && !v)
				break;
			printf("%s: %hhu\n", descr[i].name, v);
			break;
		}
		case 2: {
			uint16_t v = ((uint16_t *)(buf + n->off))[0];
			if (zFlag && !v)
				break;
			printf("%s: %hu\n", descr[i].name, v);
			break;
		}
		case 4: {
			uint32_t v = ((uint32_t *)(buf + n->off))[0];
			if (zFlag && !v)
				break;
			printf("%s: %u\n", descr[i].name, v);
			break;
		}
		case 8: {
			uint64_t v = ((uint64_t *)(buf + n->off))[0];
			if (zFlag && !v)
				break;
			printf("%s: %llu\n", descr[i].name, v);
			break;
		}
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
	printproto(PROTO_CARP, st->carp, carp_descr);
	printproto(PROTO_DIVERT6, st->divert6, divert6_descr);
	printproto(PROTO_DIVERT, st->divert, divert_descr);
	printproto(PROTO_ESP, st->esp, esp_descr);
	printproto(PROTO_ETHERIP, st->etherip, etherip_descr);
	printproto(PROTO_ICMP, st->icmp, icmp_descr);
	printproto(PROTO_ICMP6, st->icmp6, icmp6_descr);
	printproto(PROTO_IGMP, st->igmp, igmp_descr);
	printproto(PROTO_IP, st->ip, ip_descr);
	printproto(PROTO_IP6, st->ip6, ip6_descr);
	printproto(PROTO_IPCOMP, st->ipcomp, ipcomp_descr);
	printproto(PROTO_IPENCAP, st->ipip, ipip_descr);
	printproto(PROTO_IPSEC, st->ipsec, ipsec_descr);
	printproto(PROTO_PFLOW, st->pflow, pflow_descr);
	printproto(PROTO_PFSYNC, st->pfsync, pfsync_descr);
	printproto(PROTO_RIP6, st->rip6, rip6_descr);
	printproto(PROTO_TCP, st->tcp, tcp_descr);
	printproto(PROTO_UDP, st->udp, udp_descr);
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

#define diff(field, descr)	diffstat(&st1->field, &st2->field, 	\
				&out->field, descr, sizeof(descr) /	\
				sizeof(descr[0]))
void
diffstats(struct stats *st1, struct stats *st2, struct stats *out)
{
	diff(ah, ah_descr);
	diff(carp, carp_descr);
	diff(divert, divert_descr);
	diff(divert6, divert6_descr);
	diff(esp, esp_descr);
	diff(etherip, etherip_descr);
	diff(icmp, icmp_descr);
	diff(icmp6, icmp6_descr);
	diff(igmp, igmp_descr);
	diff(ip, ip_descr);
	diff(ip6, ip6_descr);
	diff(ipcomp, ipcomp_descr);
	diff(ipip, ipip_descr);
	diff(ipsec, ipsec_descr);
	diff(pflow, pflow_descr);
	diff(pfsync, pfsync_descr);
	diff(rip6, rip6_descr);
	diff(tcp, tcp_descr);
	diff(udp, udp_descr);
}

void
dumpstat(int fd, void *buf, size_t len)
{
	ssize_t r, l = 0;

	while (len != 0) {
		if ((r = write(fd, buf + l, len)) == -1)
			err(1, NULL);
		len -= r;
		l += r;
	}
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
	} while (0)

void
getstats(struct stats *st)
{
	getstat(CTL_NET, PF_INET, IPPROTO_AH, AHCTL_STATS,
	    struct ahstat, st->ah);
	getstat(CTL_NET, PF_INET, IPPROTO_CARP, CARPCTL_STATS,
	    struct carpstats, st->carp);
	getstat(CTL_NET, PF_INET6, IPPROTO_DIVERT, DIVERT6CTL_STATS,
	    struct div6stat, st->divert6);
	getstat(CTL_NET, PF_INET, IPPROTO_DIVERT, DIVERTCTL_STATS,
	    struct divstat, st->divert);
	getstat(CTL_NET, PF_INET, IPPROTO_ESP, ESPCTL_STATS,
	    struct espstat, st->esp);
	getstat(CTL_NET, PF_INET, IPPROTO_ETHERIP, ETHERIPCTL_STATS,
	    struct etheripstat, st->etherip);
	getstat(CTL_NET, PF_INET6, IPPROTO_ICMPV6, ICMPV6CTL_STATS,
	    struct icmp6stat, st->icmp6);
	getstat(CTL_NET, PF_INET, IPPROTO_ICMP, ICMPCTL_STATS,
	    struct icmpstat, st->icmp);
	getstat(CTL_NET, PF_INET, IPPROTO_IGMP, IGMPCTL_STATS,
	    struct igmpstat, st->igmp);
	getstat(CTL_NET, PF_INET, IPPROTO_IP, IPCTL_STATS,
	    struct ipstat, st->ip);
	getstat(CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_STATS,
	    struct ip6stat, st->ip6);
	getstat(CTL_NET, PF_INET, IPPROTO_IPCOMP, IPCOMPCTL_STATS,
	    struct ipcompstat, st->ipcomp);
	getstat(CTL_NET, PF_INET, IPPROTO_IPIP, IPIPCTL_STATS,
	    struct ipipstat, st->ipip);
	getstat(CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPSEC_STATS,
	    struct ipsecstat, st->ipsec);
	do {
		int mib[] = { CTL_NET, PF_PFLOW, NET_PFLOW_STATS };
		size_t len = sizeof(struct pflowstats);
		memset(&st->pflow, 0, sizeof(st->pflow));
		if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), &st->pflow,
		    &len, NULL, 0) == -1)
			err(1, NULL);
	} while (0);
	getstat(CTL_NET, PF_INET, IPPROTO_PFSYNC, PFSYNCCTL_STATS,
	    struct pfsyncstats, st->pfsync);
	getstat(CTL_NET, PF_INET6, IPPROTO_RAW, RIPV6CTL_STATS,
	    struct rip6stat, st->rip6);
	getstat(CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_STATS,
	    struct tcpstat, st->tcp);
	getstat(CTL_NET, PF_INET, IPPROTO_UDP, UDPCTL_STATS,
	    struct udpstat, st->udp);
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
	fprintf(stderr, "usage: protostat [-djlqwz] [-D id[,id]] [-I id] "
	    "[-P proto]\n");
	fprintf(stderr, "    -d\t\tprint delta since last invocation\n");
	fprintf(stderr, "    -j\t\twrite output as JSON\n");
	fprintf(stderr, "    -l\t\tlist previously stored data and ids\n");
	fprintf(stderr, "    -q\t\tskip printing state\n");
	fprintf(stderr, "    -w\t\tstore current state\n");
	fprintf(stderr, "    -w\t\tskip zero values\n");
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

	while ((ch = getopt(argc, argv, "D:I:P:djlqwz")) != -1) {
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
		case 'z':
			zFlag = 1;
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

	if (!qFlag)
		printstats(&print, protocol);
	if (wFlag)
		dumpstat(store, &print, sizeof(print));
}
