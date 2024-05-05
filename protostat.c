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

char dir[] = _PATH"/XXXXXXXXXX";

void
printstat(void *buf, struct stat_field_descr descr[], size_t nfields)
{
	size_t i;
	struct stat_field_descr *n;

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
dumpstat(void *buf, size_t len, char *prot)
{
	char *file;
	ssize_t r;
	int fd;

	if (asprintf(&file, "%s/%s", dir, prot) == -1 || file == NULL)
		err(1, NULL);

	if ((fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0644)) == -1)
		err(1, "open");
	if ((r = write(fd, buf, len)) == -1)
		err(1, NULL);
	else if (r != len)
		errx(1, "short write");

	free(file);
}

void
tcp_stats(void)
{
	struct tcpstat tcp;
	int mib[] = { CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_STATS };
	size_t len = sizeof(struct tcpstat);

	memset(&tcp, 0, sizeof(tcp));
	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), &tcp, &len,
	    NULL, 0) == -1)
		err(1, "sysctl");

	printstat(&tcp, tcp_descr, sizeof(tcp_descr) / sizeof(tcp_descr[0]));
	dumpstat(&tcp, sizeof(tcp), "tcp");
}

void
usage(void)
{
	fprintf(stderr, "usage: protostat [-djl] [-D id[,id]] [-P protocol]\n");
	fprintf(stderr, "    -d\t\tprint delta since last invocation\n");
	fprintf(stderr, "    -j\t\twrite output as JSON\n");
	fprintf(stderr, "    -l\t\tlist previously stored data and ids\n");
	fprintf(stderr, "    -D id\t\tprint delta since id or between ids\n");
	fprintf(stderr, "    -P protocol\tonly process the given protocol\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int ch, json = 0, list = 0, fd;
	uint8_t p, protocol = PROTO_ALL;
	struct stat st;

	if (unveil("/tmp/protostat", "rwc") == -1)
		err(1, NULL);

	while ((ch = getopt(argc, argv, "D:P:djl")) != -1) {
		switch (ch) {
		case 'd':
			break;
		case 'j':
			json = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 'D':
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
	printf("%d\n", st.st_mode);
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

	if (mkdtemp(dir) == NULL)
		err(1, "mkdtemp");

	if (protocol & PROTO_TCP)
		tcp_stats();

	if (list) {
		/* list /tmp/protostat/ sorted by creation date */
	}
}
