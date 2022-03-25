/* */

/*
 * Copyright (c) 2020, 2022 They University of Queensland
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <paths.h>
#include <signal.h>

#include <netdb.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <net/if_pflog.h>

#include <sys/queue.h>
#include <sys/tree.h>

#include <pcap.h>
#include <event.h>

#include "log.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ISSET
#define ISSET(_v, _m)	((_v) & (_m))
#endif

/*
 * protocols without good definitions in standard headers.
 */

#define s6_addr32 __u6_addr.__u6_addr32

struct gre_header {
	uint16_t		gre_flags;
#define GRE_CP				0x8000	/* Checksum Present */
#define GRE_KP				0x2000	/* Key Present */
#define GRE_SP				0x1000	/* Sequence Present */

#define GRE_VERS_MASK			0x0007
#define GRE_VERS_0			0x0000
#define GRE_VERS_1			0x0001

	uint16_t		gre_proto;
} __packed __aligned(4);

struct gre_h_cksum {
	uint16_t		gre_cksum;
	uint16_t		gre_reserved1;
} __packed __aligned(4);

struct gre_h_key {
	uint32_t		gre_key;
} __packed __aligned(4);

/*
 * let's go
 */

struct flow_key {
	uint16_t		k_sport;
	uint16_t		k_dport;

	int			k_vnetid;
#define FLOW_VNETID_UNSET		-1

	struct in6_addr		k_saddr;
	struct in6_addr		k_daddr;

#define k_icmp_type			k_sport
#define k_icmp_code			k_dport

#define k_gre_flags			k_sport
#define k_gre_proto			k_dport

	uint32_t		k_gre_key;
#define k_icmp_id			k_gre_key

	uint8_t			k_ipv;
	uint8_t			k_ipproto;
	uint8_t			k_action;
	uint8_t			k_dir;
} __aligned(8);

struct flow {
	struct flow_key		f_key;

	uint64_t		f_packets;
	uint64_t		f_bytes;

	uint64_t		f_syns;
	uint64_t		f_fins;
	uint64_t		f_rsts;

	RBT_ENTRY(flow)		f_entry_tree;
	TAILQ_ENTRY(flow)	f_entry_list;
};

RBT_HEAD(flow_tree, flow);
TAILQ_HEAD(flow_list, flow);

static inline int
flow_cmp(const struct flow *a, const struct flow *b)
{
	const struct flow_key *ka = &a->f_key;
	const struct flow_key *kb = &b->f_key;
	const unsigned long *la = (const unsigned long *)ka;
	const unsigned long *lb = (const unsigned long *)kb;
	size_t i;

	for (i = 0; i < sizeof(*ka) / sizeof(*la); i++) {
		if (la[i] > lb[i])
			return (1);
		if (la[i] < lb[i])
			return (-1);
	}

	return (0);
}

RBT_PROTOTYPE(flow_tree, flow, f_entry_tree, flow_cmp);

struct timeslice {
	unsigned int		ts_flow_count;
	struct flow_tree	ts_flow_tree;
	struct flow_list	ts_flow_list;

	struct timeval		ts_begin;
	struct timeval		ts_end;
	struct timeval		ts_utime;
	struct timeval		ts_stime;
	uint64_t		ts_reads;
	uint64_t		ts_packets;
	uint64_t		ts_bytes;

	uint64_t		ts_mdrop;

	uint64_t		ts_short_pfloghdr;
	uint64_t		ts_short_ip4;
	uint64_t		ts_short_ip6;
	uint64_t		ts_short_ipproto;
	uint64_t		ts_nonip;

	unsigned int		ts_pcap_recv;
	unsigned int		ts_pcap_drop;
	unsigned int		ts_pcap_ifdrop;
};

static struct timeslice	*timeslice_alloc(const struct timeval *);

struct collector;

struct pflogif {
	const char		*p_name;
	struct collector	*p_c;
	pcap_t			*p_ph;
	struct pcap_stat	 p_pstat;
	struct event		 p_ev;

	TAILQ_ENTRY(pflogif)	 p_entry;
};

TAILQ_HEAD(pflogifs, pflogif);

struct iface {
	char			if_name[IF_NAMESIZE];
	char			if_descr[IFDESCRSIZE];
	int			if_vnetid;
	time_t			if_refresh;
	RBT_ENTRY(vnetid)	if_entry;
};

RBT_HEAD(ifaces, iface);

static inline int
iface_cmp(const struct iface *a, const struct iface *b)
{
	return (strcmp(a->if_name, b->if_name));
}

RBT_PROTOTYPE(ifaces, iface, if_entry, iface_cmp);

struct buf {
	char	*mem;
	size_t	 len;
	size_t	 off;
};

struct collector {
	char			 c_hostname[HOST_NAME_MAX + 1];

	struct event		 c_tick;
	struct timeval		 c_tv;
	struct timeval		 c_now;
	int			 c_sock;

	struct ifaces		 c_ifaces;
	struct pflogifs		 c_pflogifs;
	struct flow		*c_flow;

	struct timeslice	*c_ts;

	struct rusage		 c_rusage[2];
	unsigned int		 c_rusage_gen;

	struct {
		int			 af;
		const char		*host;
		const char		*port;
		const char		*user;
		const char		*database;
		const char		*key;

		struct addrinfo		*res;
	}			 c_clickhouse;

	struct buf		 c_buf;
};

int		rdaemon(int);

static void	flow_tick(int, short, void *);
static void	pkt_capture(int, short, void *);
static void	clickhouse_resolve(struct collector *);

static int	pflagg_pcap_filter(pcap_t *);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-46d] -h clickhouse_host "
	    "[-p clickhouse_port] [-D clickhouse_db] [-U clickhouse_user] "
	    "[-k clickhouse_key] [-u user] pflog0\n", __progname);

	exit(1);
}

static int debug = 0;
static int pagesize;

int
main(int argc, char *argv[])
{
	const char *user = "_pflogflowd";
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *errstr;
	struct collector _c = {
		.c_tv = { 4, 0 },
		.c_pflogifs = TAILQ_HEAD_INITIALIZER(_c.c_pflogifs),
		.c_ifaces = RBT_INITIALIZER(_c.c_d_ifaces),

		.c_clickhouse = {
			.af = PF_UNSPEC,
			.host = NULL,
			.port = "8123",
			.user = "default",
			.database = "default",
		},
	};
	struct collector *c = &_c;
	struct pflogif *p;

	struct passwd *pw;
	int ch;
	int devnull = -1;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize == -1)
		err(1, "page size");
	if (pagesize < 1024) /* in case we're run on a crappy vax OS */
		pagesize = 4096;

	if (gethostname(c->c_hostname, sizeof(c->c_hostname)) == -1)
		err(1, "gethostname");

	while ((ch = getopt(argc, argv, "46dD:u:w:h:p:U:k:")) != -1) {
		switch (ch) {
		case '4':
			c->c_clickhouse.af = PF_INET;
			break;
		case '6':
			c->c_clickhouse.af = PF_INET6;
			break;
		case 'd':
			debug = 1;
			break;
		case 'D':
			c->c_clickhouse.database = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'w':
			c->c_tv.tv_sec = strtonum(optarg, 1, 900, &errstr);
			if (errstr != NULL)
				errx(1, "%s: %s", optarg, errstr);
			break;
		case 'h':
			c->c_clickhouse.host = optarg;
			break;
		case 'p':
			c->c_clickhouse.port = optarg;
			break;
		case 'U':
			c->c_clickhouse.user = optarg;
			break;
		case 'k':
			c->c_clickhouse.key = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	if (c->c_clickhouse.host == NULL)
		usage();

	clickhouse_resolve(c);

	signal(SIGPIPE, SIG_IGN);

	if (geteuid())
		lerrx(1, "need root privileges");

	pw = getpwnam(user);
	if (pw == NULL)
		errx(1, "%s: unknown user", user);

	if (!debug) {
		extern char *__progname;

		devnull = open(_PATH_DEVNULL, O_RDWR, 0);
		if (devnull == -1)
			err(1, "open %s", _PATH_DEVNULL);

		logger_syslog(__progname);
	}

	/* pflogifs is limited to 1 for now, but we can go higher if needed */
	for (ch = 0; ch < argc; ch++) {
		p = malloc(sizeof(*p));
		if (p == NULL)
			err(1, NULL);

		p->p_ph = pcap_create(argv[ch], errbuf);
		if (p->p_ph == NULL)
			errx(1, "%s", errbuf);

#if 0
		/* XXX TOCTOU */
		if (pcap_set_buffer_size(p->p_ph, maxbufsize) != 0)
			errx(1, "%s: %s", argv[ch], pcap_geterr(p->p_ph));
#endif

		if (pcap_set_promisc(p->p_ph, 1) != 0)
			errx(1, "%s", errbuf);

		if (pcap_set_snaplen(p->p_ph, 256) != 0)
			errx(1, "%s", errbuf);

		if (pcap_set_timeout(p->p_ph, 10) != 0)
			errx(1, "%s", errbuf);

		if (pcap_activate(p->p_ph) != 0)
			errx(1, "%s", errbuf);

		if (pcap_set_datalink(p->p_ph, DLT_PFLOG) != 0)
			errx(1, "%s", errbuf);

		if (pcap_setnonblock(p->p_ph, 1, errbuf) != 0)
			errx(1, "%s", errbuf);

		if (pflagg_pcap_filter(p->p_ph) != 0)
			errx(1, "%s: %s", argv[ch], pcap_geterr(p->p_ph));

		p->p_c = c;
		p->p_name = argv[ch];

		/* fetch a baseline */
		memset(&p->p_pstat, 0, sizeof(p->p_pstat));
		if (pcap_stats(p->p_ph, &p->p_pstat) != 0)
			errx(1, "%s %s", p->p_name, pcap_geterr(p->p_ph));

		TAILQ_INSERT_TAIL(&c->c_pflogifs, p, p_entry);
	}

	c->c_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (c->c_sock == -1)
		err(1, "ioc sock");

	if (chroot(pw->pw_dir) == -1)
		err(1, "chroot %s", pw->pw_dir);
	if (chdir("/") == -1)
		err(1, "chdir %s", pw->pw_dir);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "unable to drop privileges");

	endpwent();

	c->c_flow = malloc(sizeof(*c->c_flow));
	if (c->c_flow == NULL)
		err(1, NULL);

	gettimeofday(&c->c_now, NULL);

	c->c_ts = timeslice_alloc(&c->c_now);
	if (c->c_ts == NULL)
		err(1, NULL);

	if (!debug && rdaemon(devnull) == -1)
		err(1, "unable to daemonize");

	event_init();

	evtimer_set(&c->c_tick, flow_tick, c);
	evtimer_add(&c->c_tick, &c->c_tv);

	TAILQ_FOREACH(p, &c->c_pflogifs, p_entry) {
		event_set(&p->p_ev, pcap_get_selectable_fd(p->p_ph),
		    EV_READ | EV_PERSIST, pkt_capture, p);
		event_add(&p->p_ev, NULL);
	}

	event_dispatch();

	return (0);
}

static int
pflagg_pcap_filter(pcap_t *p)
{
	struct bpf_insn bpf_filter[] = {
		BPF_STMT(BPF_RET+BPF_K, pcap_snapshot(p)),
	};
	struct bpf_program bp = {
		.bf_insns = bpf_filter,
		.bf_len = nitems(bpf_filter),
	};

	return (pcap_setfilter(p, &bp));
}

static inline int
flow_gre_key_valid(const struct flow *f)
{
	uint16_t v = f->f_key.k_gre_flags;
	/* ignore checksum and seq no */
	v &= ~htons(GRE_CP|GRE_SP);
	return (v == htons(GRE_VERS_0|GRE_KP));
}

static void
clickhouse_resolve(struct collector *c)
{
	struct addrinfo hints, *res0;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = c->c_clickhouse.af;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(c->c_clickhouse.host, c->c_clickhouse.port,
	    &hints, &res0);
	if (error) {
		errx(1, "clickhouse host %s port %s resolve: %s",
		    c->c_clickhouse.host, c->c_clickhouse.port,
		    gai_strerror(error));
	}

	c->c_clickhouse.res = res0;
}

static int
clickhouse_connect(struct collector *c)
{
	struct addrinfo *res0 = c->c_clickhouse.res, *res;
	int serrno;
	int s;
	const char *cause = NULL;

	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			serrno = errno;
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			serrno = errno;
			close(s);
			continue;
		}

		return (s); /* okay we got one */
	}

	lwarnc(serrno, "clickhouse host %s port %s %s",
	    c->c_clickhouse.host, c->c_clickhouse.port, cause);

	return (-1);
}

static inline void
buf_init(struct buf *b)
{
	b->off = 0;
}

static void
buf_resize(struct buf *b)
{
	b->len += pagesize;
	b->mem = realloc(b->mem, b->len);
	if (b->mem == NULL)
		lerr(1, "buffer resize");
}

static void
buf_reserve(struct buf *b)
{
	if ((b->off + pagesize) > b->len)
		buf_resize(b);
}

static void
buf_cat(struct buf *b, const char *str)
{
	size_t off, rv;

	buf_reserve(b);

	for (;;) {
		rv = strlcpy(b->mem + b->off, str, b->len - b->off);
		off = b->off + rv;
		if (off < b->len)
			break;

		buf_resize(b);
	}

	b->off = off;
}

static void
buf_printf(struct buf *b, const char *fmt, ...)
{
	va_list ap;
	size_t off;
	int rv;

	buf_reserve(b);

	for (;;) {
		va_start(ap, fmt);
		rv = vsnprintf(b->mem + b->off, b->len - b->off, fmt, ap);
		va_end(ap);

		if (rv == -1)
			lerr(1, "%s", __func__);

		off = b->off + rv;
		if (off < b->len)
			break;

		buf_resize(b);
	}

	b->off = off;
}

static void
clickhouse_ts(char *buf, size_t len, const struct timeval *tv)
{
	time_t time = tv->tv_sec;
	struct tm tm;
	size_t off;

	if (gmtime_r(&time, &tm) == NULL)
		lerrx(1, "gmtime");

	off = strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
	snprintf(buf + off, len - off, ".%03lu",
	    (tv->tv_usec / 1000) % 1000);
}

static void
clickhouse_ipv6(char *buf, size_t len, const struct in6_addr *s6)
{
	struct sockaddr_in6 sin6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = *s6,
	};
	int error;

	error = getnameinfo((struct sockaddr *)&sin6, sizeof(sin6),
	    buf, len, NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV);
	if (error != 0)
		lerrx(1, "%s: %s", __func__, gai_strerror(error));
}

static const char *
pf_action(uint8_t action)
{
	const char *str = "other";

	switch (action) {
	case PF_PASS:
		str = "pass";
		break;
	case PF_DROP:
		str = "drop";
		break;
	case PF_MATCH:
		str = "match";
		break;
	}

	return (str);
}

#define JSTR(_str) "\"" _str "\""
#define JK_FMT(_key, _fmt) JSTR(_key) ":" _fmt
#define JK_STR(_key) JK_FMT(_key, "\"%s\"")
#define JK_U(_key) JK_FMT(_key, "%u")
#define JK_D(_key) JK_FMT(_key, "%D")
#define JK_U64(_key) JK_FMT(_key, "%llu")

static const char chunk_trailer[2] = "\r\n";

static ssize_t
write_chunk(int s, struct buf *b)
{
	char chunk_header[128];
	struct iovec iov[3];
	int len;

	len = snprintf(chunk_header, sizeof(chunk_header),
	    "%zx" "\r\n", b->off);

	iov[0].iov_base = chunk_header;
	iov[0].iov_len = len;
	iov[1].iov_base = b->mem;
	iov[1].iov_len = b->off;
	iov[2].iov_base = (void *)chunk_trailer;
	iov[2].iov_len = sizeof(chunk_trailer);

	return (writev(s, iov, nitems(iov)));
}

static void
clickhouse_post(struct collector *c, struct timeslice *ts)
{
	static char rbuf[8192];
	char ipbuf[NI_MAXHOST];
	char stbuf[128], etbuf[128];
	struct flow *f, *nf;
	struct buf *b = &c->c_buf;
	int s;

	s = clickhouse_connect(c);
	if (s == -1) {
		/* error was already logged */
		goto free;
	}

	buf_init(b);

	clickhouse_ts(stbuf, sizeof(stbuf), &ts->ts_begin);
	clickhouse_ts(etbuf, sizeof(etbuf), &ts->ts_end);

	buf_printf(b, "POST /?database=%s"
	    "&query=INSERT+INTO+pflog+FORMAT+JSONEachRow"
	    " HTTP/1.1" "\r\n",
	    c->c_clickhouse.database);
	buf_printf(b, "Host: %s" "\r\n",
	    c->c_clickhouse.host);
	buf_printf(b, "X-ClickHouse-User: %s" "\r\n",
	    c->c_clickhouse.user);
	if (c->c_clickhouse.key != NULL) {
		buf_printf(b, "X-ClickHouse-Key: %s" "\r\n",
		    c->c_clickhouse.key);
	}
	buf_printf(b, "Transfer-Encoding: chunked" "\r\n");
	buf_printf(b, "Content-Type: application/binary" "\r\n");
	buf_printf(b, "\r\n");

	write(s, b->mem, b->off);

	/* Expect/100 Continue? */

	buf_init(b);
	TAILQ_FOREACH(f, &ts->ts_flow_list, f_entry_list) {

		buf_printf(b, "{" JK_STR("hostname"), c->c_hostname);
		buf_printf(b, "," JK_STR("begin_at"), stbuf);
		buf_printf(b, "," JK_STR("end_at"), etbuf);
		buf_printf(b, "," JK_STR("action"),
		    pf_action(f->f_key.k_action));
		buf_printf(b, "," JK_STR("dir"),
		    f->f_key.k_dir == PF_OUT ? "out" : "in");
		buf_printf(b, "," JK_D("vnetid"), f->f_key.k_vnetid);
		buf_printf(b, "," JK_U("ipv"), f->f_key.k_ipv);

		clickhouse_ipv6(ipbuf, sizeof(ipbuf), &f->f_key.k_saddr);
		buf_printf(b, "," JK_STR("saddr"), ipbuf);
		clickhouse_ipv6(ipbuf, sizeof(ipbuf), &f->f_key.k_daddr);
		buf_printf(b, "," JK_STR("daddr"), ipbuf);

		buf_printf(b, "," JK_U("ipproto"), f->f_key.k_ipproto);

		buf_printf(b, "," JK_U("sport"), ntohs(f->f_key.k_sport));
		buf_printf(b, "," JK_U("dport"), ntohs(f->f_key.k_dport));
		buf_printf(b, "," JK_U("gre_key"), ntohl(f->f_key.k_gre_key));

		buf_printf(b, "," JK_U64("packets"), f->f_packets);
		buf_printf(b, "," JK_U64("bytes"), f->f_bytes);
		buf_printf(b, "," JK_U64("syns"), f->f_syns);
		buf_printf(b, "," JK_U64("fins"), f->f_fins);
		buf_printf(b, "," JK_U64("rsts"), f->f_rsts);
		buf_printf(b, "}\n");

		if (b->off >= (128ULL << 10)) { /* 128k? */
			write_chunk(s, b);

			buf_init(b);
		}
	}

	if (b->off > 0) {
		write_chunk(s, b);

		buf_init(b);
	}

	buf_cat(b, "0" "\r\n" "\r\n");
	write(s, b->mem, b->off);

	ssize_t rv = read(s, rbuf, sizeof(rbuf));
	switch (rv) {
	case -1:
		lwarn("read");
		break;
	case 0:
		/* connection closed */
		break;
	default:
		write(2, rbuf, rv);
		break;
	}
	close(s);

free:
	TAILQ_FOREACH_SAFE(f, &ts->ts_flow_list, f_entry_list, nf)
		free(f);
	free(ts);
}

static uint32_t
tv_to_msec(const struct timeval *tv)
{
	uint32_t msecs;

	msecs = tv->tv_sec * 1000;
	msecs += tv->tv_usec / 1000;

	return (msecs);
}

static struct timeslice *
timeslice_alloc(const struct timeval *now)
{
	struct timeslice *ts;

	ts = calloc(1, sizeof(*ts));
	if (ts == NULL)
		return (NULL);

	ts->ts_begin = *now;
	RBT_INIT(flow_tree, &ts->ts_flow_tree);
	TAILQ_INIT(&ts->ts_flow_list);

	return (ts);
}

static void
flow_tick(int nope, short events, void *arg)
{
	struct collector *c = arg;
	struct pflogif *p;
	struct timeslice *ts = c->c_ts;
	struct timeslice *nts;
	unsigned int gen;
	struct rusage *oru, *nru;

	gettimeofday(&c->c_now, NULL);

	evtimer_add(&c->c_tick, &c->c_tv);

	nts = timeslice_alloc(&c->c_now);
	if (nts == NULL) {
		/* just make this ts wider if we can't get a new one */
		return;
	}
	c->c_ts = nts;

	TAILQ_FOREACH(p, &c->c_pflogifs, p_entry) {
		struct pcap_stat pstat;

		pkt_capture(pcap_get_selectable_fd(p->p_ph), 0, p);

		memset(&pstat, 0, sizeof(pstat)); /* for ifdrop */

		if (pcap_stats(p->p_ph, &pstat) != 0)
			lerrx(1, "%s %s", p->p_name, pcap_geterr(p->p_ph));

		ts->ts_pcap_recv += pstat.ps_recv - p->p_pstat.ps_recv;
		ts->ts_pcap_drop += pstat.ps_drop - p->p_pstat.ps_drop;
		ts->ts_pcap_ifdrop += pstat.ps_ifdrop - p->p_pstat.ps_ifdrop;

		p->p_pstat = pstat;
	}

	gen = c->c_rusage_gen;
	oru = &c->c_rusage[gen % nitems(c->c_rusage)];
	gen++;
	nru = &c->c_rusage[gen % nitems(c->c_rusage)];
	c->c_rusage_gen = gen;

	if (getrusage(RUSAGE_SELF, nru) == -1)
		lerr(1, "getrusage");

	timersub(&nru->ru_utime, &oru->ru_utime, &ts->ts_utime);
	timersub(&nru->ru_stime, &oru->ru_stime, &ts->ts_stime);

	ts->ts_end = c->c_now;

	clickhouse_post(c, ts);
}

static int
pkt_count_tcp(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct tcphdr *th;

	if (buflen < sizeof(*th)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	th = (const struct tcphdr *)buf;

	f->f_key.k_sport = th->th_sport;
	f->f_key.k_dport = th->th_dport;
	f->f_syns = (th->th_flags & (TH_SYN | TH_ACK)) == TH_SYN;
	f->f_fins = (th->th_flags & (TH_FIN | TH_ACK)) == TH_FIN;
	f->f_rsts = (th->th_flags & (TH_RST | TH_ACK)) == TH_RST;

	return (0);
}

static int
pkt_count_udp(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct udphdr *uh;

	if (buflen < sizeof(*uh)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	uh = (const struct udphdr *)buf;

	f->f_key.k_sport = uh->uh_sport;
	f->f_key.k_dport = uh->uh_dport;

	return (0);
}

static int
pkt_count_gre(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct gre_header *gh;
	const struct gre_h_key *gkh;
	u_int hlen;

	if (buflen < sizeof(*gh)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	gh = (const struct gre_header *)buf;

	f->f_key.k_gre_flags = gh->gre_flags;
	f->f_key.k_gre_proto = gh->gre_proto;

	if (!flow_gre_key_valid(f))
		return (0);

	hlen = sizeof(*gh);
	if (ISSET(f->f_key.k_gre_flags, htons(GRE_CP)))
		hlen += sizeof(struct gre_h_cksum);
	gkh = (const struct gre_h_key *)buf;
	hlen += sizeof(*gkh);
	if (buflen < hlen) {
		return ts->ts_short_ipproto++;
		return (-1);
	}

	f->f_key.k_gre_key = gkh->gre_key;

	return (0);
}

static int
pkt_count_ipproto(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	switch (f->f_key.k_ipproto) {
	case IPPROTO_TCP:
		return (pkt_count_tcp(ts, f, buf, buflen));
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		return (pkt_count_udp(ts, f, buf, buflen));
	case IPPROTO_GRE:
		return (pkt_count_gre(ts, f, buf, buflen));
	}

	return (0);
}

static int
pkt_count_icmp4(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct icmp *icmp4h;

	if (buflen < offsetof(struct icmp, icmp_cksum)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	icmp4h = (const struct icmp *)buf;

	f->f_key.k_icmp_type = htons(icmp4h->icmp_type);
	f->f_key.k_icmp_code = htons(icmp4h->icmp_code);
	switch (icmp4h->icmp_type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		if (buflen < offsetof(struct icmp, icmp_seq)) {
			ts->ts_short_ipproto++;
			return (-1);
		}
		f->f_key.k_icmp_id = htonl(ntohs(icmp4h->icmp_id));
		break;
	}

	return (0);
}

static void
pkt_map_v4addr(struct in6_addr *s6, struct in_addr s4)
{
	s6->s6_addr32[0] = htonl(0);
	s6->s6_addr32[1] = htonl(0);
	s6->s6_addr32[2] = htonl(0xffff);
	s6->s6_addr32[3] = s4.s_addr;
}

static int
pkt_count_ip4(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct ip *iph;
	u_int hlen;

	if (buflen < sizeof(*iph)) {
		ts->ts_short_ip4++;
		return (-1);
	}

	iph = (const struct ip *)buf;

	/* XXX check ipv and all that poop? */

	hlen = iph->ip_hl << 2;
	if (buflen < hlen) {
		ts->ts_short_ip4++;
		return (-1);
	}

	buf += hlen;
	buflen -= hlen;

	f->f_key.k_ipv = 4;
	f->f_key.k_ipproto = iph->ip_p;
	pkt_map_v4addr(&f->f_key.k_saddr, iph->ip_src);
	pkt_map_v4addr(&f->f_key.k_daddr, iph->ip_dst);

	if (f->f_key.k_ipproto == IPPROTO_ICMP)
		return (pkt_count_icmp4(ts, f, buf, buflen));

	return (pkt_count_ipproto(ts, f, buf, buflen));
}

static int
pkt_count_icmp6(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct icmp6_hdr *icmp6h;

	if (buflen < offsetof(struct icmp6_hdr, icmp6_cksum)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	icmp6h = (const struct icmp6_hdr *)buf;

	f->f_key.k_icmp_type = htons(icmp6h->icmp6_type);
	f->f_key.k_icmp_code = htons(icmp6h->icmp6_code);

	switch (icmp6h->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
	case ICMP6_ECHO_REPLY:
		if (buflen < offsetof(struct icmp6_hdr, icmp6_seq)) {
			ts->ts_short_ipproto++;
			return (-1);
		}
		f->f_key.k_icmp_id = htonl(ntohs(icmp6h->icmp6_id));
		break;
	}

	return (0);
}

static int
pkt_count_ip6(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct ip6_hdr *ip6;

	if (buflen < sizeof(*ip6)) {
		ts->ts_short_ip6++;
		return (-1);
	}

	ip6 = (const struct ip6_hdr *)buf;

	/* XXX check ipv and all that poop? */

	buf += sizeof(*ip6);
	buflen -= sizeof(*ip6);

	f->f_key.k_ipv = 6;
	f->f_key.k_ipproto = ip6->ip6_nxt;
	f->f_key.k_saddr = ip6->ip6_src;
	f->f_key.k_daddr = ip6->ip6_dst;

	if (f->f_key.k_ipproto == IPPROTO_ICMPV6)
		return (pkt_count_icmp6(ts, f, buf, buflen));

	return (pkt_count_ipproto(ts, f, buf, buflen));
}

static struct iface *
iface_find(struct collector *c, const char *ifname)
{
	struct iface key;
	struct iface *ifp;
	struct ifreq ifr;

	if (strlcpy(key.if_name, ifname, sizeof(key.if_name)) >=
	    sizeof(key.if_name)) {
		errno = ENOBUFS;
		return (NULL);
	}

	ifp = RBT_FIND(ifaces, &c->c_ifaces, &key);
	if (ifp == NULL) {
		ifp = malloc(sizeof(*ifp));
		if (ifp == NULL)
			return (NULL);

		strlcpy(ifp->if_name, ifname, sizeof(ifp->if_name));
		if (RBT_INSERT(ifaces, &c->c_ifaces, ifp) != NULL)
			lerrx(1, "ifaces tree corruption?");
	} else if (c->c_now.tv_sec < ifp->if_refresh) {
		/* still good */
		return (ifp);
	}

	memset(&ifr, 0, sizeof(ifr));
	if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		lerrx(1, "%s: ifname is too long", __func__);

	if (ioctl(c->c_sock, SIOCGVNETID, &ifr) != -1)
		ifp->if_vnetid = ifr.ifr_vnetid;

	memset(&ifr, 0, sizeof(ifr));
	if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		lerrx(1, "%s: ifname is too long", __func__);
	ifr.ifr_data = ifp->if_descr;

	if (ioctl(c->c_sock, SIOCGIFDESCR, &ifr) == -1)
		lerrx(1, "%s: SIOCGIFDESCR %s", __func__, ifname);

	ifp->if_refresh = c->c_now.tv_sec + 180;

	return (ifp);
}

static void
pkt_count(u_char *arg, const struct pcap_pkthdr *phdr, const u_char *buf)
{
	struct collector *c = (struct collector *)arg;
	struct timeslice *ts = c->c_ts;
	struct flow *f = c->c_flow;
	struct flow *of;
	struct iface *ifp;

	struct pfloghdr *hdr;
	u_int hlen = sizeof(*hdr);

	u_int buflen = phdr->caplen;
	u_int pktlen = phdr->len;

	if (buflen < hlen) {
		ts->ts_short_pfloghdr++;
		return;
	}

	memset(&f->f_key, 0, sizeof(f->f_key));

	hdr = (struct pfloghdr *)buf;

	ifp = iface_find(c, hdr->ifname);
	if (ifp == NULL) {
		lwarn("unable to find iface for %s, dropping packet",
		    hdr->ifname);
		ts->ts_mdrop++;
		return;
	}

	f->f_key.k_action = hdr->action;
	f->f_key.k_dir = hdr->dir;
	f->f_key.k_vnetid = ifp->if_vnetid;

	buf += hlen;
	buflen -= hlen;
	pktlen -= hlen;

	ts->ts_packets++;
	ts->ts_bytes += pktlen;

	f->f_packets = 1;
	f->f_bytes = pktlen;
	f->f_syns = 0;
	f->f_fins = 0;
	f->f_rsts = 0;

	switch (hdr->af) {
	case AF_INET:
		if (pkt_count_ip4(ts, f, buf, buflen) == -1)
			return;
		break;
	case AF_INET6:
		if (pkt_count_ip6(ts, f, buf, buflen) == -1)
			return;
		break;

	default:
		ts->ts_nonip++;
		return;
	}

	of = RBT_INSERT(flow_tree, &ts->ts_flow_tree, f);
	if (of == NULL) {
		struct flow *nf = malloc(sizeof(*nf));
		if (nf == NULL) {
			/* drop this packet due to lack of memory */
			RBT_REMOVE(flow_tree, &ts->ts_flow_tree, f);
			ts->ts_mdrop++;
			return;
		}
		c->c_flow = nf;

		ts->ts_flow_count++;
		TAILQ_INSERT_TAIL(&ts->ts_flow_list, f, f_entry_list);
	} else {
		of->f_packets++;
		of->f_bytes += f->f_bytes;
		of->f_syns += f->f_syns;
		of->f_fins += f->f_fins;
		of->f_rsts += f->f_rsts;
	}
}

static void
pkt_capture(int fd, short events, void *arg)
{
	struct pflogif *p = arg;
	struct collector *c = p->p_c;
	struct timeslice *ts = c->c_ts;

	if (pcap_dispatch(p->p_ph, -1, pkt_count, (u_char *)c) < 0)
		lerrx(1, "%s", pcap_geterr(p->p_ph));

	ts->ts_reads++;
}

RBT_GENERATE(flow_tree, flow, f_entry_tree, flow_cmp);
RBT_GENERATE(ifaces, iface, if_entry, iface_cmp);

/* daemon(3) clone, intended to be used in a "r"estricted environment */
int
rdaemon(int devnull)
{
	if (devnull == -1) {
		errno = EBADF;
		return (-1);
	}
	if (fcntl(devnull, F_GETFL) == -1)
		return (-1);

	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		_exit(0);
	}

	if (setsid() == -1)
		return (-1);

	(void)dup2(devnull, STDIN_FILENO);
	(void)dup2(devnull, STDOUT_FILENO);
	(void)dup2(devnull, STDERR_FILENO);
	if (devnull > 2)
		(void)close(devnull);

	return (0);
}
