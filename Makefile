
PROG=		pflogflowd
SRCS=		pflogflowd.c
SRCS+=		log.c
MAN=

LDADD=		-lpcap -levent
DPADD=		${LIBPCAP} ${LIBEVENT}

DEBUG=		-g
WARNINGS=	Yes

.include <bsd.prog.mk>
