PREFIX?=/usr/local
BINDIR=${PREFIX}/bin
MANDIR= ${PREFIX}/man/cat

.PATH: ${.CURDIR}/../mdnsctl ${.CURDIR}/../openbsd-compat

PROG=	mdnsserve
SRCS=	mdnsserve.c log.c mdnsl.c imsg.c imsg-buffer.c

CFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mdnsd
CFLAGS+= -I${.CURDIR}/../openbsd-compat -I/usr/local/include
LDFLAGS+= -L/usr/local/lib
LDADD+= -lutil -lyaml
DPADD+=  ${LIBUTIL} ${LIBYAML}

MAN=

.include <bsd.prog.mk>
