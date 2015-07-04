PREFIX?=/usr/local
BINDIR=${PREFIX}/bin
MANDIR= ${PREFIX}/man/cat

.PATH: ${.CURDIR}/../mdnsctl ${.CURDIR}/../openbsd-compat

PROG=	mdnsd
SRCS=	log.c mdnsd.c kiface.c interface.c packet.c \
	control.c mdns.c mdnsl.c imsg.c imsg-buffer.c

MAN=	mdnsd.8

CFLAGS+= -g -Wall -I${.CURDIR} -I../
CFLAGS+= -I${.CURDIR}/../openbsd-compat -I/usr/local/include
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
LDFLAGS+= -L/usr/local/lib
LDADD+= -levent -lutil
DPADD+= ${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
.include <bsd.man.mk>
