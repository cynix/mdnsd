PREFIX?=/usr/local
BINDIR=${PREFIX}/bin
MANDIR= ${PREFIX}/man/cat

.PATH: ${.CURDIR}/../openbsd-compat

PROG=	mdnsctl
SRCS=	mdnsctl.c parser.c mdnsl.c imsg.c imsg-buffer.c

CFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mdnsd
CFLAGS+= -I${.CURDIR}/../openbsd-compat -I/usr/local/include
LDADD+= -lutil
DPADD+=  ${LIBUTIL}

MAN=	mdnsctl.8

.include <bsd.prog.mk>
