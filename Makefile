.include "Makefile.inc"

PROG=	evilhijack
SRCS=	evilhijack.c
MAN=

.if defined(PREFIX)
BINDIR?=	${PREFIX}/sbin
.else
BINDIR?=	/usr/sbin
.endif

CFLAGS+= 	-I${SRCDIR}/libexec/rtld-elf \
		-I${SRCDIR}/libexec/rtld-elf/${MACHINE_ARCH}

LDADD+=		-lhijack

.include <bsd.prog.mk>
