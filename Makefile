#
# Makefile for mod_gacl to build as a DSO module
#
SHELL = /bin/sh

MODNAME = gacl
SRC = mod_${MODNAME}.c
MODFILE = mod_${MODNAME}.so
APXS = apxs

SRC2 = mod_${MODNAME}.c
MODFILE2 = mod_${MODNAME}.la
APXS2 = apxs2

PKGFILES = ${SRC} ${SRC2} RELEASE README Makefile samples

default: ${MODFILE2}

all: ${MODFILE2}

${MODFILE2}: ${SRC2}
	${APXS2} -o $@ -c ${SRC2}

install: ${MODFILE2}
	${APXS2} -i -a -n ${MODNAME} ${MODFILE2}

clean:
	rm -rf *.o *.so *.loT *.la *.lo *.slo a.out core core.* pkg .libs

pkg: ${PKGFILES}
	d=${MODNAME}-`cat RELEASE`;			\
	mkdir $$d;					\
	cp -r ${PKGFILES} $$d;				\
	find $$d -name CVS -exec rm -rf '{}' ';';	\
	tar cvzf $$d.tar.gz $$d;			\
	rm -rf $@;					\
	mv $$d $@
