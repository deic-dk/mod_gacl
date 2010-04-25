#
# Makefile for mod_gacl to build as a DSO module
#
SHELL = /bin/sh

MODNAME = gacl
MODFILE = mod_${MODNAME}.so
SRC2 = mod_${MODNAME}.c
MODFILE2 = mod_${MODNAME}.la
# You may have to set the variable below manually
APXS2=`ls /usr/bin/apxs* /usr/sbin/apxs* 2>/dev/null | head -1`

GRIDSITE_VERSION = 1.6.0
LIB_GACL=libgacl
GACL_SOURCE1 = grst_http.c
GACL_SOURCE2 = grst_xacml.c
GACL_SOURCE3 = grst_gacl.c

PKGFILES = ${SRC2} RELEASE README Makefile gacl_interface ${GACL_SOURCE1} ${GACL_SOURCE2} ${GACL_SOURCE3}

default: all

all: libgacl link module

module: ${SRC2}
	${APXS2} -o ${MODFILE} -c ${SRC2} -L. -lgacl

link:
	ln -sf ${LIB_GACL}.so.${GRIDSITE_VERSION} ${LIB_GACL}.so

libgacl: ${GACL_SOURCE1} ${GACL_SOURCE2} ${GACL_SOURCE3}
	gcc -fPIC -shared -Wl,-soname,${LIB_GACL}.so.${GRIDSITE_VERSION} -o ${LIB_GACL}.so.${GRIDSITE_VERSION} \
	-I/usr/include/libxml2 -I./gacl_interface  -L/usr/lib \
  -lxml2 ${GACL_SOURCE1} ${GACL_SOURCE2} ${GACL_SOURCE3}

install: libgacl link module
	${APXS2} -i -a -n ${MODNAME} ${MODFILE2}

clean:
	rm -rf *.o *.so *.so.* *.loT *.la *.lo *.slo a.out core core.* pkg .libs

pkg: ${PKGFILES}
	d=${MODNAME}-`cat RELEASE`;			\
	mkdir $$d;					\
	cp -r ${PKGFILES} $$d;				\
	find $$d -name CVS -exec rm -rf '{}' ';';	\
	tar cvzf $$d.tar.gz $$d;			\
	rm -rf $@;					\
	mv $$d $@
