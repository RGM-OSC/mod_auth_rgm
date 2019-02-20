SUBDIRS = src

EXTRA_DIST = autom4 win32

install-exec-hook:
	if test "$(APXS)" != "no"; then \
		$(APXS) -i -n auth_rgm src/mod_auth_rgm.la; \
	fi

uninstall-local:
	rm -f `$(APXS) -q LIBEXECDIR`/mod_auth_rgm*;
