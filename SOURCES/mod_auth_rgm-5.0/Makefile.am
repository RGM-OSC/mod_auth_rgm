SUBDIRS = src

EXTRA_DIST = autom4 win32

install-exec-hook:
	if test "$(APXS)" != "no"; then \
		$(APXS) -i -n auth_eon src/mod_auth_eon.la; \
	fi

uninstall-local:
	rm -f `$(APXS) -q LIBEXECDIR`/mod_auth_eon*;
