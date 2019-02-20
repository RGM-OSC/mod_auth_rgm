## This is the shared library to be built
lib_LTLIBRARIES = mod_auth_eon.la

## Define some compilation parameters for the module
mod_auth_eon_la_SOURCES = mod_auth_eon.c
mod_auth_eon_la_LDFLAGS = -version-info 4:2:3 -module $(MYSQLCLIENT_LIBFLAGS)
mod_auth_eon_la_LIBADD = -l$(MYSQLCLIENT_LIB) -lz

## Add the required include files to the compiler
INCLUDES = -I$(APACHE2_INCLUDE) -I$(APR_INCLUDE) -I$(MYSQL_INCLUDE)
