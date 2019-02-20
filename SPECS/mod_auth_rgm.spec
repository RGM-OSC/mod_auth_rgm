Summary: Apache2 EoN Authorization
Name: mod_auth_eon
Version: 5.0
Release: 2.rgm
Group: System Environment/Daemons
License: Apache Software License
URL: http://www.eyesofnetwork.com/

Source: mod_auth_rgm-%{version}.tar.gz
Source1: auth_rgm.conf
Source2: 10-auth_rgm.conf

BuildRoot: %{_tmppath}/%{name}-root
Requires: httpd, mariadb

%description
This module is herited from mod_auth_form as implemented in Apache 2.2. As so it is based on 'mod_auth_mysql' and 'mod_auth_sim'. 
It is used to place access restrictions on a per-directory, per-user-request basis using session management. 
The module uses a MySQL database to retrieve users' group membership, maintain and validate users' sessions, and optionally user activity. 
This version has ported the initial module to be compliant with the new Apache 2.4 API.

%prep
%setup -q

%build
%configure MYSQLCLIENT_LIBPATH=/usr/lib64 APACHE2_INCLUDE=/usr/include/httpd/ CFLAGS="`apr-1-config --cppflags --cflags`"
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_libdir}/httpd/modules
install -m755 src/.libs/%{name}.so $RPM_BUILD_ROOT%{_libdir}/httpd/modules

# Install the config file
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.modules.d
install -m 644 %SOURCE1 $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/
install -m 644 %SOURCE2 $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.modules.d/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README
%{_libdir}/httpd/modules/*.so
%config(noreplace) %{_sysconfdir}/httpd/conf.d/auth_rgm.conf
%config(noreplace) %{_sysconfdir}/httpd/conf.modules.d/10-auth_rgm.conf

%changelog
* Wed Feb 19 2019 Michael Aubertin <maubertin@fr.scc.com> - 5.0-2.rgm
- Initial fork
* Tue Sep 27 2016 Jean-Philippe Levy <jeanphilippe.levy@gmail.com> - 5.0-2.eon
- user_name at the end of cookie chain fix

* Wed May 18 2016 Jean-Philippe Levy <jeanphilippe.levy@gmail.com> - 5.0-1.eon
- AuthEonDefaultUser : set default remote user for all websites
- AuthEonRemoteUser  : set remote user by location or directory
- user_name size fix

* Wed May 04 2016 Michael Aubertin <michael.aubertin@gmail.com> - 5.0-0.eon
- Build against 5.0 to align version. Asked by JP Levy ;)

* Mon Apr 04 2016 Jeremie Bernard <gremimail@gmail.com> - 4.2-3.eon
- ported mod_auth_form for EyesOfNetwork appliance using now Apache 2.4
- renamed mod_auth_form to mod_auth_eon

* Mon Sep 08 2008 Jean-Philippe Levy <jeanphilippe.levy@gmail.com> - 2.05-0.eon
- packaged for EyesOfNetwork appliance
