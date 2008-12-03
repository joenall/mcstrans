Summary: SELinux Translation Daemon
Name: mcstrans
Version: 0.3.0
Release: 1%{?dist}
License: GPL
Group: System Environment/Daemons
Source: http://fedora.redhat.com/projects/%{name}-%{version}.tgz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: libselinux-devel >= 1.30.3-1
BuildRequires: libcap-devel pcre-devel libsepol-devel libsepol-static
Requires: pcre
Requires(pre): /sbin/chkconfig /sbin/service
Requires(post):/sbin/chkconfig /sbin/service
Provides: setransd
Obsoletes: libsetrans

%description
Security-enhanced Linux is a feature of the Linux® kernel and a number
of utilities with enhanced security functionality designed to add
mandatory access controls to Linux.  The Security-enhanced Linux
kernel contains new architectural components originally developed to
improve the security of the Flask operating system. These
architectural components provide general support for the enforcement
of many kinds of mandatory access control policies, including those
based on the concepts of Type Enforcement®, Role-based Access
Control, and Multi-level Security.

mcstrans provides an translation daemon to translate SELinux categories 
from internal representations to user defined representation.

%prep
%setup -q

%build
make clean
make CFLAGS="-g %{optflags}"

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/%{_lib} 
mkdir -p %{buildroot}/%{_libdir} 
make DESTDIR="%{buildroot}" LIBDIR="%{buildroot}%{_libdir}" SHLIBDIR="%{buildroot}/%{_lib}" install
rm -f %{buildroot}%{_sbindir}/*
rm -f %{buildroot}%{_libdir}/*.a

%clean
rm -rf %{buildroot}

%post 
chkconfig --add mcstrans
if [ -f /var/lock/subsys/mcstransd ]; then
   mv /var/lock/subsys/mcstransd /var/lock/subsys/mcstrans
fi

%preun
if [ $1 -eq 0 ]; then
   service mcstrans stop > /dev/null 2>&1
   chkconfig --del mcstrans
fi

%postun 
if [ $1 -ge 1 ]; then
   service mcstrans condrestart > /dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,0755)
%{_mandir}/man8/mcs.8.gz
/sbin/mcstransd
%{_sysconfdir}/rc.d/init.d/mcstrans

%changelog
* Wed May 7 2008 Dan Walsh <dwalsh@redhat.com> 0.2.11-1
- More fixes from Jim Meyering

* Tue May 6 2008 Dan Walsh <dwalsh@redhat.com> 0.2.10-1
- More error checking on failed strdup

* Tue May 6 2008 Dan Walsh <dwalsh@redhat.com> 0.2.9-1
- Start mcstrans before netlabel

* Mon Apr 14 2008 Dan Walsh <dwalsh@redhat.com> 0.2.8-1
- Fix error handling

* Tue Feb 12 2008 Dan Walsh <dwalsh@redhat.com> 0.2.7-2
- Rebuild for gcc 4.3

* Mon Oct 30 2007 Steve Conklin <sconklin@redhat.com> - 0.2.7-1
- Folded current patches into tarball

* Thu Oct 25 2007 Steve Conklin <sconklin@redhat.com> - 0.2.6-3
- Fixed a compile problem with max_categories

* Thu Oct 25 2007 Steve Conklin <sconklin@redhat.com> - 0.2.6-2
- Fixed some init script errors

* Thu Sep 13 2007 Dan Walsh <dwalsh@redhat.com> 0.2.6-1
- Check for max_categories and error out

* Thu Mar 1 2007 Dan Walsh <dwalsh@redhat.com> 0.2.5-1
- Fix case where s0=""

* Mon Feb 26 2007 Dan Walsh <dwalsh@redhat.com> 0.2.4-1
- Translate range if fully specified correctly

* Mon Feb 12 2007 Dan Walsh <dwalsh@redhat.com> 0.2.3-1
- Additional fix to handle ssh root/sysadm_r/s0:c1,c2
Resolves: #224637

* Mon Feb 5 2007 Dan Walsh <dwalsh@redhat.com> 0.2.1-1
- Rewrite to handle MLS properly
Resolves: #225355

* Mon Jan 29 2007 Dan Walsh <dwalsh@redhat.com> 0.1.10-2
- Cleanup memory when complete

* Mon Dec 4 2006 Dan Walsh <dwalsh@redhat.com> 0.1.10-1
- Fix Memory Leak
Resolves: #218173

* Thu Sep 21 2006 Dan Walsh <dwalsh@redhat.com> 0.1.9-1
- Add -pie
- Fix compiler warnings
- Fix Memory Leak
Resolves: #218173

* Wed Sep 13 2006 Peter Jones <pjones@redhat.com> - 0.1.8-3
- Fix subsys locking in init script

* Wed Aug 23 2006 Dan Walsh <dwalsh@redhat.com> 0.1.8-1
- Only allow one version to run

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - sh: line 0: fg: no job control
- rebuild

* Mon Jun 19 2006 Dan Walsh <dwalsh@redhat.com> 0.1.7-1
- Apply sgrubb patch to only call getpeercon on translations

* Tue Jun 6 2006 Dan Walsh <dwalsh@redhat.com> 0.1.6-1
- Exit gracefully when selinux is not enabled

* Mon May 15 2006 Dan Walsh <dwalsh@redhat.com> 0.1.5-1
- Fix sighup handling

* Mon May 15 2006 Dan Walsh <dwalsh@redhat.com> 0.1.4-1
- Add patch from sgrubb
- 	Fix 64 bit size problems
- 	Increase the open file limit
-	Make sure maximum size is not exceeded

* Fri May 12 2006 Dan Walsh <dwalsh@redhat.com> 0.1.3-1
- Move initscripts to /etc/rc.d/init.d

* Thu May 11 2006 Dan Walsh <dwalsh@redhat.com> 0.1.2-1
- Drop Privs

* Mon May 8 2006 Dan Walsh <dwalsh@redhat.com> 0.1.1-1
- Initial Version
- This daemon reuses the code from libsetrans
