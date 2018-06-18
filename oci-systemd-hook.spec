%global provider        github
%global provider_tld    com
%global project         projectatomic
%global repo            oci-systemd-hook
# https://github.com/projectatomic/oci-systemd-hook
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          05bd9a0cceb8ad88a2815f25911f519162181def
%global shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           %{repo}
Version:        0.1.16
Release:        1.git%{shortcommit}%{?dist}
Summary:        OCI systemd hook for docker
Group:          Applications/Text
License:        GPLv3+
URL:            https://%{import_path}
Source0:        https://%{import_path}/archive/%{commit}/%{name}-%{shortcommit}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  pkgconfig(yajl)
BuildRequires:  pkgconfig(libselinux)
BuildRequires:  pkgconfig(mount)
BuildRequires:  pcre-devel
BuildRequires:  go-md2man
Obsoletes:      %{name} <= 1.10.3-46
# golang / go-md2man not available on ppc64
ExcludeArch:    ppc64

%description
OCI systemd hooks enable running systemd in a OCI runc/docker container.

%prep
%setup -q -n %{name}-%{commit}

%build
aclocal
autoreconf -i
%configure --libexecdir=%{_libexecdir}/oci/hooks.d/
make %{?_smp_mflags}

%install
%make_install

#define license tag if not already defined
%{!?_licensedir:%global license %doc}
%files
%doc README.md
%license LICENSE
%{_mandir}/man1/%{name}.1*
%dir %{_libexecdir}/oci
%dir %{_libexecdir}/oci/hooks.d
%{_libexecdir}/oci/hooks.d/%{name}
%dir %{_usr}/share/containers/oci/hooks.d
%{_usr}/share/containers/oci/hooks.d/oci-systemd-hook.json

%changelog
* Tue May 1 2018 Dan Walsh <dwalsh@redhat.name> - 1:0.1.16-1.git05bd9a0
- Merge pull request #90 from brahim-raddahi/master
- fix invalid /etc/machine-id

* Thu Dec 21 2017 Dan Walsh <dwalsh@redhat.com> - 1:0.1.15-1.git
- Fix issue with oci-systemd-hook running in user namespaces
- fix json file to run container with proper stage field.

* Wed Sep 13 2017 Dan Walsh <dwalsh@redhat.com> - 0.1.5-1.gitde345df
- Add support for json configuration to identify when to use hook
- Needed for crio package

* Thu Feb 18 2016 Dan Walsh <dwalsh@redhat.com> - 0.1.4-1.gitde345df
- Fix up to prepare for review

* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.3
- Fix bug in man page installation
* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.2
- Add man pages
* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.1
- Initial RPM release
