const TEST_REPORT = {
  "apiVersion": "aquasecurity.github.io/v1alpha1",
  "kind": "VulnerabilityReport",
  "metadata": {
    "annotations": {
      "trivy-operator.aquasecurity.github.io/report-ttl": "24h0m0s"
    },
    "creationTimestamp": "2022-10-21T02:36:14Z",
    "generation": 1,
    "labels": {
      "resource-spec-hash": "d5c99cb6",
      "trivy-operator.container.name": "nginx",
      "trivy-operator.resource.kind": "ReplicaSet",
      "trivy-operator.resource.name": "nginx-67cddc5c44",
      "trivy-operator.resource.namespace": "default"
    },
    "name": "replicaset-nginx-67cddc5c44-nginx",
    "namespace": "default",
    "ownerReferences": [
      {
        "apiVersion": "apps/v1",
        "blockOwnerDeletion": false,
        "controller": true,
        "kind": "ReplicaSet",
        "name": "nginx-67cddc5c44",
        "uid": "2bc9fba1-6f24-4af3-a91b-7a150b813a1b"
      }
    ],
    "resourceVersion": "183501",
    "uid": "ee208ebf-9b3d-48f1-b98c-5a19f755196e"
  },
  "report": {
    "artifact": {
      "repository": "library/nginx",
      "tag": "1.15"
    },
    "registry": {
      "server": "index.docker.io"
    },
    "scanner": {
      "name": "Trivy",
      "vendor": "Aqua Security",
      "version": "0.31.3"
    },
    "summary": {
      "criticalCount": 59,
      "highCount": 105,
      "lowCount": 163,
      "mediumCount": 84,
      "noneCount": 0,
      "unknownCount": 7
    },
    "updateTimestamp": "2022-10-21T02:36:14Z",
    "vulnerabilities": [
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L"
          },
          "redhat": {
            "V3Score": 5.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L"
          }
        },
        "description": "APT had several integer overflows and underflows while parsing .deb packages, aka GHSL-2020-168 GHSL-2020-169, in files apt-pkg/contrib/extracttar.cc, apt-pkg/deb/debfile.cc, and apt-pkg/contrib/arfile.cc. This issue affects: apt 1.2.32ubuntu0 versions prior to 1.2.32ubuntu0.2; 1.6.12ubuntu0 versions prior to 1.6.12ubuntu0.2; 2.0.2ubuntu0 versions prior to 2.0.2ubuntu0.2; 2.1.10ubuntu0 versions prior to 2.1.10ubuntu0.1;",
        "fixedVersion": "1.4.11",
        "installedVersion": "1.4.9",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-27350",
          "https://bugs.launchpad.net/bugs/1899193",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27350",
          "https://security.netapp.com/advisory/ntap-20210108-0005/",
          "https://ubuntu.com/security/notices/USN-4667-1",
          "https://ubuntu.com/security/notices/USN-4667-2",
          "https://usn.ubuntu.com/usn/usn-4667-1",
          "https://www.debian.org/security/2020/dsa-4808"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-27350",
        "resource": "apt",
        "score": 5.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "apt: integer overflows and underflows while parsing .deb packages",
        "vulnerabilityID": "CVE-2020-27350"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Missing input validation in the ar/tar implementations of APT before version 2.1.2 could result in denial of service when processing specially crafted deb files.",
        "fixedVersion": "1.4.10",
        "installedVersion": "1.4.9",
        "links": [
          "https://bugs.launchpad.net/bugs/1878177",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3810",
          "https://github.com/Debian/apt/issues/111",
          "https://github.com/julian-klode/apt/commit/de4efadc3c92e26d37272fd310be148ec61dcf36",
          "https://lists.debian.org/debian-security-announce/2020/msg00089.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U4PEH357MZM2SUGKETMEHMSGQS652QHH/",
          "https://salsa.debian.org/apt-team/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6",
          "https://salsa.debian.org/jak/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6",
          "https://tracker.debian.org/news/1144109/accepted-apt-212-source-into-unstable/",
          "https://ubuntu.com/security/notices/USN-4359-1",
          "https://ubuntu.com/security/notices/USN-4359-2",
          "https://usn.ubuntu.com/4359-1/",
          "https://usn.ubuntu.com/4359-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-3810",
        "resource": "apt",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "Missing input validation in the ar/tar implementations of APT before v ...",
        "vulnerabilityID": "CVE-2020-3810"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
            "V3Score": 3.7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
          }
        },
        "description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
        "fixedVersion": "",
        "installedVersion": "1.4.9",
        "links": [
          "https://access.redhat.com/security/cve/cve-2011-3374",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=642480",
          "https://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-3374.html",
          "https://seclists.org/fulldisclosure/2011/Sep/221",
          "https://security-tracker.debian.org/tracker/CVE-2011-3374",
          "https://snyk.io/vuln/SNYK-LINUX-APT-116518",
          "https://ubuntu.com/security/CVE-2011-3374"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2011-3374",
        "resource": "apt",
        "score": 3.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "It was found that apt-key in apt, all versions, do not correctly valid ...",
        "vulnerabilityID": "CVE-2011-3374"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.",
        "fixedVersion": "",
        "installedVersion": "4.4-5",
        "links": [
          "http://packetstormsecurity.com/files/155498/Bash-5.0-Patch-11-Privilege-Escalation.html",
          "https://access.redhat.com/security/cve/CVE-2019-18276",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18276",
          "https://github.com/bminor/bash/commit/951bdaad7a18cc0dc1036bba86b18b90874d39ff",
          "https://linux.oracle.com/cve/CVE-2019-18276.html",
          "https://linux.oracle.com/errata/ELSA-2021-1679.html",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-18276",
          "https://security.gentoo.org/glsa/202105-34",
          "https://security.netapp.com/advisory/ntap-20200430-0003/",
          "https://ubuntu.com/security/notices/USN-5380-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.youtube.com/watch?v=-wGtxJ8opa8"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-18276",
        "resource": "bash",
        "score": 7.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "bash: when effective UID is not equal to its real UID the saved UID is not dropped",
        "vulnerabilityID": "CVE-2019-18276"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/02/27/1",
          "http://www.openwall.com/lists/oss-security/2016/02/27/2",
          "https://access.redhat.com/security/cve/CVE-2016-2779",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2779",
        "resource": "bsdutils",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: runuser tty hijack via TIOCSTI ioctl",
        "vulnerabilityID": "CVE-2016-2779"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-37600",
          "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
          "https://github.com/karelzak/util-linux/issues/1395",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
          "https://security.netapp.com/advisory/ntap-20210902-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-37600",
        "resource": "bsdutils",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
        "vulnerabilityID": "CVE-2021-37600"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0563",
          "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
          "https://security.netapp.com/advisory/ntap-20220331-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0563",
        "resource": "bsdutils",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
        "vulnerabilityID": "CVE-2022-0563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:P/A:N",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "8.26-3",
        "links": [
          "http://seclists.org/oss-sec/2016/q1/452",
          "http://www.openwall.com/lists/oss-security/2016/02/28/2",
          "http://www.openwall.com/lists/oss-security/2016/02/28/3",
          "https://access.redhat.com/security/cve/CVE-2016-2781",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2781",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lore.kernel.org/patchwork/patch/793178/",
          "https://nvd.nist.gov/vuln/detail/CVE-2016-2781"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2781",
        "resource": "coreutils",
        "score": 8.6,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "coreutils: Non-privileged session can escape to the parent session in chroot",
        "vulnerabilityID": "CVE-2016-2781"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:N",
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N"
          },
          "redhat": {
            "V3Score": 4.2,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L"
          }
        },
        "description": "In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file with a symlink during use of the POSIX \"-R -L\" options, which allows local users to modify the ownership of arbitrary files by leveraging a race condition.",
        "fixedVersion": "",
        "installedVersion": "8.26-3",
        "links": [
          "http://lists.gnu.org/archive/html/coreutils/2017-12/msg00045.html",
          "https://access.redhat.com/security/cve/CVE-2017-18018"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-18018",
        "resource": "coreutils",
        "score": 4.2,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "coreutils: race condition vulnerability in chown and chgrp",
        "vulnerabilityID": "CVE-2017-18018"
      },
      {
        "fixedVersion": "2017.5+deb9u2",
        "installedVersion": "2017.5",
        "resource": "debian-archive-keyring",
        "severity": "UNKNOWN",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "debian-archive-keyring - security update",
        "vulnerabilityID": "DLA-2948-1"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "Dpkg::Source::Archive in dpkg, the Debian package management system, before version 1.21.8, 1.20.10, 1.19.8, 1.18.26 is prone to a directory traversal vulnerability. When extracting untrusted source packages in v2 and v3 source package formats that include a debian.tar, the in-place extraction can lead to directory traversal situations on specially crafted orig.tar and debian.tar tarballs.",
        "fixedVersion": "1.18.26",
        "installedVersion": "1.18.25",
        "links": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1664",
          "https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=1f23dddc17f69c9598477098c7fb9936e15fa495",
          "https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=58814cacee39c4ce9e2cd0e3a3b9b57ad437eff5",
          "https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=7a6c03cb34d4a09f35df2f10779cbf1b70a5200b",
          "https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be",
          "https://lists.debian.org/debian-lts-announce/2022/05/msg00033.html",
          "https://lists.debian.org/debian-security-announce/2022/msg00115.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1664",
          "https://security.netapp.com/advisory/ntap-20221007-0002/",
          "https://ubuntu.com/security/notices/USN-5446-1",
          "https://ubuntu.com/security/notices/USN-5446-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1664",
        "resource": "dpkg",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "Dpkg::Source::Archive in dpkg, the Debian package management system, b ...",
        "vulnerabilityID": "CVE-2022-1664"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
        "fixedVersion": "",
        "installedVersion": "1.43.4-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1304",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
          "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1304",
          "https://ubuntu.com/security/notices/USN-5464-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1304",
        "resource": "e2fslibs",
        "score": 5.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
        "vulnerabilityID": "CVE-2022-1304"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An exploitable code execution vulnerability exists in the quota file functionality of E2fsprogs 1.45.3. A specially crafted ext4 partition can cause an out-of-bounds write on the heap, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
        "fixedVersion": "1.43.4-2+deb9u1",
        "installedVersion": "1.43.4-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-5094",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5094",
          "https://linux.oracle.com/cve/CVE-2019-5094.html",
          "https://linux.oracle.com/errata/ELSA-2020-4011.html",
          "https://lists.debian.org/debian-lts-announce/2019/09/msg00029.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-5094",
          "https://seclists.org/bugtraq/2019/Sep/58",
          "https://security.gentoo.org/glsa/202003-05",
          "https://security.netapp.com/advisory/ntap-20200115-0002/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0887",
          "https://ubuntu.com/security/notices/USN-4142-1",
          "https://ubuntu.com/security/notices/USN-4142-2",
          "https://usn.ubuntu.com/4142-1/",
          "https://usn.ubuntu.com/4142-2/",
          "https://www.debian.org/security/2019/dsa-4535"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5094",
        "resource": "e2fslibs",
        "score": 6.4,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: Crafted ext4 partition leads to out-of-bounds write",
        "vulnerabilityID": "CVE-2019-5094"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.4,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H"
          }
        },
        "description": "A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
        "fixedVersion": "1.43.4-2+deb9u2",
        "installedVersion": "1.43.4-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00004.html",
          "https://access.redhat.com/security/cve/CVE-2019-5188",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5188",
          "https://linux.oracle.com/cve/CVE-2019-5188.html",
          "https://linux.oracle.com/errata/ELSA-2020-4011.html",
          "https://lists.debian.org/debian-lts-announce/2020/03/msg00030.html",
          "https://lists.debian.org/debian-lts-announce/2020/07/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-5188",
          "https://security.netapp.com/advisory/ntap-20220506-0001/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0973",
          "https://ubuntu.com/security/notices/USN-4249-1",
          "https://usn.ubuntu.com/4249-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5188",
        "resource": "e2fslibs",
        "score": 7.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: Out-of-bounds write in e2fsck/rehash.c",
        "vulnerabilityID": "CVE-2019-5188"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
        "fixedVersion": "",
        "installedVersion": "1.43.4-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1304",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
          "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1304",
          "https://ubuntu.com/security/notices/USN-5464-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1304",
        "resource": "e2fsprogs",
        "score": 5.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
        "vulnerabilityID": "CVE-2022-1304"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An exploitable code execution vulnerability exists in the quota file functionality of E2fsprogs 1.45.3. A specially crafted ext4 partition can cause an out-of-bounds write on the heap, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
        "fixedVersion": "1.43.4-2+deb9u1",
        "installedVersion": "1.43.4-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-5094",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5094",
          "https://linux.oracle.com/cve/CVE-2019-5094.html",
          "https://linux.oracle.com/errata/ELSA-2020-4011.html",
          "https://lists.debian.org/debian-lts-announce/2019/09/msg00029.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-5094",
          "https://seclists.org/bugtraq/2019/Sep/58",
          "https://security.gentoo.org/glsa/202003-05",
          "https://security.netapp.com/advisory/ntap-20200115-0002/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0887",
          "https://ubuntu.com/security/notices/USN-4142-1",
          "https://ubuntu.com/security/notices/USN-4142-2",
          "https://usn.ubuntu.com/4142-1/",
          "https://usn.ubuntu.com/4142-2/",
          "https://www.debian.org/security/2019/dsa-4535"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5094",
        "resource": "e2fsprogs",
        "score": 6.4,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: Crafted ext4 partition leads to out-of-bounds write",
        "vulnerabilityID": "CVE-2019-5094"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.4,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H"
          }
        },
        "description": "A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
        "fixedVersion": "1.43.4-2+deb9u2",
        "installedVersion": "1.43.4-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00004.html",
          "https://access.redhat.com/security/cve/CVE-2019-5188",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5188",
          "https://linux.oracle.com/cve/CVE-2019-5188.html",
          "https://linux.oracle.com/errata/ELSA-2020-4011.html",
          "https://lists.debian.org/debian-lts-announce/2020/03/msg00030.html",
          "https://lists.debian.org/debian-lts-announce/2020/07/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-5188",
          "https://security.netapp.com/advisory/ntap-20220506-0001/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0973",
          "https://ubuntu.com/security/notices/USN-4249-1",
          "https://usn.ubuntu.com/4249-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5188",
        "resource": "e2fsprogs",
        "score": 7.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: Out-of-bounds write in e2fsck/rehash.c",
        "vulnerabilityID": "CVE-2019-5188"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H"
          }
        },
        "description": "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
        "fixedVersion": "",
        "installedVersion": "6.3.0-18+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-12886",
          "https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379\u0026view=markup",
          "https://www.gnu.org/software/gcc/gcc-8/changes.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-12886",
        "resource": "gcc-6-base",
        "score": 6.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gcc: spilling of stack protection address in cfgexpand.c and function.c leads to stack-overflow protection bypass",
        "vulnerabilityID": "CVE-2018-12886"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "An issue was discovered in GNU gettext 0.19.8. There is a double free in default_add_message in read-catalog.c, related to an invalid free in po_gram_parse in po-gram-gen.y, as demonstrated by lt-msgfmt.",
        "fixedVersion": "",
        "installedVersion": "0.19.8.1-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00061.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00065.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00025.html",
          "https://access.redhat.com/errata/RHSA-2019:3643",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-18751.json",
          "https://access.redhat.com/security/cve/CVE-2018-18751",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18751",
          "https://errata.almalinux.org/8/ALSA-2019-3643.html",
          "https://github.com/CCCCCrash/POCs/tree/master/Bin/Tools-gettext-0.19.8.1/doublefree",
          "https://github.com/CCCCCrash/POCs/tree/master/Bin/Tools-gettext-0.19.8.1/heapcorruption",
          "https://linux.oracle.com/cve/CVE-2018-18751.html",
          "https://linux.oracle.com/errata/ELSA-2020-1138.html",
          "https://ubuntu.com/security/notices/USN-3815-1",
          "https://ubuntu.com/security/notices/USN-3815-2",
          "https://usn.ubuntu.com/3815-1/",
          "https://usn.ubuntu.com/3815-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-18751",
        "resource": "gettext-base",
        "score": 4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gettext: double free in default_add_message in read-catalog.c",
        "vulnerabilityID": "CVE-2018-18751"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          }
        },
        "description": "GnuPG version 2.1.12 - 2.2.11 contains a Cross ite Request Forgery (CSRF) vulnerability in dirmngr that can result in Attacker controlled CSRF, Information Disclosure, DoS. This attack appear to be exploitable via Victim must perform a WKD request, e.g. enter an email address in the composer window of Thunderbird/Enigmail. This vulnerability appears to have been fixed in after commit 4a4bb874f63741026bd26264c43bb32b1099f060.",
        "fixedVersion": "",
        "installedVersion": "2.1.18-8~deb9u4",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-1000858.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-13050.json",
          "https://access.redhat.com/security/cve/CVE-2018-1000858",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858",
          "https://errata.almalinux.org/8/ALSA-2020-4490.html",
          "https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html",
          "https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html",
          "https://ubuntu.com/security/notices/USN-3853-1",
          "https://usn.ubuntu.com/3853-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-1000858",
        "resource": "gpgv",
        "score": 5.4,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gnupg2: Cross site request forgery in dirmngr resulting in an information disclosure or denial of service",
        "vulnerabilityID": "CVE-2018-1000858"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N"
          },
          "redhat": {
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"
          }
        },
        "description": "GnuPG through 2.3.6, in unusual situations where an attacker possesses any secret-key information from a victim's keyring and other constraints (e.g., use of GPGME) are met, allows signature forgery via injection into the status line.",
        "fixedVersion": "",
        "installedVersion": "2.1.18-8~deb9u4",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/07/02/1",
          "https://access.redhat.com/errata/RHSA-2022:6602",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-34903.json",
          "https://access.redhat.com/security/cve/CVE-2022-34903",
          "https://bugs.debian.org/1014157",
          "https://bugzilla.redhat.com/2102868",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-34903",
          "https://dev.gnupg.org/T6027",
          "https://errata.almalinux.org/9/ALSA-2022-6602.html",
          "https://linux.oracle.com/cve/CVE-2022-34903.html",
          "https://linux.oracle.com/errata/ELSA-2022-6602.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRLWJQ76A4UKHI3Q36BKSJKS4LFLQO33/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NPTAR76EIZY7NQFENSOZO7U473257OVZ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VN63GBTMRWO36Y7BKA2WQHROAKCXKCBL/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU64FUVG2PRZBSHFOQRSP7KDVEIZ23OS/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-34903",
          "https://security.netapp.com/advisory/ntap-20220826-0005/",
          "https://ubuntu.com/security/notices/USN-5503-1",
          "https://ubuntu.com/security/notices/USN-5503-2",
          "https://www.debian.org/security/2022/dsa-5174",
          "https://www.openwall.com/lists/oss-security/2022/06/30/1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-34903",
        "resource": "gpgv",
        "score": 5.9,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gpg: Signature spoofing via status line injection",
        "vulnerabilityID": "CVE-2022-34903"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 2.2,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N"
          }
        },
        "description": "GnuPG 2.2.4 and 2.2.5 does not enforce a configuration in which key certification requires an offline master Certify key, which results in apparently valid certifications that occurred only with access to a signing subkey.",
        "fixedVersion": "",
        "installedVersion": "2.1.18-8~deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-9234",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9234",
          "https://dev.gnupg.org/T3844",
          "https://ubuntu.com/security/notices/USN-3675-1",
          "https://usn.ubuntu.com/3675-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-9234",
        "resource": "gpgv",
        "score": 2.2,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "GnuPG: Unenforced configuration allows for apparently valid certifications actually signed by signing subkeys",
        "vulnerabilityID": "CVE-2018-9234"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the way certificate signatures could be forged using collisions found in the SHA-1 algorithm. An attacker could use this weakness to create forged certificate signatures. This issue affects GnuPG versions before 2.2.18.",
        "fixedVersion": "",
        "installedVersion": "2.1.18-8~deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-14855",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-14855",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14855",
          "https://dev.gnupg.org/T4755",
          "https://eprint.iacr.org/2020/014.pdf",
          "https://lists.gnupg.org/pipermail/gnupg-announce/2019q4/000442.html",
          "https://rwc.iacr.org/2020/slides/Leurent.pdf",
          "https://ubuntu.com/security/notices/USN-4516-1",
          "https://usn.ubuntu.com/4516-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-14855",
        "resource": "gpgv",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gnupg2: OpenPGP Key Certification Forgeries with SHA-1",
        "vulnerabilityID": "CVE-2019-14855"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An arbitrary file write vulnerability was found in GNU gzip's zgrep utility. When zgrep is applied on the attacker's chosen file name (for example, a crafted file name), this can overwrite an attacker's content to an arbitrary attacker-selected file. This flaw occurs due to insufficient validation when processing filenames with two or more newlines where selected content and the target file names are embedded in crafted multi-line file names. This flaw allows a remote, low privileged attacker to force zgrep to write arbitrary files on the system.",
        "fixedVersion": "1.6-5+deb9u1",
        "installedVersion": "1.6-5",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-1271.json",
          "https://access.redhat.com/security/cve/CVE-2022-1271",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2073310",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1271",
          "https://errata.almalinux.org/8/ALSA-2022-1537.html",
          "https://git.tukaani.org/?p=xz.git;a=commit;h=69d1b3fc29677af8ade8dc15dba83f0589cb63d6",
          "https://linux.oracle.com/cve/CVE-2022-1271.html",
          "https://linux.oracle.com/errata/ELSA-2022-5052.html",
          "https://lists.gnu.org/r/bug-gzip/2022-04/msg00011.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1271",
          "https://security-tracker.debian.org/tracker/CVE-2022-1271",
          "https://security.gentoo.org/glsa/202209-01",
          "https://security.netapp.com/advisory/ntap-20220930-0006/",
          "https://tukaani.org/xz/xzgrep-ZDI-CAN-16587.patch",
          "https://ubuntu.com/security/notices/USN-5378-1",
          "https://ubuntu.com/security/notices/USN-5378-2",
          "https://ubuntu.com/security/notices/USN-5378-3",
          "https://ubuntu.com/security/notices/USN-5378-4",
          "https://www.openwall.com/lists/oss-security/2022/04/07/8"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1271",
        "resource": "gzip",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gzip: arbitrary-file-write vulnerability",
        "vulnerabilityID": "CVE-2022-1271"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L"
          },
          "redhat": {
            "V3Score": 5.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L"
          }
        },
        "description": "APT had several integer overflows and underflows while parsing .deb packages, aka GHSL-2020-168 GHSL-2020-169, in files apt-pkg/contrib/extracttar.cc, apt-pkg/deb/debfile.cc, and apt-pkg/contrib/arfile.cc. This issue affects: apt 1.2.32ubuntu0 versions prior to 1.2.32ubuntu0.2; 1.6.12ubuntu0 versions prior to 1.6.12ubuntu0.2; 2.0.2ubuntu0 versions prior to 2.0.2ubuntu0.2; 2.1.10ubuntu0 versions prior to 2.1.10ubuntu0.1;",
        "fixedVersion": "1.4.11",
        "installedVersion": "1.4.9",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-27350",
          "https://bugs.launchpad.net/bugs/1899193",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27350",
          "https://security.netapp.com/advisory/ntap-20210108-0005/",
          "https://ubuntu.com/security/notices/USN-4667-1",
          "https://ubuntu.com/security/notices/USN-4667-2",
          "https://usn.ubuntu.com/usn/usn-4667-1",
          "https://www.debian.org/security/2020/dsa-4808"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-27350",
        "resource": "libapt-pkg5.0",
        "score": 5.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "apt: integer overflows and underflows while parsing .deb packages",
        "vulnerabilityID": "CVE-2020-27350"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Missing input validation in the ar/tar implementations of APT before version 2.1.2 could result in denial of service when processing specially crafted deb files.",
        "fixedVersion": "1.4.10",
        "installedVersion": "1.4.9",
        "links": [
          "https://bugs.launchpad.net/bugs/1878177",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3810",
          "https://github.com/Debian/apt/issues/111",
          "https://github.com/julian-klode/apt/commit/de4efadc3c92e26d37272fd310be148ec61dcf36",
          "https://lists.debian.org/debian-security-announce/2020/msg00089.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U4PEH357MZM2SUGKETMEHMSGQS652QHH/",
          "https://salsa.debian.org/apt-team/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6",
          "https://salsa.debian.org/jak/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6",
          "https://tracker.debian.org/news/1144109/accepted-apt-212-source-into-unstable/",
          "https://ubuntu.com/security/notices/USN-4359-1",
          "https://ubuntu.com/security/notices/USN-4359-2",
          "https://usn.ubuntu.com/4359-1/",
          "https://usn.ubuntu.com/4359-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-3810",
        "resource": "libapt-pkg5.0",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "Missing input validation in the ar/tar implementations of APT before v ...",
        "vulnerabilityID": "CVE-2020-3810"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
            "V3Score": 3.7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
          }
        },
        "description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
        "fixedVersion": "",
        "installedVersion": "1.4.9",
        "links": [
          "https://access.redhat.com/security/cve/cve-2011-3374",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=642480",
          "https://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-3374.html",
          "https://seclists.org/fulldisclosure/2011/Sep/221",
          "https://security-tracker.debian.org/tracker/CVE-2011-3374",
          "https://snyk.io/vuln/SNYK-LINUX-APT-116518",
          "https://ubuntu.com/security/CVE-2011-3374"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2011-3374",
        "resource": "libapt-pkg5.0",
        "score": 3.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "It was found that apt-key in apt, all versions, do not correctly valid ...",
        "vulnerabilityID": "CVE-2011-3374"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/02/27/1",
          "http://www.openwall.com/lists/oss-security/2016/02/27/2",
          "https://access.redhat.com/security/cve/CVE-2016-2779",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2779",
        "resource": "libblkid1",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: runuser tty hijack via TIOCSTI ioctl",
        "vulnerabilityID": "CVE-2016-2779"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-37600",
          "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
          "https://github.com/karelzak/util-linux/issues/1395",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
          "https://security.netapp.com/advisory/ntap-20210902-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-37600",
        "resource": "libblkid1",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
        "vulnerabilityID": "CVE-2021-37600"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0563",
          "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
          "https://security.netapp.com/advisory/ntap-20220331-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0563",
        "resource": "libblkid1",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
        "vulnerabilityID": "CVE-2022-0563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "nlist.c in libbsd before 0.10.0 has an out-of-bounds read during a comparison for a symbol name from the string table (strtab).",
        "fixedVersion": "0.8.3-1+deb9u1",
        "installedVersion": "0.8.3-1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00043.html",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20367",
          "https://gitlab.freedesktop.org/libbsd/libbsd/commit/9d917aad37778a9f4a96ba358415f077f3f36f3b",
          "https://lists.apache.org/thread.html/r0e913668380f59bcbd14fdd8ae8d24f95f99995e290cd18a7822c6e5@%3Cdev.tomee.apache.org%3E",
          "https://lists.apache.org/thread.html/ra781e51cf1ec40381c98cddc073b3576fb56c3978f4564d2fa431550@%3Cdev.tomee.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2021/02/msg00027.html",
          "https://lists.freedesktop.org/archives/libbsd/2019-August/000229.html",
          "https://ubuntu.com/security/notices/USN-4243-1",
          "https://usn.ubuntu.com/4243-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-20367",
        "resource": "libbsd0",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "nlist.c in libbsd before 0.10.0 has an out-of-bounds read during a com ...",
        "vulnerabilityID": "CVE-2019-20367"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "BZ2_decompress in decompress.c in bzip2 through 1.0.6 has an out-of-bounds write when there are many selectors.",
        "fixedVersion": "",
        "installedVersion": "1.0.6-8.1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00040.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00050.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00078.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00000.html",
          "http://packetstormsecurity.com/files/153644/Slackware-Security-Advisory-bzip2-Updates.html",
          "http://packetstormsecurity.com/files/153957/FreeBSD-Security-Advisory-FreeBSD-SA-19-18.bzip2.html",
          "https://access.redhat.com/security/cve/CVE-2019-12900",
          "https://bugs.launchpad.net/ubuntu/+source/bzip2/+bug/1834494",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12900",
          "https://gitlab.com/federicomenaquintero/bzip2/commit/74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc",
          "https://lists.apache.org/thread.html/ra0adb9653c7de9539b93cc8434143b655f753b9f60580ff260becb2b@%3Cusers.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/rce8cd8c30f60604b580ea01bebda8a671a25c9a1629f409fc24e7774@%3Cuser.flink.apache.org%3E",
          "https://lists.apache.org/thread.html/rda98305669476c4d90cc8527c4deda7e449019dd1fe9936b56671dd4@%3Cuser.flink.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2019/06/msg00021.html",
          "https://lists.debian.org/debian-lts-announce/2019/07/msg00014.html",
          "https://lists.debian.org/debian-lts-announce/2019/10/msg00012.html",
          "https://lists.debian.org/debian-lts-announce/2019/10/msg00018.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-12900",
          "https://seclists.org/bugtraq/2019/Aug/4",
          "https://seclists.org/bugtraq/2019/Jul/22",
          "https://security.FreeBSD.org/advisories/FreeBSD-SA-19:18.bzip2.asc",
          "https://support.f5.com/csp/article/K68713584?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/notices/USN-4038-1",
          "https://ubuntu.com/security/notices/USN-4038-2",
          "https://ubuntu.com/security/notices/USN-4038-3",
          "https://ubuntu.com/security/notices/USN-4038-4",
          "https://ubuntu.com/security/notices/USN-4146-1",
          "https://ubuntu.com/security/notices/USN-4146-2",
          "https://usn.ubuntu.com/4038-1/",
          "https://usn.ubuntu.com/4038-2/",
          "https://usn.ubuntu.com/4146-1/",
          "https://usn.ubuntu.com/4146-2/",
          "https://www.oracle.com/security-alerts/cpuoct2020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-12900",
        "resource": "libbz2-1.0",
        "score": 4,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "bzip2: out-of-bounds write in function BZ2_decompress",
        "vulnerabilityID": "CVE-2019-12900"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "An integer overflow in the implementation of the posix_memalign in memalign functions in the GNU C Library (aka glibc or libc6) 2.26 and earlier could cause these functions to return a pointer to a heap area that is too small, potentially leading to heap corruption.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://bugs.debian.org/878159",
          "http://www.securityfocus.com/bid/102912",
          "https://access.redhat.com/errata/RHBA-2019:0327",
          "https://access.redhat.com/errata/RHSA-2018:3092",
          "https://access.redhat.com/security/cve/CVE-2018-6485",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485",
          "https://linux.oracle.com/cve/CVE-2018-6485.html",
          "https://linux.oracle.com/errata/ELSA-2018-3092.html",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22343",
          "https://ubuntu.com/security/notices/USN-4218-1",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4218-1/",
          "https://usn.ubuntu.com/4416-1/",
          "https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6485",
        "resource": "libc-bin",
        "score": 5.3,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Integer overflow in posix_memalign in memalign functions",
        "vulnerabilityID": "CVE-2018-6485"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "The malloc implementation in the GNU C Library (aka glibc or libc6), from version 2.24 to 2.26 on powerpc, and only in version 2.26 on i386, did not properly handle malloc calls with arguments close to SIZE_MAX and could return a pointer to a heap region that is smaller than requested, eventually leading to heap corruption.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-6551",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22774",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6551",
        "resource": "libc-bin",
        "score": 5.3,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: integer overflow in malloc functions",
        "vulnerabilityID": "CVE-2018-6551"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, proceed_next_node in posix/regexec.c has a heap-based buffer over-read via an attempted case-insensitive regular-expression match.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/107160",
          "https://access.redhat.com/security/cve/CVE-2019-9169",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10278",
          "https://linux.oracle.com/cve/CVE-2019-9169.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-9169",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24114",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9",
          "https://support.f5.com/csp/article/K54823184",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-9169",
        "resource": "libc-bin",
        "score": 6.5,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: regular-expression match via proceed_next_node in posix/regexec.c leads to heap-based buffer over-read",
        "vulnerabilityID": "CVE-2019-9169"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The mq_notify function in the GNU C Library (aka glibc) versions 2.32 and 2.33 has a use-after-free. It may use the notification thread attributes object (passed through its struct sigevent parameter) after it has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified other impact.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-33574",
          "https://linux.oracle.com/cve/CVE-2021-33574.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-33574",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210629-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27896",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-33574",
        "resource": "libc-bin",
        "score": 5.9,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: mq_notify does not handle separately allocated thread attributes",
        "vulnerabilityID": "CVE-2021-33574"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in a denial of service or disclosure of information. This occurs because atoi was used but strtoul should have been used to ensure correct calculations.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json",
          "https://access.redhat.com/security/cve/CVE-2021-35942",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942",
          "https://linux.oracle.com/cve/CVE-2021-35942.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-35942",
          "https://security.gentoo.org/glsa/202208-24",
          "https://security.netapp.com/advisory/ntap-20210827-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28011",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c",
          "https://sourceware.org/glibc/wiki/Security%20Exceptions",
          "https://ubuntu.com/security/notices/USN-5310-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-35942",
        "resource": "libc-bin",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Arbitrary read in wordexp()",
        "vulnerabilityID": "CVE-2021-35942"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "The deprecated compatibility function svcunix_create in the sunrpc module of the GNU C Library (aka glibc) through 2.34 copies its path argument on the stack without validating its length, which may result in a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a stack protector enabled) arbitrary code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-23218",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218",
          "https://linux.oracle.com/cve/CVE-2022-23218.html",
          "https://linux.oracle.com/errata/ELSA-2022-9421.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23218",
          "https://security.gentoo.org/glsa/202208-24",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28768",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23218",
        "resource": "libc-bin",
        "score": 7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Stack-based buffer overflow in svcunix_create via long pathnames",
        "vulnerabilityID": "CVE-2022-23218"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "The deprecated compatibility function clnt_create in the sunrpc module of the GNU C Library (aka glibc) through 2.34 copies its hostname argument on the stack without validating its length, which may result in a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a stack protector enabled) arbitrary code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-23219",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219",
          "https://linux.oracle.com/cve/CVE-2022-23219.html",
          "https://linux.oracle.com/errata/ELSA-2022-9421.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23219",
          "https://security.gentoo.org/glsa/202208-24",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22542",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23219",
        "resource": "libc-bin",
        "score": 7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Stack-based buffer overflow in sunrpc clnt_create via a long pathname",
        "vulnerabilityID": "CVE-2022-23219"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272",
          "https://access.redhat.com/security/cve/CVE-2009-5155",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=11053",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672",
          "https://support.f5.com/csp/article/K64119434",
          "https://support.f5.com/csp/article/K64119434?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/notices/USN-4954-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2009-5155",
        "resource": "libc-bin",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: parse_reg_exp in posix/regcomp.c misparses alternatives leading to denial of service or trigger incorrect result",
        "vulnerabilityID": "CVE-2009-5155"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In glibc 2.26 and earlier there is confusion in the usage of getcwd() by realpath() which can be used to write before the destination buffer leading to a buffer underflow and potential code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://seclists.org/oss-sec/2018/q1/38",
          "http://www.openwall.com/lists/oss-security/2018/01/11/5",
          "http://www.securityfocus.com/bid/102525",
          "http://www.securitytracker.com/id/1040162",
          "https://access.redhat.com/errata/RHSA-2018:0805",
          "https://access.redhat.com/security/cve/CVE-2018-1000001",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001",
          "https://linux.oracle.com/cve/CVE-2018-1000001.html",
          "https://linux.oracle.com/errata/ELSA-2018-0805.html",
          "https://lists.samba.org/archive/rsync/2018-February/031478.html",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=18203",
          "https://ubuntu.com/security/notices/USN-3534-1",
          "https://ubuntu.com/security/notices/USN-3536-1",
          "https://usn.ubuntu.com/3534-1/",
          "https://usn.ubuntu.com/3536-1/",
          "https://www.exploit-db.com/exploits/43775/",
          "https://www.exploit-db.com/exploits/44889/",
          "https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-1000001",
        "resource": "libc-bin",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: realpath() buffer underflow when getcwd() returns relative path allows privilege escalation",
        "vulnerabilityID": "CVE-2018-1000001"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:C",
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the frame address, resulting in a denial of service or potential code execution. The highest threat from this vulnerability is to system availability.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-1751",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751",
          "https://linux.oracle.com/cve/CVE-2020-1751.html",
          "https://linux.oracle.com/errata/ELSA-2020-4444.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1751",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20200430-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25423",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1751",
        "resource": "libc-bin",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: array overflow in backtrace functions for powerpc",
        "vulnerabilityID": "CVE-2020-1751"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 3.7,
            "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A use-after-free vulnerability introduced in glibc upstream version 2.14 was found in the way the tilde expansion was carried out. Directory paths containing an initial tilde followed by a valid username were affected by this issue. A local attacker could exploit this flaw by creating a specially crafted path that, when processed by the glob function, would potentially lead to arbitrary code execution. This was fixed in version 2.32.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-1752",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752",
          "https://linux.oracle.com/cve/CVE-2020-1752.html",
          "https://linux.oracle.com/errata/ELSA-2020-4444.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1752",
          "https://security.gentoo.org/glsa/202101-20",
          "https://security.netapp.com/advisory/ntap-20200511-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25414",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1752",
        "resource": "libc-bin",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: use-after-free in glob() function when expanding ~user",
        "vulnerabilityID": "CVE-2020-1752"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid input sequences in the ISO-2022-JP-3 encoding, fails an assertion in the code path and aborts the program, potentially resulting in a denial of service.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.openwall.com/lists/oss-security/2021/01/28/2",
          "https://access.redhat.com/security/cve/CVE-2021-3326",
          "https://bugs.chromium.org/p/project-zero/issues/detail?id=2146",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326",
          "https://linux.oracle.com/cve/CVE-2021-3326.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3326",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210304-0007/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27256",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888",
          "https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3326",
        "resource": "libc-bin",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters",
        "vulnerabilityID": "CVE-2021-3326"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A flaw was found in glibc. An off-by-one buffer overflow and underflow in getcwd() may lead to memory corruption when the size of the buffer is exactly 1. A local attacker who can control the input buffer and size passed to getcwd() in a setuid program could use this flaw to potentially execute arbitrary code and escalate their privileges on the system.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3999.json",
          "https://access.redhat.com/security/cve/CVE-2021-3999",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2024637",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999",
          "https://linux.oracle.com/cve/CVE-2021-3999.html",
          "https://linux.oracle.com/errata/ELSA-2022-9234.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3999",
          "https://security-tracker.debian.org/tracker/CVE-2021-3999",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28769",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=23e0e8f5f1fb5ed150253d986ecccdc90c2dcd5e",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.openwall.com/lists/oss-security/2022/01/24/4"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3999",
        "resource": "libc-bin",
        "score": 7.4,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Off-by-one buffer overflow/underflow in getcwd()",
        "vulnerabilityID": "CVE-2021-3999"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          },
          "redhat": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.28, the getaddrinfo function would successfully parse a string that contained an IPv4 address followed by whitespace and arbitrary characters, which could lead applications to incorrectly assume that it had parsed a valid string, without the possibility of embedded HTTP headers or other potentially dangerous substrings.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html",
          "http://www.securityfocus.com/bid/106672",
          "https://access.redhat.com/errata/RHSA-2019:2118",
          "https://access.redhat.com/errata/RHSA-2019:3513",
          "https://access.redhat.com/security/cve/CVE-2016-10739",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1347549",
          "https://linux.oracle.com/cve/CVE-2016-10739.html",
          "https://linux.oracle.com/errata/ELSA-2019-3513.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2016-10739",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=20018"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-10739",
        "resource": "libc-bin",
        "score": 5.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: getaddrinfo should reject IP addresses with trailing characters",
        "vulnerabilityID": "CVE-2016-10739"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"
          },
          "redhat": {
            "V3Score": 3,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N"
          }
        },
        "description": "The DNS stub resolver in the GNU C Library (aka glibc or libc6) before version 2.26, when EDNS support is enabled, will solicit large UDP responses from name servers, potentially simplifying off-path DNS spoofing attacks due to IP fragmentation.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/100598",
          "https://access.redhat.com/errata/RHSA-2018:0805",
          "https://access.redhat.com/security/cve/CVE-2017-12132",
          "https://arxiv.org/pdf/1205.4011.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12132",
          "https://linux.oracle.com/cve/CVE-2017-12132.html",
          "https://linux.oracle.com/errata/ELSA-2018-0805.html",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=21361"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-12132",
        "resource": "libc-bin",
        "score": 3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Fragmentation attacks possible when EDNS0 is enabled",
        "vulnerabilityID": "CVE-2017-12132"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.1,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:C",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv feature in the GNU C Library (aka glibc or libc6) through 2.32, when processing invalid multi-byte input sequences in the EUC-KR encoding, may have a buffer over-read.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-25013",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013",
          "https://linux.oracle.com/cve/CVE-2019-25013.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-25013",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210205-0004/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24973",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-25013",
        "resource": "libc-bin",
        "score": 4.8,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: buffer over-read in iconv when processing invalid multi-byte input sequences in the EUC-KR encoding",
        "vulnerabilityID": "CVE-2019-25013"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H"
          }
        },
        "description": "The GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to sysdeps/ieee754/ldbl-96/e_rem_pio2l.c.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html",
          "https://access.redhat.com/security/cve/CVE-2020-10029",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029",
          "https://linux.oracle.com/cve/CVE-2020-10029.html",
          "https://linux.oracle.com/errata/ELSA-2021-0348.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-10029",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20200327-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25487",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-10029",
        "resource": "libc-bin",
        "score": 5.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: stack corruption from crafted input in cosl, sinl, sincosl, and tanl functions",
        "vulnerabilityID": "CVE-2020-10029"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid multi-byte input sequences in IBM1364, IBM1371, IBM1388, IBM1390, and IBM1399 encodings, fails to advance the input state, which could lead to an infinite loop in applications, resulting in a denial of service, a different vulnerability from CVE-2016-10228.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-27618",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618",
          "https://linux.oracle.com/cve/CVE-2020-27618.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-27618",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210401-0006/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=26224",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-27618",
        "resource": "libc-bin",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: iconv when processing invalid multi-byte input sequences fails to advance the input state, which could result in an infinite loop",
        "vulnerabilityID": "CVE-2020-27618"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4,
            "V2Vector": "AV:N/AC:L/Au:S/C:N/I:N/A:P"
          },
          "redhat": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P"
          }
        },
        "description": "The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://cxib.net/stuff/glob-0day.c",
          "http://securityreason.com/achievement_securityalert/89",
          "http://securityreason.com/exploitalert/9223",
          "https://access.redhat.com/security/cve/CVE-2010-4756",
          "https://bugzilla.redhat.com/show_bug.cgi?id=681681",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-4756",
          "https://nvd.nist.gov/vuln/detail/CVE-2010-4756"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2010-4756",
        "resource": "libc-bin",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions",
        "vulnerabilityID": "CVE-2010-4756"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P"
          }
        },
        "description": "The pop_fail_stack function in the GNU C Library (aka glibc or libc6) allows context-dependent attackers to cause a denial of service (assertion failure and application crash) via vectors related to extended regular expression processing.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.openwall.com/lists/oss-security/2017/02/14/9",
          "http://www.securityfocus.com/bid/76916",
          "https://access.redhat.com/security/cve/CVE-2015-8985",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=779392",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8985",
          "https://security.gentoo.org/glsa/201908-06",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=bc680b336971305cb39896b30d72dc7101b62242"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2015-8985",
        "resource": "libc-bin",
        "score": 5.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: potential denial of service in pop_fail_stack()",
        "vulnerabilityID": "CVE-2015-8985"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The iconv program in the GNU C Library (aka glibc or libc6) 2.31 and earlier, when invoked with multiple suffixes in the destination encoding (TRANSLATE or IGNORE) along with the -c option, enters an infinite loop when processing invalid multi-byte input sequences, leading to a denial of service.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://openwall.com/lists/oss-security/2017/03/01/10",
          "http://www.securityfocus.com/bid/96525",
          "https://access.redhat.com/security/cve/CVE-2016-10228",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10228",
          "https://linux.oracle.com/cve/CVE-2016-10228.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://security.gentoo.org/glsa/202101-20",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=26224",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-10228",
        "resource": "libc-bin",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: iconv program can hang when invoked with the -c option",
        "vulnerabilityID": "CVE-2016-10228"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\\227|)(\\\\1\\\\1|t1|\\\\\\2537)+' in grep.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/107160",
          "https://access.redhat.com/security/cve/CVE-2018-20796",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34141",
          "https://lists.gnu.org/archive/html/bug-gnulib/2019-01/msg00108.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-20796",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp;utm_medium=RSS"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-20796",
        "resource": "libc-bin",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
        "vulnerabilityID": "CVE-2018-20796"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-1010022",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010022",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22850",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22850#c3",
          "https://ubuntu.com/security/CVE-2019-1010022"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010022",
        "resource": "libc-bin",
        "score": 9.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: stack guard protection bypass",
        "vulnerabilityID": "CVE-2019-1010022"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/109167",
          "https://access.redhat.com/security/cve/CVE-2019-1010023",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010023",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22851",
          "https://support.f5.com/csp/article/K11932200?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010023"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010023",
        "resource": "libc-bin",
        "score": 7.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: running ldd on malicious ELF leads to code execution because of wrong size computation",
        "vulnerabilityID": "CVE-2019-1010023"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/109162",
          "https://access.redhat.com/security/cve/CVE-2019-1010024",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010024",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22852",
          "https://support.f5.com/csp/article/K06046097",
          "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010024"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010024",
        "resource": "libc-bin",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: ASLR bypass using cache of thread stack and heap",
        "vulnerabilityID": "CVE-2019-1010024"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 2.9,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is \"ASLR bypass itself is not a vulnerability.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-1010025",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010025",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22853",
          "https://support.f5.com/csp/article/K06046097",
          "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010025"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010025",
        "resource": "libc-bin",
        "score": 2.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: information disclosure of heap addresses of pthread_created thread",
        "vulnerabilityID": "CVE-2019-1010025"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 2.9,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "On the x86-64 architecture, the GNU C Library (aka glibc) before 2.31 fails to ignore the LD_PREFER_MAP_32BIT_EXEC environment variable during program execution after a security transition, allowing local attackers to restrict the possible mapping addresses for loaded libraries and thus bypass ASLR for a setuid program.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-19126",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19126",
          "https://linux.oracle.com/cve/CVE-2019-19126.html",
          "https://linux.oracle.com/errata/ELSA-2020-3861.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4FQ5LC6JOYSOYFPRUZ4S45KL6IP3RPPZ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZFJ5E7NWOL6ROE5QVICHKIOUGCPFJVUH/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-19126",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25204",
          "https://sourceware.org/ml/libc-alpha/2019-11/msg00649.html",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-19126",
        "resource": "libc-bin",
        "score": 2.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: LD_PREFER_MAP_32BIT_EXEC not ignored in setuid binaries",
        "vulnerabilityID": "CVE-2019-19126"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The string component in the GNU C Library (aka glibc or libc6) through 2.28, when running on the x32 architecture, incorrectly attempts to use a 64-bit register for size_t in assembly codes, which can lead to a segmentation fault or possibly unspecified other impact, as demonstrated by a crash in __memmove_avx_unaligned_erms in sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S during a memcpy.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/106671",
          "https://access.redhat.com/security/cve/CVE-2019-6488",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-6488",
          "https://security.gentoo.org/glsa/202006-04",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24097"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-6488",
        "resource": "libc-bin",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Incorrect attempt to use a 64-bit register for size_t in assembly codes results in segmentation fault",
        "vulnerabilityID": "CVE-2019-6488"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, the memcmp function for the x32 architecture can incorrectly return zero (indicating that the inputs are equal) because the RDX most significant bit is mishandled.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/106835",
          "https://access.redhat.com/security/cve/CVE-2019-7309",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-7309",
          "https://security.gentoo.org/glsa/202006-04",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24155",
          "https://sourceware.org/ml/libc-alpha/2019-02/msg00041.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-7309",
        "resource": "libc-bin",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: memcmp function incorrectly returns zero",
        "vulnerabilityID": "CVE-2019-7309"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 2.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "** DISPUTED ** In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\\\1\\\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-9192",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-9192",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24269",
          "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp;utm_medium=RSS"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-9192",
        "resource": "libc-bin",
        "score": 2.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
        "vulnerabilityID": "CVE-2019-9192"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An exploitable signed comparison vulnerability exists in the ARMv7 memcpy() implementation of GNU glibc 2.30.9000. Calling memcpy() (on ARMv7 targets that utilize the GNU glibc implementation) with a negative value for the 'num' parameter results in a signed comparison vulnerability. If an attacker underflows the 'num' parameter to memcpy(), this vulnerability could lead to undefined behavior such as writing to out-of-bounds memory and potentially remote code execution. Furthermore, this memcpy() implementation allows for program execution to continue in scenarios where a segmentation fault or crash should have occurred. The dangers occur in that subsequent execution and iterations of this code will be executed with this corrupted data.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-6096",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-6096",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SPYXTDOOB4PQGTYAMZAZNJIB3FF6YQXI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/URXOIA2LDUKHQXK4BE55BQBRI6ZZG3Y6/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-6096",
          "https://security.gentoo.org/glsa/202101-20",
          "https://sourceware.org/bugzilla/attachment.cgi?id=12334",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25620",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1019",
          "https://ubuntu.com/security/notices/USN-4954-1",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1019"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-6096",
        "resource": "libc-bin",
        "score": 8.1,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: signed comparison vulnerability in the ARMv7 memcpy function",
        "vulnerabilityID": "CVE-2020-6096"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 2.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 2.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The nameserver caching daemon (nscd) in the GNU C Library (aka glibc or libc6) 2.29 through 2.33, when processing a request for netgroup lookup, may crash due to a double-free, potentially resulting in degraded service or Denial of Service on the local system. This is related to netgroupcache.c.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-27645",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27645",
          "https://linux.oracle.com/cve/CVE-2021-27645.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7LZNT6KTMCCWPWXEOGSHD3YLYZKUGMH5/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I7TS26LIZSOBLGJEZMJX4PXT5BQDE2WS/",
          "https://security.gentoo.org/glsa/202107-07",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27462",
          "https://ubuntu.com/security/notices/USN-5310-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-27645",
        "resource": "libc-bin",
        "score": 2.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Use-after-free in addgetnetgrentX function in netgroupcache.c",
        "vulnerabilityID": "CVE-2021-27645"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "An integer overflow in the implementation of the posix_memalign in memalign functions in the GNU C Library (aka glibc or libc6) 2.26 and earlier could cause these functions to return a pointer to a heap area that is too small, potentially leading to heap corruption.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://bugs.debian.org/878159",
          "http://www.securityfocus.com/bid/102912",
          "https://access.redhat.com/errata/RHBA-2019:0327",
          "https://access.redhat.com/errata/RHSA-2018:3092",
          "https://access.redhat.com/security/cve/CVE-2018-6485",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485",
          "https://linux.oracle.com/cve/CVE-2018-6485.html",
          "https://linux.oracle.com/errata/ELSA-2018-3092.html",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22343",
          "https://ubuntu.com/security/notices/USN-4218-1",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4218-1/",
          "https://usn.ubuntu.com/4416-1/",
          "https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6485",
        "resource": "libc6",
        "score": 5.3,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Integer overflow in posix_memalign in memalign functions",
        "vulnerabilityID": "CVE-2018-6485"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "The malloc implementation in the GNU C Library (aka glibc or libc6), from version 2.24 to 2.26 on powerpc, and only in version 2.26 on i386, did not properly handle malloc calls with arguments close to SIZE_MAX and could return a pointer to a heap region that is smaller than requested, eventually leading to heap corruption.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-6551",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22774",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6551",
        "resource": "libc6",
        "score": 5.3,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: integer overflow in malloc functions",
        "vulnerabilityID": "CVE-2018-6551"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, proceed_next_node in posix/regexec.c has a heap-based buffer over-read via an attempted case-insensitive regular-expression match.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/107160",
          "https://access.redhat.com/security/cve/CVE-2019-9169",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10278",
          "https://linux.oracle.com/cve/CVE-2019-9169.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-9169",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24114",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9",
          "https://support.f5.com/csp/article/K54823184",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-9169",
        "resource": "libc6",
        "score": 6.5,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: regular-expression match via proceed_next_node in posix/regexec.c leads to heap-based buffer over-read",
        "vulnerabilityID": "CVE-2019-9169"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The mq_notify function in the GNU C Library (aka glibc) versions 2.32 and 2.33 has a use-after-free. It may use the notification thread attributes object (passed through its struct sigevent parameter) after it has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified other impact.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-33574",
          "https://linux.oracle.com/cve/CVE-2021-33574.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-33574",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210629-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27896",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-33574",
        "resource": "libc6",
        "score": 5.9,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: mq_notify does not handle separately allocated thread attributes",
        "vulnerabilityID": "CVE-2021-33574"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in a denial of service or disclosure of information. This occurs because atoi was used but strtoul should have been used to ensure correct calculations.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json",
          "https://access.redhat.com/security/cve/CVE-2021-35942",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942",
          "https://linux.oracle.com/cve/CVE-2021-35942.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-35942",
          "https://security.gentoo.org/glsa/202208-24",
          "https://security.netapp.com/advisory/ntap-20210827-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28011",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c",
          "https://sourceware.org/glibc/wiki/Security%20Exceptions",
          "https://ubuntu.com/security/notices/USN-5310-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-35942",
        "resource": "libc6",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Arbitrary read in wordexp()",
        "vulnerabilityID": "CVE-2021-35942"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "The deprecated compatibility function svcunix_create in the sunrpc module of the GNU C Library (aka glibc) through 2.34 copies its path argument on the stack without validating its length, which may result in a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a stack protector enabled) arbitrary code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-23218",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218",
          "https://linux.oracle.com/cve/CVE-2022-23218.html",
          "https://linux.oracle.com/errata/ELSA-2022-9421.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23218",
          "https://security.gentoo.org/glsa/202208-24",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28768",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23218",
        "resource": "libc6",
        "score": 7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Stack-based buffer overflow in svcunix_create via long pathnames",
        "vulnerabilityID": "CVE-2022-23218"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "The deprecated compatibility function clnt_create in the sunrpc module of the GNU C Library (aka glibc) through 2.34 copies its hostname argument on the stack without validating its length, which may result in a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a stack protector enabled) arbitrary code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-23219",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219",
          "https://linux.oracle.com/cve/CVE-2022-23219.html",
          "https://linux.oracle.com/errata/ELSA-2022-9421.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23219",
          "https://security.gentoo.org/glsa/202208-24",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22542",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23219",
        "resource": "libc6",
        "score": 7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Stack-based buffer overflow in sunrpc clnt_create via a long pathname",
        "vulnerabilityID": "CVE-2022-23219"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272",
          "https://access.redhat.com/security/cve/CVE-2009-5155",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=11053",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672",
          "https://support.f5.com/csp/article/K64119434",
          "https://support.f5.com/csp/article/K64119434?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/notices/USN-4954-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2009-5155",
        "resource": "libc6",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: parse_reg_exp in posix/regcomp.c misparses alternatives leading to denial of service or trigger incorrect result",
        "vulnerabilityID": "CVE-2009-5155"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In glibc 2.26 and earlier there is confusion in the usage of getcwd() by realpath() which can be used to write before the destination buffer leading to a buffer underflow and potential code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://seclists.org/oss-sec/2018/q1/38",
          "http://www.openwall.com/lists/oss-security/2018/01/11/5",
          "http://www.securityfocus.com/bid/102525",
          "http://www.securitytracker.com/id/1040162",
          "https://access.redhat.com/errata/RHSA-2018:0805",
          "https://access.redhat.com/security/cve/CVE-2018-1000001",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001",
          "https://linux.oracle.com/cve/CVE-2018-1000001.html",
          "https://linux.oracle.com/errata/ELSA-2018-0805.html",
          "https://lists.samba.org/archive/rsync/2018-February/031478.html",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=18203",
          "https://ubuntu.com/security/notices/USN-3534-1",
          "https://ubuntu.com/security/notices/USN-3536-1",
          "https://usn.ubuntu.com/3534-1/",
          "https://usn.ubuntu.com/3536-1/",
          "https://www.exploit-db.com/exploits/43775/",
          "https://www.exploit-db.com/exploits/44889/",
          "https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-1000001",
        "resource": "libc6",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: realpath() buffer underflow when getcwd() returns relative path allows privilege escalation",
        "vulnerabilityID": "CVE-2018-1000001"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:C",
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the frame address, resulting in a denial of service or potential code execution. The highest threat from this vulnerability is to system availability.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-1751",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751",
          "https://linux.oracle.com/cve/CVE-2020-1751.html",
          "https://linux.oracle.com/errata/ELSA-2020-4444.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1751",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20200430-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25423",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1751",
        "resource": "libc6",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: array overflow in backtrace functions for powerpc",
        "vulnerabilityID": "CVE-2020-1751"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 3.7,
            "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A use-after-free vulnerability introduced in glibc upstream version 2.14 was found in the way the tilde expansion was carried out. Directory paths containing an initial tilde followed by a valid username were affected by this issue. A local attacker could exploit this flaw by creating a specially crafted path that, when processed by the glob function, would potentially lead to arbitrary code execution. This was fixed in version 2.32.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-1752",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752",
          "https://linux.oracle.com/cve/CVE-2020-1752.html",
          "https://linux.oracle.com/errata/ELSA-2020-4444.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1752",
          "https://security.gentoo.org/glsa/202101-20",
          "https://security.netapp.com/advisory/ntap-20200511-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25414",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1752",
        "resource": "libc6",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: use-after-free in glob() function when expanding ~user",
        "vulnerabilityID": "CVE-2020-1752"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid input sequences in the ISO-2022-JP-3 encoding, fails an assertion in the code path and aborts the program, potentially resulting in a denial of service.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.openwall.com/lists/oss-security/2021/01/28/2",
          "https://access.redhat.com/security/cve/CVE-2021-3326",
          "https://bugs.chromium.org/p/project-zero/issues/detail?id=2146",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326",
          "https://linux.oracle.com/cve/CVE-2021-3326.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3326",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210304-0007/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27256",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888",
          "https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3326",
        "resource": "libc6",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters",
        "vulnerabilityID": "CVE-2021-3326"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A flaw was found in glibc. An off-by-one buffer overflow and underflow in getcwd() may lead to memory corruption when the size of the buffer is exactly 1. A local attacker who can control the input buffer and size passed to getcwd() in a setuid program could use this flaw to potentially execute arbitrary code and escalate their privileges on the system.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3999.json",
          "https://access.redhat.com/security/cve/CVE-2021-3999",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2024637",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999",
          "https://linux.oracle.com/cve/CVE-2021-3999.html",
          "https://linux.oracle.com/errata/ELSA-2022-9234.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3999",
          "https://security-tracker.debian.org/tracker/CVE-2021-3999",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28769",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=23e0e8f5f1fb5ed150253d986ecccdc90c2dcd5e",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.openwall.com/lists/oss-security/2022/01/24/4"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3999",
        "resource": "libc6",
        "score": 7.4,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Off-by-one buffer overflow/underflow in getcwd()",
        "vulnerabilityID": "CVE-2021-3999"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          },
          "redhat": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.28, the getaddrinfo function would successfully parse a string that contained an IPv4 address followed by whitespace and arbitrary characters, which could lead applications to incorrectly assume that it had parsed a valid string, without the possibility of embedded HTTP headers or other potentially dangerous substrings.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html",
          "http://www.securityfocus.com/bid/106672",
          "https://access.redhat.com/errata/RHSA-2019:2118",
          "https://access.redhat.com/errata/RHSA-2019:3513",
          "https://access.redhat.com/security/cve/CVE-2016-10739",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1347549",
          "https://linux.oracle.com/cve/CVE-2016-10739.html",
          "https://linux.oracle.com/errata/ELSA-2019-3513.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2016-10739",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=20018"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-10739",
        "resource": "libc6",
        "score": 5.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: getaddrinfo should reject IP addresses with trailing characters",
        "vulnerabilityID": "CVE-2016-10739"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"
          },
          "redhat": {
            "V3Score": 3,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N"
          }
        },
        "description": "The DNS stub resolver in the GNU C Library (aka glibc or libc6) before version 2.26, when EDNS support is enabled, will solicit large UDP responses from name servers, potentially simplifying off-path DNS spoofing attacks due to IP fragmentation.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/100598",
          "https://access.redhat.com/errata/RHSA-2018:0805",
          "https://access.redhat.com/security/cve/CVE-2017-12132",
          "https://arxiv.org/pdf/1205.4011.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12132",
          "https://linux.oracle.com/cve/CVE-2017-12132.html",
          "https://linux.oracle.com/errata/ELSA-2018-0805.html",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=21361"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-12132",
        "resource": "libc6",
        "score": 3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Fragmentation attacks possible when EDNS0 is enabled",
        "vulnerabilityID": "CVE-2017-12132"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.1,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:C",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv feature in the GNU C Library (aka glibc or libc6) through 2.32, when processing invalid multi-byte input sequences in the EUC-KR encoding, may have a buffer over-read.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-25013",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013",
          "https://linux.oracle.com/cve/CVE-2019-25013.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-25013",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210205-0004/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24973",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-25013",
        "resource": "libc6",
        "score": 4.8,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: buffer over-read in iconv when processing invalid multi-byte input sequences in the EUC-KR encoding",
        "vulnerabilityID": "CVE-2019-25013"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H"
          }
        },
        "description": "The GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to sysdeps/ieee754/ldbl-96/e_rem_pio2l.c.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html",
          "https://access.redhat.com/security/cve/CVE-2020-10029",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029",
          "https://linux.oracle.com/cve/CVE-2020-10029.html",
          "https://linux.oracle.com/errata/ELSA-2021-0348.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-10029",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20200327-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25487",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-10029",
        "resource": "libc6",
        "score": 5.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: stack corruption from crafted input in cosl, sinl, sincosl, and tanl functions",
        "vulnerabilityID": "CVE-2020-10029"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid multi-byte input sequences in IBM1364, IBM1371, IBM1388, IBM1390, and IBM1399 encodings, fails to advance the input state, which could lead to an infinite loop in applications, resulting in a denial of service, a different vulnerability from CVE-2016-10228.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-27618",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618",
          "https://linux.oracle.com/cve/CVE-2020-27618.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-27618",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210401-0006/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=26224",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-27618",
        "resource": "libc6",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: iconv when processing invalid multi-byte input sequences fails to advance the input state, which could result in an infinite loop",
        "vulnerabilityID": "CVE-2020-27618"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4,
            "V2Vector": "AV:N/AC:L/Au:S/C:N/I:N/A:P"
          },
          "redhat": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P"
          }
        },
        "description": "The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://cxib.net/stuff/glob-0day.c",
          "http://securityreason.com/achievement_securityalert/89",
          "http://securityreason.com/exploitalert/9223",
          "https://access.redhat.com/security/cve/CVE-2010-4756",
          "https://bugzilla.redhat.com/show_bug.cgi?id=681681",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-4756",
          "https://nvd.nist.gov/vuln/detail/CVE-2010-4756"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2010-4756",
        "resource": "libc6",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions",
        "vulnerabilityID": "CVE-2010-4756"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P"
          }
        },
        "description": "The pop_fail_stack function in the GNU C Library (aka glibc or libc6) allows context-dependent attackers to cause a denial of service (assertion failure and application crash) via vectors related to extended regular expression processing.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.openwall.com/lists/oss-security/2017/02/14/9",
          "http://www.securityfocus.com/bid/76916",
          "https://access.redhat.com/security/cve/CVE-2015-8985",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=779392",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8985",
          "https://security.gentoo.org/glsa/201908-06",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=bc680b336971305cb39896b30d72dc7101b62242"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2015-8985",
        "resource": "libc6",
        "score": 5.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: potential denial of service in pop_fail_stack()",
        "vulnerabilityID": "CVE-2015-8985"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The iconv program in the GNU C Library (aka glibc or libc6) 2.31 and earlier, when invoked with multiple suffixes in the destination encoding (TRANSLATE or IGNORE) along with the -c option, enters an infinite loop when processing invalid multi-byte input sequences, leading to a denial of service.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://openwall.com/lists/oss-security/2017/03/01/10",
          "http://www.securityfocus.com/bid/96525",
          "https://access.redhat.com/security/cve/CVE-2016-10228",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10228",
          "https://linux.oracle.com/cve/CVE-2016-10228.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://security.gentoo.org/glsa/202101-20",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=26224",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-10228",
        "resource": "libc6",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: iconv program can hang when invoked with the -c option",
        "vulnerabilityID": "CVE-2016-10228"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\\227|)(\\\\1\\\\1|t1|\\\\\\2537)+' in grep.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/107160",
          "https://access.redhat.com/security/cve/CVE-2018-20796",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34141",
          "https://lists.gnu.org/archive/html/bug-gnulib/2019-01/msg00108.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-20796",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp;utm_medium=RSS"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-20796",
        "resource": "libc6",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
        "vulnerabilityID": "CVE-2018-20796"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-1010022",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010022",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22850",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22850#c3",
          "https://ubuntu.com/security/CVE-2019-1010022"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010022",
        "resource": "libc6",
        "score": 9.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: stack guard protection bypass",
        "vulnerabilityID": "CVE-2019-1010022"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/109167",
          "https://access.redhat.com/security/cve/CVE-2019-1010023",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010023",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22851",
          "https://support.f5.com/csp/article/K11932200?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010023"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010023",
        "resource": "libc6",
        "score": 7.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: running ldd on malicious ELF leads to code execution because of wrong size computation",
        "vulnerabilityID": "CVE-2019-1010023"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/109162",
          "https://access.redhat.com/security/cve/CVE-2019-1010024",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010024",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22852",
          "https://support.f5.com/csp/article/K06046097",
          "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010024"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010024",
        "resource": "libc6",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: ASLR bypass using cache of thread stack and heap",
        "vulnerabilityID": "CVE-2019-1010024"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 2.9,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is \"ASLR bypass itself is not a vulnerability.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-1010025",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010025",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22853",
          "https://support.f5.com/csp/article/K06046097",
          "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010025"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010025",
        "resource": "libc6",
        "score": 2.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: information disclosure of heap addresses of pthread_created thread",
        "vulnerabilityID": "CVE-2019-1010025"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 2.9,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "On the x86-64 architecture, the GNU C Library (aka glibc) before 2.31 fails to ignore the LD_PREFER_MAP_32BIT_EXEC environment variable during program execution after a security transition, allowing local attackers to restrict the possible mapping addresses for loaded libraries and thus bypass ASLR for a setuid program.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-19126",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19126",
          "https://linux.oracle.com/cve/CVE-2019-19126.html",
          "https://linux.oracle.com/errata/ELSA-2020-3861.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4FQ5LC6JOYSOYFPRUZ4S45KL6IP3RPPZ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZFJ5E7NWOL6ROE5QVICHKIOUGCPFJVUH/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-19126",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25204",
          "https://sourceware.org/ml/libc-alpha/2019-11/msg00649.html",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-19126",
        "resource": "libc6",
        "score": 2.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: LD_PREFER_MAP_32BIT_EXEC not ignored in setuid binaries",
        "vulnerabilityID": "CVE-2019-19126"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The string component in the GNU C Library (aka glibc or libc6) through 2.28, when running on the x32 architecture, incorrectly attempts to use a 64-bit register for size_t in assembly codes, which can lead to a segmentation fault or possibly unspecified other impact, as demonstrated by a crash in __memmove_avx_unaligned_erms in sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S during a memcpy.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/106671",
          "https://access.redhat.com/security/cve/CVE-2019-6488",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-6488",
          "https://security.gentoo.org/glsa/202006-04",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24097"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-6488",
        "resource": "libc6",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Incorrect attempt to use a 64-bit register for size_t in assembly codes results in segmentation fault",
        "vulnerabilityID": "CVE-2019-6488"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, the memcmp function for the x32 architecture can incorrectly return zero (indicating that the inputs are equal) because the RDX most significant bit is mishandled.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/106835",
          "https://access.redhat.com/security/cve/CVE-2019-7309",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-7309",
          "https://security.gentoo.org/glsa/202006-04",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24155",
          "https://sourceware.org/ml/libc-alpha/2019-02/msg00041.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-7309",
        "resource": "libc6",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: memcmp function incorrectly returns zero",
        "vulnerabilityID": "CVE-2019-7309"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 2.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "** DISPUTED ** In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\\\1\\\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-9192",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-9192",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24269",
          "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp;utm_medium=RSS"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-9192",
        "resource": "libc6",
        "score": 2.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
        "vulnerabilityID": "CVE-2019-9192"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An exploitable signed comparison vulnerability exists in the ARMv7 memcpy() implementation of GNU glibc 2.30.9000. Calling memcpy() (on ARMv7 targets that utilize the GNU glibc implementation) with a negative value for the 'num' parameter results in a signed comparison vulnerability. If an attacker underflows the 'num' parameter to memcpy(), this vulnerability could lead to undefined behavior such as writing to out-of-bounds memory and potentially remote code execution. Furthermore, this memcpy() implementation allows for program execution to continue in scenarios where a segmentation fault or crash should have occurred. The dangers occur in that subsequent execution and iterations of this code will be executed with this corrupted data.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-6096",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-6096",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SPYXTDOOB4PQGTYAMZAZNJIB3FF6YQXI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/URXOIA2LDUKHQXK4BE55BQBRI6ZZG3Y6/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-6096",
          "https://security.gentoo.org/glsa/202101-20",
          "https://sourceware.org/bugzilla/attachment.cgi?id=12334",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25620",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1019",
          "https://ubuntu.com/security/notices/USN-4954-1",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1019"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-6096",
        "resource": "libc6",
        "score": 8.1,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: signed comparison vulnerability in the ARMv7 memcpy function",
        "vulnerabilityID": "CVE-2020-6096"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 2.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 2.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The nameserver caching daemon (nscd) in the GNU C Library (aka glibc or libc6) 2.29 through 2.33, when processing a request for netgroup lookup, may crash due to a double-free, potentially resulting in degraded service or Denial of Service on the local system. This is related to netgroupcache.c.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-27645",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27645",
          "https://linux.oracle.com/cve/CVE-2021-27645.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7LZNT6KTMCCWPWXEOGSHD3YLYZKUGMH5/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I7TS26LIZSOBLGJEZMJX4PXT5BQDE2WS/",
          "https://security.gentoo.org/glsa/202107-07",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27462",
          "https://ubuntu.com/security/notices/USN-5310-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-27645",
        "resource": "libc6",
        "score": 2.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Use-after-free in addgetnetgrentX function in netgroupcache.c",
        "vulnerabilityID": "CVE-2021-27645"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
        "fixedVersion": "",
        "installedVersion": "1.43.4-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1304",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
          "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1304",
          "https://ubuntu.com/security/notices/USN-5464-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1304",
        "resource": "libcomerr2",
        "score": 5.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
        "vulnerabilityID": "CVE-2022-1304"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An exploitable code execution vulnerability exists in the quota file functionality of E2fsprogs 1.45.3. A specially crafted ext4 partition can cause an out-of-bounds write on the heap, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
        "fixedVersion": "1.43.4-2+deb9u1",
        "installedVersion": "1.43.4-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-5094",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5094",
          "https://linux.oracle.com/cve/CVE-2019-5094.html",
          "https://linux.oracle.com/errata/ELSA-2020-4011.html",
          "https://lists.debian.org/debian-lts-announce/2019/09/msg00029.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-5094",
          "https://seclists.org/bugtraq/2019/Sep/58",
          "https://security.gentoo.org/glsa/202003-05",
          "https://security.netapp.com/advisory/ntap-20200115-0002/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0887",
          "https://ubuntu.com/security/notices/USN-4142-1",
          "https://ubuntu.com/security/notices/USN-4142-2",
          "https://usn.ubuntu.com/4142-1/",
          "https://usn.ubuntu.com/4142-2/",
          "https://www.debian.org/security/2019/dsa-4535"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5094",
        "resource": "libcomerr2",
        "score": 6.4,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: Crafted ext4 partition leads to out-of-bounds write",
        "vulnerabilityID": "CVE-2019-5094"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.4,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H"
          }
        },
        "description": "A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
        "fixedVersion": "1.43.4-2+deb9u2",
        "installedVersion": "1.43.4-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00004.html",
          "https://access.redhat.com/security/cve/CVE-2019-5188",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5188",
          "https://linux.oracle.com/cve/CVE-2019-5188.html",
          "https://linux.oracle.com/errata/ELSA-2020-4011.html",
          "https://lists.debian.org/debian-lts-announce/2020/03/msg00030.html",
          "https://lists.debian.org/debian-lts-announce/2020/07/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-5188",
          "https://security.netapp.com/advisory/ntap-20220506-0001/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0973",
          "https://ubuntu.com/security/notices/USN-4249-1",
          "https://usn.ubuntu.com/4249-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5188",
        "resource": "libcomerr2",
        "score": 7.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: Out-of-bounds write in e2fsck/rehash.c",
        "vulnerabilityID": "CVE-2019-5188"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "SQLite3 from 3.6.0 to and including 3.27.2 is vulnerable to heap out-of-bound read in the rtreenode() function when handling invalid rtree tables.",
        "fixedVersion": "",
        "installedVersion": "5.3.28-12+deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00074.html",
          "https://access.redhat.com/security/cve/CVE-2019-8457",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8457",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10365",
          "https://linux.oracle.com/cve/CVE-2019-8457.html",
          "https://linux.oracle.com/errata/ELSA-2020-1810.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPKYSWCOM3CL66RI76TYVIG6TJ263RXH/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SJPFGA45DI4F5MCF2OAACGH3HQOF4G3M/",
          "https://security.netapp.com/advisory/ntap-20190606-0002/",
          "https://ubuntu.com/security/notices/USN-4004-1",
          "https://ubuntu.com/security/notices/USN-4004-2",
          "https://ubuntu.com/security/notices/USN-4019-1",
          "https://ubuntu.com/security/notices/USN-4019-2",
          "https://usn.ubuntu.com/4004-1/",
          "https://usn.ubuntu.com/4004-2/",
          "https://usn.ubuntu.com/4019-1/",
          "https://usn.ubuntu.com/4019-2/",
          "https://www.oracle.com/security-alerts/cpuapr2020.html",
          "https://www.oracle.com/security-alerts/cpujan2020.html",
          "https://www.oracle.com/security-alerts/cpujul2020.html",
          "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html",
          "https://www.sqlite.org/releaselog/3_28_0.html",
          "https://www.sqlite.org/src/info/90acdbfce9c08858"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-8457",
        "resource": "libdb5.3",
        "score": 7.5,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "sqlite: heap out-of-bound read in function rtreenode()",
        "vulnerabilityID": "CVE-2019-8457"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/01/17/3",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-22822",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22822",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/539",
          "https://linux.oracle.com/cve/CVE-2022-22822.html",
          "https://linux.oracle.com/errata/ELSA-2022-1069.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-22822",
          "https://security.gentoo.org/glsa/202209-24",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-22822",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in addBinding in xmlparse.c",
        "vulnerabilityID": "CVE-2022-22822"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "build_model in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/01/17/3",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-22823",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22823",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/539",
          "https://linux.oracle.com/cve/CVE-2022-22823.html",
          "https://linux.oracle.com/errata/ELSA-2022-1069.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-22823",
          "https://security.gentoo.org/glsa/202209-24",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-22823",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in build_model in xmlparse.c",
        "vulnerabilityID": "CVE-2022-22823"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "defineAttribute in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/01/17/3",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-22824",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22824",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/539",
          "https://linux.oracle.com/cve/CVE-2022-22824.html",
          "https://linux.oracle.com/errata/ELSA-2022-1069.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-22824",
          "https://security.gentoo.org/glsa/202209-24",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-22824",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in defineAttribute in xmlparse.c",
        "vulnerabilityID": "CVE-2022-22824"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "Expat (aka libexpat) before 2.4.4 has a signed integer overflow in XML_GetBuffer, for configurations with a nonzero XML_CONTEXT_BYTES.",
        "fixedVersion": "2.2.0-2+deb9u5",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-23852",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23852",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/550",
          "https://linux.oracle.com/cve/CVE-2022-23852.html",
          "https://linux.oracle.com/errata/ELSA-2022-1069.html",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00007.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23852",
          "https://security.gentoo.org/glsa/202209-24",
          "https://security.netapp.com/advisory/ntap-20220217-0001/",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23852",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in function XML_GetBuffer",
        "vulnerabilityID": "CVE-2022-23852"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "Expat (aka libexpat) before 2.4.4 has an integer overflow in the doProlog function.",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-23990",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23990",
          "https://github.com/libexpat/libexpat/pull/551",
          "https://linux.oracle.com/cve/CVE-2022-23990.html",
          "https://linux.oracle.com/errata/ELSA-2022-9232.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/34NXVL2RZC2YZRV74ZQ3RNFB7WCEUP7D/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R7FF2UH7MPXKTADYSJUAHI2Y5UHBSHUH/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23990",
          "https://security.gentoo.org/glsa/202209-24",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23990",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: integer overflow in the doProlog function",
        "vulnerabilityID": "CVE-2022-23990"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks for whether a UTF-8 character is valid in a certain context.",
        "fixedVersion": "2.2.0-2+deb9u5",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/02/19/1",
          "https://access.redhat.com/security/cve/CVE-2022-25235",
          "https://blog.hartwork.org/posts/expat-2-4-5-released/",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25235",
          "https://github.com/libexpat/libexpat/pull/562",
          "https://github.com/libexpat/libexpat/pull/562/commits/367ae600b48d74261bbc339b17e9318424049791 (fix)",
          "https://github.com/libexpat/libexpat/pull/562/commits/97cfdc3fa7dca759880d81e371901f4620279106 (tests)",
          "https://linux.oracle.com/cve/CVE-2022-25235.html",
          "https://linux.oracle.com/errata/ELSA-2022-9359.html",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00007.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UFRBA3UQVIQKXTBUQXDWQOVWNBKLERU/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Y27XO3JMKAOMQZVPS3B4MJGEAHCZF5OM/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-25235",
          "https://security.gentoo.org/glsa/202209-24",
          "https://security.netapp.com/advisory/ntap-20220303-0008/",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5085",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-25235",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Malformed 2- and 3-byte UTF-8 sequences can lead to arbitrary code execution",
        "vulnerabilityID": "CVE-2022-25235"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters into namespace URIs.",
        "fixedVersion": "2.2.0-2+deb9u5",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://packetstormsecurity.com/files/167238/Zoom-XMPP-Stanza-Smuggling-Remote-Code-Execution.html",
          "http://www.openwall.com/lists/oss-security/2022/02/19/1",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-25236",
          "https://blog.hartwork.org/posts/expat-2-4-5-released/",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25236",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/561",
          "https://github.com/libexpat/libexpat/pull/561/commits/2de077423fb22750ebea599677d523b53cb93b1d (test)",
          "https://github.com/libexpat/libexpat/pull/561/commits/a2fe525e660badd64b6c557c2b1ec26ddc07f6e4 (fix)",
          "https://github.com/libexpat/libexpat/pull/577",
          "https://linux.oracle.com/cve/CVE-2022-25236.html",
          "https://linux.oracle.com/errata/ELSA-2022-9359.html",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00007.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UFRBA3UQVIQKXTBUQXDWQOVWNBKLERU/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Y27XO3JMKAOMQZVPS3B4MJGEAHCZF5OM/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-25236",
          "https://security.gentoo.org/glsa/202209-24",
          "https://security.netapp.com/advisory/ntap-20220303-0008/",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5085",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-25236",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Namespace-separator characters in \"xmlns[:prefix]\" attribute values can lead to arbitrary code execution",
        "vulnerabilityID": "CVE-2022-25236"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In Expat (aka libexpat) before 2.4.5, there is an integer overflow in storeRawNames.",
        "fixedVersion": "2.2.0-2+deb9u5",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/02/19/1",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-25315",
          "https://blog.hartwork.org/posts/expat-2-4-5-released/",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25315",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/559",
          "https://linux.oracle.com/cve/CVE-2022-25315.html",
          "https://linux.oracle.com/errata/ELSA-2022-9359.html",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00007.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UFRBA3UQVIQKXTBUQXDWQOVWNBKLERU/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Y27XO3JMKAOMQZVPS3B4MJGEAHCZF5OM/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-25315",
          "https://security.gentoo.org/glsa/202209-24",
          "https://security.netapp.com/advisory/ntap-20220303-0008/",
          "https://ubuntu.com/security/notices/USN-5320-1",
          "https://www.debian.org/security/2022/dsa-5085",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-25315",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in storeRawNames()",
        "vulnerabilityID": "CVE-2022-25315"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c.",
        "fixedVersion": "",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "https://access.redhat.com/errata/RHSA-2022:7026",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-40674.json",
          "https://access.redhat.com/security/cve/CVE-2022-40674",
          "https://blog.hartwork.org/posts/expat-2-4-9-released/",
          "https://bugzilla.redhat.com/2130769",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40674",
          "https://errata.almalinux.org/9/ALSA-2022-7026.html",
          "https://github.com/advisories/GHSA-2vq2-xc55-3j5m",
          "https://github.com/libexpat/libexpat/pull/629",
          "https://github.com/libexpat/libexpat/pull/640",
          "https://linux.oracle.com/cve/CVE-2022-40674.html",
          "https://linux.oracle.com/errata/ELSA-2022-7026.html",
          "https://lists.debian.org/debian-lts-announce/2022/09/msg00029.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/J2IGJNHFV53PYST7VQV3T4NHVYAMXA36/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WE2ZKEPGFCZ7R6DRVH3K6RBJPT42ZBEG/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-40674",
          "https://security.gentoo.org/glsa/202209-24",
          "https://ubuntu.com/security/notices/USN-5638-1",
          "https://www.debian.org/security/2022/dsa-5236"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-40674",
        "resource": "libexpat1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: a use-after-free in the doContent function in xmlparse.c",
        "vulnerabilityID": "CVE-2022-40674"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.8,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In libexpat in Expat before 2.2.7, XML input including XML names that contain a large number of colons could make the XML parser consume a high amount of RAM and CPU resources while processing (enough to be usable for denial-of-service attacks).",
        "fixedVersion": "2.2.0-2+deb9u2",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00039.html",
          "https://access.redhat.com/security/cve/CVE-2018-20843",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=5226",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=931031",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20843",
          "https://github.com/libexpat/libexpat/blob/R_2_2_7/expat/Changes",
          "https://github.com/libexpat/libexpat/issues/186",
          "https://github.com/libexpat/libexpat/pull/262",
          "https://github.com/libexpat/libexpat/pull/262/commits/11f8838bf99ea0a6f0b76f9760c43704d00c4ff6",
          "https://linux.oracle.com/cve/CVE-2018-20843.html",
          "https://linux.oracle.com/errata/ELSA-2020-4484.html",
          "https://lists.debian.org/debian-lts-announce/2019/06/msg00028.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CEJJSQSG3KSUQY4FPVHZ7ZTT7FORMFVD/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IDAUGEB3TUP6NEKJDBUBZX7N5OAUOOOK/",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-20843",
          "https://seclists.org/bugtraq/2019/Jun/39",
          "https://security.gentoo.org/glsa/201911-08",
          "https://security.netapp.com/advisory/ntap-20190703-0001/",
          "https://support.f5.com/csp/article/K51011533",
          "https://ubuntu.com/security/notices/USN-4040-1",
          "https://ubuntu.com/security/notices/USN-4040-2",
          "https://usn.ubuntu.com/4040-1/",
          "https://usn.ubuntu.com/4040-2/",
          "https://www.debian.org/security/2019/dsa-4472",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2020.html",
          "https://www.oracle.com/security-alerts/cpuoct2020.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html",
          "https://www.tenable.com/security/tns-2021-11"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-20843",
        "resource": "libexpat1",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: large number of colons in input makes parser consume high amount of resources, leading to DoS",
        "vulnerabilityID": "CVE-2018-20843"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to document parsing too early; a consecutive call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber) then resulted in a heap-based buffer over-read.",
        "fixedVersion": "2.2.0-2+deb9u3",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00080.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00081.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00000.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00002.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00003.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00013.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00016.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00017.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00018.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00019.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00008.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00040.html",
          "http://packetstormsecurity.com/files/154503/Slackware-Security-Advisory-expat-Updates.html",
          "http://packetstormsecurity.com/files/154927/Slackware-Security-Advisory-python-Updates.html",
          "http://packetstormsecurity.com/files/154947/Slackware-Security-Advisory-mozilla-firefox-Updates.html",
          "http://seclists.org/fulldisclosure/2019/Dec/23",
          "http://seclists.org/fulldisclosure/2019/Dec/26",
          "http://seclists.org/fulldisclosure/2019/Dec/27",
          "http://seclists.org/fulldisclosure/2019/Dec/30",
          "https://access.redhat.com/errata/RHSA-2019:3210",
          "https://access.redhat.com/errata/RHSA-2019:3237",
          "https://access.redhat.com/errata/RHSA-2019:3756",
          "https://access.redhat.com/security/cve/CVE-2019-15903",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15903",
          "https://github.com/libexpat/libexpat/commit/c20b758c332d9a13afbbb276d30db1d183a85d43",
          "https://github.com/libexpat/libexpat/issues/317",
          "https://github.com/libexpat/libexpat/issues/342",
          "https://github.com/libexpat/libexpat/pull/318",
          "https://linux.oracle.com/cve/CVE-2019-15903.html",
          "https://linux.oracle.com/errata/ELSA-2020-4484.html",
          "https://lists.debian.org/debian-lts-announce/2019/11/msg00006.html",
          "https://lists.debian.org/debian-lts-announce/2019/11/msg00017.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/A4TZKPJFTURRLXIGLB34WVKQ5HGY6JJA/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BDUTI5TVQWIGGQXPEVI4T2ENHFSBMIBP/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S26LGXXQ7YF2BP3RGOWELBFKM6BHF6UG/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-15903",
          "https://seclists.org/bugtraq/2019/Dec/17",
          "https://seclists.org/bugtraq/2019/Dec/21",
          "https://seclists.org/bugtraq/2019/Dec/23",
          "https://seclists.org/bugtraq/2019/Nov/1",
          "https://seclists.org/bugtraq/2019/Nov/24",
          "https://seclists.org/bugtraq/2019/Oct/29",
          "https://seclists.org/bugtraq/2019/Sep/30",
          "https://seclists.org/bugtraq/2019/Sep/37",
          "https://security.gentoo.org/glsa/201911-08",
          "https://security.netapp.com/advisory/ntap-20190926-0004/",
          "https://support.apple.com/kb/HT210785",
          "https://support.apple.com/kb/HT210788",
          "https://support.apple.com/kb/HT210789",
          "https://support.apple.com/kb/HT210790",
          "https://support.apple.com/kb/HT210793",
          "https://support.apple.com/kb/HT210794",
          "https://support.apple.com/kb/HT210795",
          "https://ubuntu.com/security/notices/USN-4132-1",
          "https://ubuntu.com/security/notices/USN-4132-2",
          "https://ubuntu.com/security/notices/USN-4165-1",
          "https://ubuntu.com/security/notices/USN-4202-1",
          "https://ubuntu.com/security/notices/USN-4335-1",
          "https://usn.ubuntu.com/4132-1/",
          "https://usn.ubuntu.com/4132-2/",
          "https://usn.ubuntu.com/4165-1/",
          "https://usn.ubuntu.com/4202-1/",
          "https://usn.ubuntu.com/4335-1/",
          "https://www.debian.org/security/2019/dsa-4530",
          "https://www.debian.org/security/2019/dsa-4549",
          "https://www.debian.org/security/2019/dsa-4571",
          "https://www.mozilla.org/en-US/security/advisories/mfsa2019-34/#CVE-2019-15903",
          "https://www.oracle.com/security-alerts/cpuapr2020.html",
          "https://www.oracle.com/security-alerts/cpuoct2020.html",
          "https://www.tenable.com/security/tns-2021-11"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-15903",
        "resource": "libexpat1",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: heap-based buffer over-read via crafted XML input",
        "vulnerabilityID": "CVE-2019-15903"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 9,
            "V2Vector": "AV:N/AC:L/Au:S/C:C/I:C/A:C",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/01/17/3",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2021-45960",
          "https://bugzilla.mozilla.org/show_bug.cgi?id=1217609",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45960",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/issues/531",
          "https://github.com/libexpat/libexpat/pull/534",
          "https://github.com/libexpat/libexpat/pull/534/commits/0adcb34c49bee5b19bd29b16a578c510c23597ea",
          "https://linux.oracle.com/cve/CVE-2021-45960.html",
          "https://linux.oracle.com/errata/ELSA-2022-1069.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-45960",
          "https://security.gentoo.org/glsa/202209-24",
          "https://security.netapp.com/advisory/ntap-20220121-0004/",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-45960",
        "resource": "libexpat1",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Large number of prefixed XML attributes on a single tag can crash libexpat",
        "vulnerabilityID": "CVE-2021-45960"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In doProlog in xmlparse.c in Expat (aka libexpat) before 2.4.3, an integer overflow exists for m_groupSize.",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/01/17/3",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2021-46143",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-46143",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/issues/532",
          "https://github.com/libexpat/libexpat/pull/538",
          "https://linux.oracle.com/cve/CVE-2021-46143.html",
          "https://linux.oracle.com/errata/ELSA-2022-9227.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-46143",
          "https://security.gentoo.org/glsa/202209-24",
          "https://security.netapp.com/advisory/ntap-20220121-0006/",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-46143",
        "resource": "libexpat1",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in doProlog in xmlparse.c",
        "vulnerabilityID": "CVE-2021-46143"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "lookup in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/01/17/3",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-22825",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22825",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/539",
          "https://linux.oracle.com/cve/CVE-2022-22825.html",
          "https://linux.oracle.com/errata/ELSA-2022-1069.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-22825",
          "https://security.gentoo.org/glsa/202209-24",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-22825",
        "resource": "libexpat1",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in lookup in xmlparse.c",
        "vulnerabilityID": "CVE-2022-22825"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "nextScaffoldPart in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/01/17/3",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-22826",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22826",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/539",
          "https://linux.oracle.com/cve/CVE-2022-22826.html",
          "https://linux.oracle.com/errata/ELSA-2022-1069.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-22826",
          "https://security.gentoo.org/glsa/202209-24",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-22826",
        "resource": "libexpat1",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in nextScaffoldPart in xmlparse.c",
        "vulnerabilityID": "CVE-2022-22826"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "storeAtts in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.",
        "fixedVersion": "2.2.0-2+deb9u4",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/01/17/3",
          "https://access.redhat.com/errata/RHSA-2022:0951",
          "https://access.redhat.com/security/cve/CVE-2022-22827",
          "https://bugzilla.redhat.com/2044451",
          "https://bugzilla.redhat.com/2044455",
          "https://bugzilla.redhat.com/2044457",
          "https://bugzilla.redhat.com/2044464",
          "https://bugzilla.redhat.com/2044467",
          "https://bugzilla.redhat.com/2044479",
          "https://bugzilla.redhat.com/2044484",
          "https://bugzilla.redhat.com/2044488",
          "https://bugzilla.redhat.com/2044613",
          "https://bugzilla.redhat.com/2056363",
          "https://bugzilla.redhat.com/2056366",
          "https://bugzilla.redhat.com/2056370",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22827",
          "https://errata.almalinux.org/8/ALSA-2022-0951.html",
          "https://github.com/libexpat/libexpat/pull/539",
          "https://linux.oracle.com/cve/CVE-2022-22827.html",
          "https://linux.oracle.com/errata/ELSA-2022-1069.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-22827",
          "https://security.gentoo.org/glsa/202209-24",
          "https://ubuntu.com/security/notices/USN-5288-1",
          "https://www.debian.org/security/2022/dsa-5073",
          "https://www.tenable.com/security/tns-2022-05"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-22827",
        "resource": "libexpat1",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: Integer overflow in storeAtts in xmlparse.c",
        "vulnerabilityID": "CVE-2022-22827"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In Expat (aka libexpat) before 2.4.5, an attacker can trigger stack exhaustion in build_model via a large nesting depth in the DTD element.",
        "fixedVersion": "2.2.0-2+deb9u5",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/02/19/1",
          "https://access.redhat.com/errata/RHSA-2022:5244",
          "https://access.redhat.com/security/cve/CVE-2022-25313",
          "https://blog.hartwork.org/posts/expat-2-4-5-released/",
          "https://bugzilla.redhat.com/2056350",
          "https://bugzilla.redhat.com/2056354",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-484086.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25313",
          "https://errata.almalinux.org/9/ALSA-2022-5244.html",
          "https://github.com/libexpat/libexpat/pull/558",
          "https://linux.oracle.com/cve/CVE-2022-25313.html",
          "https://linux.oracle.com/errata/ELSA-2022-5314.html",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00007.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UFRBA3UQVIQKXTBUQXDWQOVWNBKLERU/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Y27XO3JMKAOMQZVPS3B4MJGEAHCZF5OM/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-25313",
          "https://security.gentoo.org/glsa/202209-24",
          "https://security.netapp.com/advisory/ntap-20220303-0008/",
          "https://ubuntu.com/security/notices/USN-5320-1",
          "https://www.debian.org/security/2022/dsa-5085",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-25313",
        "resource": "libexpat1",
        "score": 6.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: stack exhaustion in doctype parsing",
        "vulnerabilityID": "CVE-2022-25313"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P"
          },
          "redhat": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P"
          }
        },
        "description": "expat 2.1.0 and earlier does not properly handle entities expansion unless an application developer uses the XML_SetEntityDeclHandler function, which allows remote attackers to cause a denial of service (resource consumption), send HTTP requests to intranet servers, or read arbitrary files via a crafted XML document, aka an XML External Entity (XXE) issue.  NOTE: it could be argued that because expat already provides the ability to disable external entity expansion, the responsibility for resolving this issue lies with application developers; according to this argument, this entry should be REJECTed, and each affected application would need its own CVE.",
        "fixedVersion": "",
        "installedVersion": "2.2.0-2+deb9u1",
        "links": [
          "http://openwall.com/lists/oss-security/2013/02/22/3",
          "http://seclists.org/fulldisclosure/2021/Oct/61",
          "http://seclists.org/fulldisclosure/2021/Oct/62",
          "http://seclists.org/fulldisclosure/2021/Oct/63",
          "http://seclists.org/fulldisclosure/2021/Sep/33",
          "http://seclists.org/fulldisclosure/2021/Sep/34",
          "http://seclists.org/fulldisclosure/2021/Sep/35",
          "http://seclists.org/fulldisclosure/2021/Sep/38",
          "http://seclists.org/fulldisclosure/2021/Sep/39",
          "http://seclists.org/fulldisclosure/2021/Sep/40",
          "http://securitytracker.com/id?1028213",
          "http://www.openwall.com/lists/oss-security/2013/04/12/6",
          "http://www.openwall.com/lists/oss-security/2021/10/07/4",
          "http://www.osvdb.org/90634",
          "http://www.securityfocus.com/bid/58233",
          "https://access.redhat.com/security/cve/CVE-2013-0340",
          "https://lists.apache.org/thread.html/r41eca5f4f09e74436cbb05dec450fc2bef37b5d3e966aa7cc5fada6d@%3Cannounce.apache.org%3E",
          "https://lists.apache.org/thread.html/rfb2c193360436e230b85547e85a41bea0916916f96c501f5b6fc4702@%3Cusers.openoffice.apache.org%3E",
          "https://nvd.nist.gov/vuln/detail/CVE-2013-0340",
          "https://security.gentoo.org/glsa/201701-21",
          "https://support.apple.com/kb/HT212804",
          "https://support.apple.com/kb/HT212805",
          "https://support.apple.com/kb/HT212807",
          "https://support.apple.com/kb/HT212814",
          "https://support.apple.com/kb/HT212815",
          "https://support.apple.com/kb/HT212819"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2013-0340",
        "resource": "libexpat1",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "expat: internal entity expansion",
        "vulnerabilityID": "CVE-2013-0340"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/02/27/1",
          "http://www.openwall.com/lists/oss-security/2016/02/27/2",
          "https://access.redhat.com/security/cve/CVE-2016-2779",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2779",
        "resource": "libfdisk1",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: runuser tty hijack via TIOCSTI ioctl",
        "vulnerabilityID": "CVE-2016-2779"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-37600",
          "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
          "https://github.com/karelzak/util-linux/issues/1395",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
          "https://security.netapp.com/advisory/ntap-20210902-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-37600",
        "resource": "libfdisk1",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
        "vulnerabilityID": "CVE-2021-37600"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0563",
          "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
          "https://security.netapp.com/advisory/ntap-20220331-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0563",
        "resource": "libfdisk1",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
        "vulnerabilityID": "CVE-2022-0563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.6,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H"
          }
        },
        "description": "FreeType commit 1e2eb65048f75c64b68708efed6ce904c31f3b2f was discovered to contain a heap buffer overflow via the function sfnt_init_face.",
        "fixedVersion": "",
        "installedVersion": "2.6.3-3.2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-27404",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-27404",
          "https://gitlab.freedesktop.org/freetype/freetype/-/issues/1138",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EFPNRKDLCXHZVYYQLQMP44UHLU32GA6Z/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FDU2FOEMCEF6WVR6ZBIH5MT5O7FAK6UP/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IWQ7IB2A75MEHM63WEUXBYEC7OR5SGDY/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NYVC2NPKKXKP3TWJWG4ONYWNO6ZPHLA5/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TCEMWCM46PKM4U5ENRASPKQD6JDOLKRU/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-27404",
          "https://ubuntu.com/security/notices/USN-5528-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-27404",
        "resource": "libfreetype6",
        "score": 7.6,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "FreeType: Buffer overflow in sfnt_init_face",
        "vulnerabilityID": "CVE-2022-27404"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "FreeType commit 53dfdcd8198d2b3201a23c4bad9190519ba918db was discovered to contain a segmentation violation via the function FNT_Size_Request.",
        "fixedVersion": "",
        "installedVersion": "2.6.3-3.2",
        "links": [
          "http://freetype.com",
          "https://access.redhat.com/security/cve/CVE-2022-27405",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-27405",
          "https://gitlab.freedesktop.org/freetype/freetype/-/issues/1139",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EFPNRKDLCXHZVYYQLQMP44UHLU32GA6Z/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FDU2FOEMCEF6WVR6ZBIH5MT5O7FAK6UP/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IWQ7IB2A75MEHM63WEUXBYEC7OR5SGDY/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NYVC2NPKKXKP3TWJWG4ONYWNO6ZPHLA5/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TCEMWCM46PKM4U5ENRASPKQD6JDOLKRU/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-27405",
          "https://ubuntu.com/security/notices/USN-5528-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-27405",
        "resource": "libfreetype6",
        "score": 7.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "FreeType: Segmentation violation via FNT_Size_Request",
        "vulnerabilityID": "CVE-2022-27405"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "FreeType commit 22a0cccb4d9d002f33c1ba7a4b36812c7d4f46b5 was discovered to contain a segmentation violation via the function FT_Request_Size.",
        "fixedVersion": "",
        "installedVersion": "2.6.3-3.2",
        "links": [
          "http://freetype.com",
          "https://access.redhat.com/security/cve/CVE-2022-27406",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-27406",
          "https://gitlab.freedesktop.org/freetype/freetype/-/issues/1140",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EFPNRKDLCXHZVYYQLQMP44UHLU32GA6Z/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FDU2FOEMCEF6WVR6ZBIH5MT5O7FAK6UP/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IWQ7IB2A75MEHM63WEUXBYEC7OR5SGDY/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NYVC2NPKKXKP3TWJWG4ONYWNO6ZPHLA5/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TCEMWCM46PKM4U5ENRASPKQD6JDOLKRU/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-27406",
          "https://ubuntu.com/security/notices/USN-5453-1",
          "https://ubuntu.com/security/notices/USN-5528-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-27406",
        "resource": "libfreetype6",
        "score": 7.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "Freetype: Segmentation violation via FT_Request_Size",
        "vulnerabilityID": "CVE-2022-27406"
      },
      {
        "cvss": {
          "ghsa": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "Heap buffer overflow in Freetype in Google Chrome prior to 86.0.4240.111 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.",
        "fixedVersion": "2.6.3-3.2+deb9u2",
        "installedVersion": "2.6.3-3.2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00016.html",
          "http://seclists.org/fulldisclosure/2020/Nov/33",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-15999.json",
          "https://access.redhat.com/security/cve/CVE-2020-15999",
          "https://bugs.chromium.org/p/project-zero/issues/detail?id=2103",
          "https://chromereleases.googleblog.com/2020/10/stable-channel-update-for-desktop_20.html",
          "https://crbug.com/1139963",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15999",
          "https://errata.almalinux.org/8/ALSA-2020-4952.html",
          "https://github.com/advisories/GHSA-pv36-h7jh-qm62",
          "https://github.com/cefsharp/CefSharp/security/advisories/GHSA-pv36-h7jh-qm62",
          "https://googleprojectzero.blogspot.com/p/rca-cve-2020-15999.html",
          "https://linux.oracle.com/cve/CVE-2020-15999.html",
          "https://linux.oracle.com/errata/ELSA-2020-4952.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/J3QVIGAAJ4D62YEJAJJWMCCBCOQ6TVL7/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-15999",
          "https://security.gentoo.org/glsa/202011-12",
          "https://security.gentoo.org/glsa/202012-04",
          "https://ubuntu.com/security/notices/USN-4593-1",
          "https://ubuntu.com/security/notices/USN-4593-2",
          "https://www.debian.org/security/2021/dsa-4824",
          "https://www.mozilla.org/en-US/security/advisories/mfsa2020-52/#CVE-2020-15999",
          "https://www.nuget.org/packages/CefSharp.Common/",
          "https://www.nuget.org/packages/CefSharp.WinForms",
          "https://www.nuget.org/packages/CefSharp.Wpf",
          "https://www.nuget.org/packages/CefSharp.Wpf.HwndHost"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-15999",
        "resource": "libfreetype6",
        "score": 8.6,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "freetype: Heap-based buffer overflow due to integer truncation in Load_SBit_Png",
        "vulnerabilityID": "CVE-2020-15999"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "ftbench.c in FreeType Demo Programs through 2.12.1 has a heap-based buffer overflow.",
        "fixedVersion": "",
        "installedVersion": "2.6.3-3.2",
        "links": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31782",
          "https://gitlab.freedesktop.org/freetype/freetype-demos/-/issues/8",
          "https://ubuntu.com/security/notices/USN-5528-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-31782",
        "resource": "libfreetype6",
        "score": 7.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ftbench.c in FreeType Demo Programs through 2.12.1 has a heap-based bu ...",
        "vulnerabilityID": "CVE-2022-31782"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H"
          }
        },
        "description": "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
        "fixedVersion": "",
        "installedVersion": "6.3.0-18+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-12886",
          "https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379\u0026view=markup",
          "https://www.gnu.org/software/gcc/gcc-8/changes.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-12886",
        "resource": "libgcc1",
        "score": 6.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gcc: spilling of stack protection address in cfgexpand.c and function.c leads to stack-overflow protection bypass",
        "vulnerabilityID": "CVE-2018-12886"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appropriately. This, for example, affects use of ElGamal in OpenPGP.",
        "fixedVersion": "",
        "installedVersion": "1.7.6-2+deb9u3",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-33560.json",
          "https://access.redhat.com/security/cve/CVE-2021-33560",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33560",
          "https://dev.gnupg.org/T5305",
          "https://dev.gnupg.org/T5328",
          "https://dev.gnupg.org/T5466",
          "https://dev.gnupg.org/rCe8b7f10be275bcedb5fc05ed4837a89bfd605c61",
          "https://eprint.iacr.org/2021/923",
          "https://errata.almalinux.org/8/ALSA-2021-4409.html",
          "https://linux.oracle.com/cve/CVE-2021-33560.html",
          "https://linux.oracle.com/errata/ELSA-2022-9263.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BKKTOIGFW2SGN3DO2UHHVZ7MJSYN4AAB/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R7OAPCUGPF3VLA7QAJUQSL255D4ITVTL/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-33560",
          "https://ubuntu.com/security/notices/USN-5080-1",
          "https://ubuntu.com/security/notices/USN-5080-2",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-33560",
        "resource": "libgcrypt20",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libgcrypt: mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm",
        "vulnerabilityID": "CVE-2021-33560"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.6,
            "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:N",
            "V3Score": 6.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
          },
          "redhat": {
            "V3Score": 6.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
          }
        },
        "description": "It was discovered that there was a ECDSA timing attack in the libgcrypt20 cryptographic library. Version affected: 1.8.4-5, 1.7.6-2+deb9u3, and 1.6.3-2+deb8u4. Versions fixed: 1.8.5-2 and 1.6.3-2+deb8u7.",
        "fixedVersion": "",
        "installedVersion": "1.7.6-2+deb9u3",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00060.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00018.html",
          "http://www.openwall.com/lists/oss-security/2019/10/02/2",
          "https://access.redhat.com/security/cve/CVE-2019-13627",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13627",
          "https://dev.gnupg.org/T4683",
          "https://github.com/gpg/libgcrypt/releases/tag/libgcrypt-1.8.5",
          "https://linux.oracle.com/cve/CVE-2019-13627.html",
          "https://linux.oracle.com/errata/ELSA-2020-4482.html",
          "https://lists.debian.org/debian-lts-announce/2019/09/msg00024.html",
          "https://lists.debian.org/debian-lts-announce/2020/01/msg00001.html",
          "https://minerva.crocs.fi.muni.cz/",
          "https://security-tracker.debian.org/tracker/CVE-2019-13627",
          "https://security.gentoo.org/glsa/202003-32",
          "https://ubuntu.com/security/notices/USN-4236-1",
          "https://ubuntu.com/security/notices/USN-4236-2",
          "https://ubuntu.com/security/notices/USN-4236-3",
          "https://usn.ubuntu.com/4236-1/",
          "https://usn.ubuntu.com/4236-2/",
          "https://usn.ubuntu.com/4236-3/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-13627",
        "resource": "libgcrypt20",
        "score": 6.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libgcrypt: ECDSA timing attack allowing private key leak",
        "vulnerabilityID": "CVE-2019-13627"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.6,
            "V2Vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "The ElGamal implementation in Libgcrypt before 1.9.4 allows plaintext recovery because, during interaction between two cryptographic libraries, a certain dangerous combination of the prime defined by the receiver's public key, the generator defined by the receiver's public key, and the sender's ephemeral exponents can lead to a cross-configuration attack against OpenPGP.",
        "fixedVersion": "1.7.6-2+deb9u4",
        "installedVersion": "1.7.6-2+deb9u3",
        "links": [
          "https://access.redhat.com/errata/RHSA-2022:5311",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-40528.json",
          "https://access.redhat.com/security/cve/CVE-2021-40528",
          "https://bugzilla.redhat.com/2002816",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40528",
          "https://dev.gnupg.org/rCb118681ebc4c9ea4b9da79b0f9541405a64f4c13",
          "https://eprint.iacr.org/2021/923",
          "https://errata.almalinux.org/8/ALSA-2022-5311.html",
          "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libgcrypt.git;a=commit;h=3462280f2e23e16adf3ed5176e0f2413d8861320",
          "https://ibm.github.io/system-security-research-updates/2021/07/20/insecurity-elgamal-pt1",
          "https://ibm.github.io/system-security-research-updates/2021/09/06/insecurity-elgamal-pt2",
          "https://linux.oracle.com/cve/CVE-2021-40528.html",
          "https://linux.oracle.com/errata/ELSA-2022-9564.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-40528",
          "https://ubuntu.com/security/notices/USN-5080-1",
          "https://ubuntu.com/security/notices/USN-5080-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-40528",
        "resource": "libgcrypt20",
        "score": 5.9,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libgcrypt: ElGamal implementation allows plaintext recovery",
        "vulnerabilityID": "CVE-2021-40528"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "cipher/elgamal.c in Libgcrypt through 1.8.2, when used to encrypt messages directly, improperly encodes plaintexts, which allows attackers to obtain sensitive information by reading ciphertext data (i.e., it does not have semantic security in face of a ciphertext-only attack). The Decisional Diffie-Hellman (DDH) assumption does not hold for Libgcrypt's ElGamal implementation.",
        "fixedVersion": "",
        "installedVersion": "1.7.6-2+deb9u3",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-6829",
          "https://github.com/weikengchen/attack-on-libgcrypt-elgamal",
          "https://github.com/weikengchen/attack-on-libgcrypt-elgamal/wiki",
          "https://lists.gnupg.org/pipermail/gcrypt-devel/2018-February/004394.html",
          "https://www.oracle.com/security-alerts/cpujan2020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6829",
        "resource": "libgcrypt20",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libgcrypt: ElGamal implementation doesn't have semantic security due to incorrectly encoded plaintexts possibly allowing to obtain sensitive information",
        "vulnerabilityID": "CVE-2018-6829"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** In the GD Graphics Library (aka LibGD) through 2.2.5, there is a heap-based buffer over-read in tiffWriter in gd_tiff.c. NOTE: the vendor says \"In my opinion this issue should not have a CVE, since the GD and GD2 formats are documented to be 'obsolete, and should only be used for development and testing purposes.'\"",
        "fixedVersion": "",
        "installedVersion": "2.2.4-2+deb9u4",
        "links": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6363",
          "https://github.com/libgd/libgd/commit/0be86e1926939a98afbd2f3a23c673dfc4df2a7c",
          "https://github.com/libgd/libgd/commit/2dbd8f6e66b73ed43d9b81a45350922b80f75397",
          "https://github.com/libgd/libgd/issues/383",
          "https://ubuntu.com/security/notices/USN-5068-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-6363",
        "resource": "libgd3",
        "score": 8.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "** DISPUTED ** In the GD Graphics Library (aka LibGD) through 2.2.5, t ...",
        "vulnerabilityID": "CVE-2017-6363"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "read_header_tga in gd_tga.c in the GD Graphics Library (aka LibGD) through 2.3.2 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted TGA file.",
        "fixedVersion": "",
        "installedVersion": "2.2.4-2+deb9u4",
        "links": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38115",
          "https://github.com/libgd/libgd/commit/8b111b2b4a4842179be66db68d84dda91a246032",
          "https://github.com/libgd/libgd/issues/697",
          "https://github.com/libgd/libgd/pull/711/commits/8b111b2b4a4842179be66db68d84dda91a246032",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-38115",
          "https://ubuntu.com/security/notices/USN-5068-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-38115",
        "resource": "libgd3",
        "score": 6.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "read_header_tga in gd_tga.c in the GD Graphics Library (aka LibGD) thr ...",
        "vulnerabilityID": "CVE-2021-38115"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The GD Graphics Library (aka LibGD) through 2.3.2 has an out-of-bounds read because of the lack of certain gdGetBuf and gdPutBuf return value checks.",
        "fixedVersion": "",
        "installedVersion": "2.2.4-2+deb9u4",
        "links": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40812",
          "https://github.com/libgd/libgd/commit/6f5136821be86e7068fcdf651ae9420b5d42e9a9",
          "https://github.com/libgd/libgd/issues/750#issuecomment-914872385",
          "https://github.com/libgd/libgd/issues/757",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-40812"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-40812",
        "resource": "libgd3",
        "score": 6.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "The GD Graphics Library (aka LibGD) through 2.3.2 has an out-of-bounds ...",
        "vulnerabilityID": "CVE-2021-40812"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H"
          }
        },
        "description": "gdImageClone in gd.c in libgd 2.1.0-rc2 through 2.2.5 has a NULL pointer dereference allowing attackers to crash an application via a specific function call sequence. Only affects PHP when linked with an external libgd (not bundled).",
        "fixedVersion": "",
        "installedVersion": "2.2.4-2+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00020.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-14553.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-6977.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-6978.json",
          "https://access.redhat.com/security/cve/CVE-2018-14553",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1599032",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14553",
          "https://github.com/libgd/libgd/commit/a93eac0e843148dc2d631c3ba80af17e9c8c860f",
          "https://github.com/libgd/libgd/pull/580",
          "https://linux.oracle.com/cve/CVE-2018-14553.html",
          "https://linux.oracle.com/errata/ELSA-2020-4659.html",
          "https://lists.debian.org/debian-lts-announce/2020/02/msg00014.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3CZ2QADQTKRHTGB2AHD7J4QQNDLBEMM6/",
          "https://ubuntu.com/security/notices/USN-4316-1",
          "https://ubuntu.com/security/notices/USN-4316-2",
          "https://usn.ubuntu.com/4316-1/",
          "https://usn.ubuntu.com/4316-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-14553",
        "resource": "libgd3",
        "score": 7.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gd: NULL pointer dereference in gdImageClone",
        "vulnerabilityID": "CVE-2018-14553"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
          }
        },
        "description": "When using the gdImageCreateFromXbm() function in the GD Graphics Library (aka LibGD) 2.2.5, as used in the PHP GD extension in PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and 7.3.x below 7.3.6, it is possible to supply data that will cause the function to use the value of uninitialized variable. This may lead to disclosing contents of the stack that has been left there by previous code.",
        "fixedVersion": "2.2.4-2+deb9u5",
        "installedVersion": "2.2.4-2+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00020.html",
          "https://access.redhat.com/errata/RHSA-2019:2519",
          "https://access.redhat.com/errata/RHSA-2019:3299",
          "https://access.redhat.com/security/cve/CVE-2019-11038",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=929821",
          "https://bugs.php.net/bug.php?id=77973",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1724149",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1724432",
          "https://bugzilla.suse.com/show_bug.cgi?id=1140118",
          "https://bugzilla.suse.com/show_bug.cgi?id=1140120",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11038",
          "https://github.com/libgd/libgd/issues/501",
          "https://lists.debian.org/debian-lts-announce/2019/06/msg00003.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3CZ2QADQTKRHTGB2AHD7J4QQNDLBEMM6/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PKSSWFR2WPMUOIB5EN5ZM252NNEPYUTG/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WAZBVK6XNYEIN7RDQXESSD63QHXPLKWL/",
          "https://seclists.org/bugtraq/2019/Sep/38",
          "https://ubuntu.com/security/notices/USN-4316-1",
          "https://ubuntu.com/security/notices/USN-4316-2",
          "https://usn.ubuntu.com/4316-1/",
          "https://usn.ubuntu.com/4316-2/",
          "https://www.debian.org/security/2019/dsa-4529"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-11038",
        "resource": "libgd3",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gd: Information disclosure in gdImageCreateFromXbm()",
        "vulnerabilityID": "CVE-2019-11038"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** gdImageGd2Ptr in gd_gd2.c in the GD Graphics Library (aka LibGD) through 2.3.2 has a double free. NOTE: the vendor's position is \"The GD2 image format is a proprietary image format of libgd. It has to be regarded as being obsolete, and should only be used for development and testing purposes.\"",
        "fixedVersion": "",
        "installedVersion": "2.2.4-2+deb9u4",
        "links": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40145",
          "https://github.com/libgd/libgd/commit/c5fd25ce0e48fd5618a972ca9f5e28d6d62006af",
          "https://github.com/libgd/libgd/issues/700",
          "https://github.com/libgd/libgd/pull/713",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-40145",
          "https://ubuntu.com/security/notices/USN-5068-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-40145",
        "resource": "libgd3",
        "score": 7.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "** DISPUTED ** gdImageGd2Ptr in gd_gd2.c in the GD Graphics Library (a ...",
        "vulnerabilityID": "CVE-2021-40145"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An issue was discovered in International Components for Unicode (ICU) for C/C++ through 66.1. An integer overflow, leading to a heap-based buffer overflow, exists in the UnicodeString::doAppend() function in common/unistr.cpp.",
        "fixedVersion": "57.1-6+deb9u4",
        "installedVersion": "57.1-6+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00004.html",
          "https://access.redhat.com/errata/RHSA-2020:0738",
          "https://access.redhat.com/security/cve/CVE-2020-10531",
          "https://bugs.chromium.org/p/chromium/issues/detail?id=1044570",
          "https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop_24.html",
          "https://chromium.googlesource.com/chromium/deps/icu/+/9f4020916eb1f28f3666f018fdcbe6c9a37f0e08",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10531",
          "https://errata.almalinux.org/8/ALSA-2020-1317.html",
          "https://github.com/unicode-org/icu/commit/b7d08bc04a4296982fcef8b6b8a354a9e4e7afca",
          "https://github.com/unicode-org/icu/pull/971",
          "https://linux.oracle.com/cve/CVE-2020-10531.html",
          "https://linux.oracle.com/errata/ELSA-2020-1317.html",
          "https://lists.debian.org/debian-lts-announce/2020/03/msg00024.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4OOYAMJVLLCLXDTHW3V5UXNULZBBK4O6/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6IOHSO6BUKC6I66J5PZOMAGFVJ66ZS57/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/X3B5RWJQD5LA45MYLLR55KZJOJ5NVZGP/",
          "https://security.gentoo.org/glsa/202003-15",
          "https://ubuntu.com/security/notices/USN-4305-1",
          "https://unicode-org.atlassian.net/browse/ICU-20958",
          "https://usn.ubuntu.com/4305-1/",
          "https://www.debian.org/security/2020/dsa-4646",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-10531",
        "resource": "libicu57",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ICU: Integer overflow in UnicodeString::doAppend()",
        "vulnerabilityID": "CVE-2020-10531"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "International Components for Unicode (ICU-20850) v66.1 was discovered to contain a use after free bug in the pkg_createWithAssemblyCode function in the file tools/pkgdata/pkgdata.cpp.",
        "fixedVersion": "57.1-6+deb9u5",
        "installedVersion": "57.1-6+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-21913",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-21913",
          "https://github.com/unicode-org/icu/pull/886",
          "https://lists.debian.org/debian-lts-announce/2021/10/msg00008.html",
          "https://ubuntu.com/security/notices/USN-5133-1",
          "https://unicode-org.atlassian.net/browse/ICU-20850",
          "https://www.debian.org/security/2021/dsa-5014"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-21913",
        "resource": "libicu57",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "icu: Use after free in pkg_createWithAssemblyCode function in tools/pkgdata/pkgdata.cpp",
        "vulnerabilityID": "CVE-2020-21913"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In LibTIFF 4.0.8, there is a memory malloc failure in tif_jbig.c. A crafted TIFF document can lead to an abort resulting in a remote denial of service attack.",
        "fixedVersion": "",
        "installedVersion": "2.1-3.1",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2707",
          "http://www.securityfocus.com/bid/99304",
          "https://access.redhat.com/security/cve/CVE-2017-9937",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9937",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-9937",
        "resource": "libjbig0",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: memory malloc failure in tif_jbig.c could cause DOS.",
        "vulnerabilityID": "CVE-2017-9937"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 9.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In generate_jsimd_ycc_rgb_convert_neon of jsimd_arm64_neon.S, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution in an unprivileged process with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-120551338",
        "fixedVersion": "1:1.5.1-2+deb9u2",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00047.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00048.html",
          "https://access.redhat.com/security/cve/CVE-2019-2201",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2201",
          "https://lists.apache.org/thread.html/rc800763a88775ac9abb83b3402bcd0913d41ac65fdfc759af38f2280@%3Ccommits.mxnet.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/05/msg00048.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Y4QPASQPZO644STRFTLOD35RIRGWWRNI/",
          "https://security.gentoo.org/glsa/202003-23",
          "https://source.android.com/security/bulletin/2019-11-01",
          "https://ubuntu.com/security/notices/USN-4190-1",
          "https://usn.ubuntu.com/4190-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-2201",
        "resource": "libjpeg62-turbo",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg-turbo: several integer overflows and subsequent segfaults when attempting to compress/decompress gigapixel images",
        "vulnerabilityID": "CVE-2019-2201"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          }
        },
        "description": "libjpeg-turbo 2.0.4, and mozjpeg 4.0.0, has a heap-based buffer over-read in get_rgb_row() in rdppm.c via a malformed PPM input file.",
        "fixedVersion": "1:1.5.1-2+deb9u1",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00031.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00062.html",
          "https://access.redhat.com/security/cve/CVE-2020-13790",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13790",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/commit/3de15e0c344d11d4b90f4a47136467053eb2d09a",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/issues/433",
          "https://lists.debian.org/debian-lts-announce/2020/07/msg00033.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/P4D6KNUY7YANSPH7SVQ44PJKSABFKAUB/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U6563YHSVZK24MPJXGJVK3CQG7JVWZGK/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-13790",
          "https://security.gentoo.org/glsa/202010-03",
          "https://ubuntu.com/security/notices/USN-4386-1",
          "https://usn.ubuntu.com/4386-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-13790",
        "resource": "libjpeg62-turbo",
        "score": 8.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg-turbo: heap-based buffer over-read in get_rgb_row() in rdppm.c",
        "vulnerabilityID": "CVE-2020-13790"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          }
        },
        "description": "In IJG JPEG (aka libjpeg) before 9d, jpeg_mem_available() in jmemnobs.c in djpeg does not honor the max_memory_to_use setting, possibly causing excessive memory consumption.",
        "fixedVersion": "1:1.5.1-2+deb9u1",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "http://www.ijg.org/files/jpegsrc.v9d.tar.gz",
          "https://access.redhat.com/security/cve/CVE-2020-14152",
          "https://bugs.gentoo.org/727908",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14152",
          "https://lists.debian.org/debian-lts-announce/2020/07/msg00033.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-14152",
          "https://ubuntu.com/security/notices/USN-5497-1",
          "https://ubuntu.com/security/notices/USN-5553-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-14152",
        "resource": "libjpeg62-turbo",
        "score": 7.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg: improper handling of max_memory_to_use setting can lead to excessive memory consumption",
        "vulnerabilityID": "CVE-2020-14152"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "libjpeg-turbo 1.5.90 is vulnerable to a denial of service vulnerability caused by a divide by zero when processing a crafted BMP image.",
        "fixedVersion": "1:1.5.1-2+deb9u1",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00015.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00015.html",
          "http://www.securityfocus.com/bid/104543",
          "https://access.redhat.com/security/cve/CVE-2018-1152",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1152",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/commit/43e84cff1bb2bd8293066f6ac4eb0df61ddddbc6",
          "https://lists.debian.org/debian-lts-announce/2019/01/msg00015.html",
          "https://lists.debian.org/debian-lts-announce/2020/07/msg00033.html",
          "https://ubuntu.com/security/notices/USN-3706-1",
          "https://ubuntu.com/security/notices/USN-3706-2",
          "https://usn.ubuntu.com/3706-1/",
          "https://usn.ubuntu.com/3706-2/",
          "https://www.tenable.com/security/research/tra-2018-17"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-1152",
        "resource": "libjpeg62-turbo",
        "score": 4.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg-turbo: Divide by zero allows for denial of service via crafted BMP image",
        "vulnerabilityID": "CVE-2018-1152"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          }
        },
        "description": "get_8bit_row in rdbmp.c in libjpeg-turbo through 1.5.90 and MozJPEG through 3.3.1 allows attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted 8-bit BMP in which one or more of the color indices is out of range for the number of palette entries.",
        "fixedVersion": "1:1.5.1-2+deb9u1",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00015.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00015.html",
          "https://access.redhat.com/errata/RHSA-2019:2052",
          "https://access.redhat.com/errata/RHSA-2019:3705",
          "https://access.redhat.com/security/cve/CVE-2018-14498",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14498",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/commit/9c78a04df4e44ef6487eee99c4258397f4fdca55",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/issues/258",
          "https://github.com/mozilla/mozjpeg/issues/299",
          "https://linux.oracle.com/cve/CVE-2018-14498.html",
          "https://linux.oracle.com/errata/ELSA-2019-3705.html",
          "https://lists.debian.org/debian-lts-announce/2019/03/msg00021.html",
          "https://lists.debian.org/debian-lts-announce/2020/07/msg00033.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/F7YP4QUEYGHI4Q7GIAVFVKWQ7DJMBYLU/",
          "https://ubuntu.com/security/notices/USN-4190-1",
          "https://ubuntu.com/security/notices/USN-5553-1",
          "https://usn.ubuntu.com/4190-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-14498",
        "resource": "libjpeg62-turbo",
        "score": 4.4,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg-turbo: heap-based buffer over-read via crafted 8-bit BMP in get_8bit_row in rdbmp.c leads to denial of service",
        "vulnerabilityID": "CVE-2018-14498"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A crafted input file could cause a null pointer dereference in jcopy_sample_rows() when processed by libjpeg-turbo.",
        "fixedVersion": "",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-35538",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35538",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/commit/9120a247436e84c0b4eea828cb11e8f665fcde30",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/issues/441",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-35538",
          "https://ubuntu.com/security/notices/USN-5631-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-35538",
        "resource": "libjpeg62-turbo",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg-turbo: Null pointer dereference in jcopy_sample_rows() function",
        "vulnerabilityID": "CVE-2020-35538"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The PPM reader in libjpeg-turbo through 2.0.90 mishandles use of tjLoadImage for loading a 16-bit binary PPM file into a grayscale buffer and loading a 16-bit binary PGM file into an RGB buffer. This is related to a heap-based buffer overflow in the get_word_rgb_row function in rdppm.c.",
        "fixedVersion": "",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-46822",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-46822",
          "https://exchange.xforce.ibmcloud.com/vulnerabilities/221567",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/commit/f35fd27ec641c42d6b115bfa595e483ec58188d2",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-46822",
          "https://ubuntu.com/security/notices/USN-5631-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-46822",
        "resource": "libjpeg62-turbo",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg-turbo: heap buffer overflow in get_word_rgb_row() in rdppm.c",
        "vulnerabilityID": "CVE-2021-46822"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "libjpeg-turbo 1.5.2 has a NULL Pointer Dereference in jdpostct.c and jquant1.c via a crafted JPEG file.",
        "fixedVersion": "",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2017-15232",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15232",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/pull/182",
          "https://github.com/mozilla/mozjpeg/issues/268",
          "https://ubuntu.com/security/notices/USN-3706-1",
          "https://usn.ubuntu.com/3706-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-15232",
        "resource": "libjpeg62-turbo",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg-turbo: NULL pointer dereference in jdpostct.c and jquant1.c",
        "vulnerabilityID": "CVE-2017-15232"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "libjpeg 9c has a large loop because read_pixel in rdtarga.c mishandles EOF.",
        "fixedVersion": "",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00015.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00015.html",
          "http://www.ijg.org/files/jpegsrc.v9d.tar.gz",
          "https://access.redhat.com/errata/RHSA-2019:2052",
          "https://access.redhat.com/security/cve/CVE-2018-11813",
          "https://bugs.gentoo.org/727908",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11813",
          "https://github.com/ChijinZ/security_advisories/blob/master/libjpeg-v9c/mail.pdf",
          "https://github.com/ChijinZ/security_advisories/tree/master/libjpeg-v9c",
          "https://linux.oracle.com/cve/CVE-2018-11813.html",
          "https://linux.oracle.com/errata/ELSA-2019-2052.html",
          "https://ubuntu.com/security/notices/USN-5497-1",
          "https://ubuntu.com/security/notices/USN-5553-1",
          "https://ubuntu.com/security/notices/USN-5631-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-11813",
        "resource": "libjpeg62-turbo",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg: \"cjpeg\" utility large loop because read_pixel in rdtarga.c mishandles EOF",
        "vulnerabilityID": "CVE-2018-11813"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "Libjpeg-turbo all version have a stack-based buffer overflow in the \"transform\" component. A remote attacker can send a malformed jpeg file to the service and cause arbitrary code execution or denial of service of the target service.",
        "fixedVersion": "",
        "installedVersion": "1:1.5.1-2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-17541.json",
          "https://access.redhat.com/security/cve/CVE-2020-17541",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17541",
          "https://cwe.mitre.org/data/definitions/121.html",
          "https://github.com/libjpeg-turbo/libjpeg-turbo/issues/392",
          "https://linux.oracle.com/cve/CVE-2020-17541.html",
          "https://linux.oracle.com/errata/ELSA-2021-4288.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-17541",
          "https://ubuntu.com/security/notices/USN-5553-1",
          "https://ubuntu.com/security/notices/USN-5631-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-17541",
        "resource": "libjpeg62-turbo",
        "score": 8.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libjpeg-turbo: Stack-based buffer overflow in the \"transform\" component",
        "vulnerabilityID": "CVE-2020-17541"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "There's a flaw in lz4. An attacker who submits a crafted file to an application linked with lz4 may be able to trigger an integer overflow, leading to calling of memmove() on a negative size argument, causing an out-of-bounds write and/or a crash. The greatest impact of this flaw is to availability, with some potential impact to confidentiality and integrity as well.",
        "fixedVersion": "0.0~r131-2+deb9u1",
        "installedVersion": "0.0~r131-2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3520.json",
          "https://access.redhat.com/security/cve/CVE-2021-3520",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1954559",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3520",
          "https://errata.almalinux.org/8/ALSA-2021-2575.html",
          "https://github.com/lz4/lz4/pull/972",
          "https://linux.oracle.com/cve/CVE-2021-3520.html",
          "https://linux.oracle.com/errata/ELSA-2021-2575.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3520",
          "https://security.netapp.com/advisory/ntap-20211104-0005/",
          "https://ubuntu.com/security/notices/USN-4968-1",
          "https://ubuntu.com/security/notices/USN-4968-2",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3520",
        "resource": "liblz4-1",
        "score": 8.6,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "lz4: memory corruption due to an integer overflow bug caused by memmove argument",
        "vulnerabilityID": "CVE-2021-3520"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "LZ4 before 1.9.2 has a heap-based buffer overflow in LZ4_write32 (related to LZ4_compress_destSize), affecting applications that call LZ4_compress_fast with a large input. (This issue can also lead to data corruption.) NOTE: the vendor states \"only a few specific / uncommon usages of the API are at risk.\"",
        "fixedVersion": "",
        "installedVersion": "0.0~r131-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00069.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00070.html",
          "https://access.redhat.com/security/cve/CVE-2019-17543",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15941",
          "https://github.com/lz4/lz4/compare/v1.9.1...v1.9.2",
          "https://github.com/lz4/lz4/issues/801",
          "https://github.com/lz4/lz4/pull/756",
          "https://github.com/lz4/lz4/pull/760",
          "https://lists.apache.org/thread.html/25015588b770d67470b7ba7ea49a305d6735dd7f00eabe7d50ec1e17@%3Cissues.arrow.apache.org%3E",
          "https://lists.apache.org/thread.html/543302d55e2d2da4311994e9b0debdc676bf3fd05e1a2be3407aa2d6@%3Cissues.arrow.apache.org%3E",
          "https://lists.apache.org/thread.html/793012683dc0fa6819b7c2560e6cf990811014c40c7d75412099c357@%3Cissues.arrow.apache.org%3E",
          "https://lists.apache.org/thread.html/9ff0606d16be2ab6a81619e1c9e23c3e251756638e36272c8c8b7fa3@%3Cissues.arrow.apache.org%3E",
          "https://lists.apache.org/thread.html/f0038c4fab2ee25aee849ebeff6b33b3aa89e07ccfb06b5c87b36316@%3Cissues.arrow.apache.org%3E",
          "https://lists.apache.org/thread.html/f506bc371d4a068d5d84d7361293568f61167d3a1c3e91f0def2d7d3@%3Cdev.arrow.apache.org%3E",
          "https://lists.apache.org/thread.html/r0fb226357e7988a241b06b93bab065bcea2eb38658b382e485960e26@%3Cissues.kudu.apache.org%3E",
          "https://lists.apache.org/thread.html/r4068ba81066792f2b4d208b39c4c4713c5d4c79bd8cb6c1904af5720@%3Cissues.kudu.apache.org%3E",
          "https://lists.apache.org/thread.html/r7bc72200f94298bc9a0e35637f388deb53467ca4b2e2ad1ff66d8960@%3Cissues.kudu.apache.org%3E",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuoct2020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17543",
        "resource": "liblz4-1",
        "score": 8.1,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "lz4: heap-based buffer overflow in LZ4_write32",
        "vulnerabilityID": "CVE-2019-17543"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An arbitrary file write vulnerability was found in GNU gzip's zgrep utility. When zgrep is applied on the attacker's chosen file name (for example, a crafted file name), this can overwrite an attacker's content to an arbitrary attacker-selected file. This flaw occurs due to insufficient validation when processing filenames with two or more newlines where selected content and the target file names are embedded in crafted multi-line file names. This flaw allows a remote, low privileged attacker to force zgrep to write arbitrary files on the system.",
        "fixedVersion": "5.2.2-1.2+deb9u1",
        "installedVersion": "5.2.2-1.2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-1271.json",
          "https://access.redhat.com/security/cve/CVE-2022-1271",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2073310",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1271",
          "https://errata.almalinux.org/8/ALSA-2022-1537.html",
          "https://git.tukaani.org/?p=xz.git;a=commit;h=69d1b3fc29677af8ade8dc15dba83f0589cb63d6",
          "https://linux.oracle.com/cve/CVE-2022-1271.html",
          "https://linux.oracle.com/errata/ELSA-2022-5052.html",
          "https://lists.gnu.org/r/bug-gzip/2022-04/msg00011.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1271",
          "https://security-tracker.debian.org/tracker/CVE-2022-1271",
          "https://security.gentoo.org/glsa/202209-01",
          "https://security.netapp.com/advisory/ntap-20220930-0006/",
          "https://tukaani.org/xz/xzgrep-ZDI-CAN-16587.patch",
          "https://ubuntu.com/security/notices/USN-5378-1",
          "https://ubuntu.com/security/notices/USN-5378-2",
          "https://ubuntu.com/security/notices/USN-5378-3",
          "https://ubuntu.com/security/notices/USN-5378-4",
          "https://www.openwall.com/lists/oss-security/2022/04/07/8"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1271",
        "resource": "liblzma5",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gzip: arbitrary-file-write vulnerability",
        "vulnerabilityID": "CVE-2022-1271"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/02/27/1",
          "http://www.openwall.com/lists/oss-security/2016/02/27/2",
          "https://access.redhat.com/security/cve/CVE-2016-2779",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2779",
        "resource": "libmount1",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: runuser tty hijack via TIOCSTI ioctl",
        "vulnerabilityID": "CVE-2016-2779"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-37600",
          "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
          "https://github.com/karelzak/util-linux/issues/1395",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
          "https://security.netapp.com/advisory/ntap-20210902-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-37600",
        "resource": "libmount1",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
        "vulnerabilityID": "CVE-2021-37600"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0563",
          "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
          "https://security.netapp.com/advisory/ntap-20220331-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0563",
        "resource": "libmount1",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
        "vulnerabilityID": "CVE-2022-0563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-29458",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29458",
          "https://invisible-island.net/ncurses/NEWS.html#t20220416",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00014.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00016.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-29458",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-29458",
        "resource": "libncurses5",
        "score": 6.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: segfaulting OOB read",
        "vulnerabilityID": "CVE-2022-29458"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In ncurses 6.1, there is a NULL pointer dereference at function _nc_parse_entry in parse_entry.c that will lead to a denial of service attack. The product proceeds to the dereference code path even after a \"dubious character `*' in name or alias field\" detection.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-19211",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1643754",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19211",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-19211",
        "resource": "libncurses5",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: Null pointer dereference at function _nc_parse_entry in parse_entry.c",
        "vulnerabilityID": "CVE-2018-19211"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the _nc_find_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17594",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17594",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17594.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00017.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17594",
        "resource": "libncurses5",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the _nc_find_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17594"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          },
          "redhat": {
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the fmt_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17595",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17595",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17595.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00013.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17595",
        "resource": "libncurses5",
        "score": 5.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the fmt_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17595"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
          "https://access.redhat.com/security/cve/CVE-2021-39537",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39537",
          "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-39537",
        "resource": "libncurses5",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
        "vulnerabilityID": "CVE-2021-39537"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-29458",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29458",
          "https://invisible-island.net/ncurses/NEWS.html#t20220416",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00014.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00016.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-29458",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-29458",
        "resource": "libncursesw5",
        "score": 6.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: segfaulting OOB read",
        "vulnerabilityID": "CVE-2022-29458"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In ncurses 6.1, there is a NULL pointer dereference at function _nc_parse_entry in parse_entry.c that will lead to a denial of service attack. The product proceeds to the dereference code path even after a \"dubious character `*' in name or alias field\" detection.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-19211",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1643754",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19211",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-19211",
        "resource": "libncursesw5",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: Null pointer dereference at function _nc_parse_entry in parse_entry.c",
        "vulnerabilityID": "CVE-2018-19211"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the _nc_find_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17594",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17594",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17594.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00017.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17594",
        "resource": "libncursesw5",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the _nc_find_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17594"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          },
          "redhat": {
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the fmt_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17595",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17595",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17595.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00013.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17595",
        "resource": "libncursesw5",
        "score": 5.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the fmt_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17595"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
          "https://access.redhat.com/security/cve/CVE-2021-39537",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39537",
          "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-39537",
        "resource": "libncursesw5",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
        "vulnerabilityID": "CVE-2021-39537"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "libpcre in PCRE before 8.44 allows an integer overflow via a large number after a (?C substring.",
        "fixedVersion": "",
        "installedVersion": "2:8.39-3",
        "links": [
          "http://seclists.org/fulldisclosure/2020/Dec/32",
          "http://seclists.org/fulldisclosure/2021/Feb/14",
          "https://about.gitlab.com/releases/2020/07/01/security-release-13-1-2-release/",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-20838.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14155.json",
          "https://access.redhat.com/security/cve/CVE-2020-14155",
          "https://bugs.gentoo.org/717920",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14155",
          "https://errata.almalinux.org/8/ALSA-2021-4373.html",
          "https://linux.oracle.com/cve/CVE-2020-14155.html",
          "https://linux.oracle.com/errata/ELSA-2021-4373.html",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-14155",
          "https://support.apple.com/kb/HT211931",
          "https://support.apple.com/kb/HT212147",
          "https://ubuntu.com/security/notices/USN-5425-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.pcre.org/original/changelog.txt"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-14155",
        "resource": "libpcre3",
        "score": 5.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "pcre: Integer overflow when parsing callout numeric arguments",
        "vulnerabilityID": "CVE-2020-14155"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.8,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression.",
        "fixedVersion": "",
        "installedVersion": "2:8.39-3",
        "links": [
          "http://openwall.com/lists/oss-security/2017/07/11/3",
          "http://www.securityfocus.com/bid/99575",
          "https://access.redhat.com/security/cve/CVE-2017-11164",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11164",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-11164",
        "resource": "libpcre3",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "pcre: OP_KETRMAX feature in the match function in pcre_exec.c",
        "vulnerabilityID": "CVE-2017-11164"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** In PCRE 8.41, after compiling, a pcretest load test PoC produces a crash overflow in the function match() in pcre_exec.c because of a self-recursive call. NOTE: third parties dispute the relevance of this report, noting that there are options that can be used to limit the amount of stack that is used.",
        "fixedVersion": "",
        "installedVersion": "2:8.39-3",
        "links": [
          "http://packetstormsecurity.com/files/150897/PCRE-8.41-Buffer-Overflow.html",
          "http://seclists.org/fulldisclosure/2018/Dec/33",
          "http://www.openwall.com/lists/oss-security/2017/11/01/11",
          "http://www.openwall.com/lists/oss-security/2017/11/01/3",
          "http://www.openwall.com/lists/oss-security/2017/11/01/7",
          "http://www.openwall.com/lists/oss-security/2017/11/01/8",
          "http://www.securityfocus.com/bid/101688",
          "https://access.redhat.com/security/cve/CVE-2017-16231",
          "https://bugs.exim.org/show_bug.cgi?id=2047"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-16231",
        "resource": "libpcre3",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "pcre: self-recursive call in match() in pcre_exec.c leads to denial of service",
        "vulnerabilityID": "CVE-2017-16231"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 3.7,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "Stack-based buffer overflow in the pcre32_copy_substring function in pcre_get.c in libpcre1 in PCRE 8.40 allows remote attackers to cause a denial of service (WRITE of size 4) or possibly have unspecified other impact via a crafted file.",
        "fixedVersion": "",
        "installedVersion": "2:8.39-3",
        "links": [
          "http://www.securityfocus.com/bid/97067",
          "https://access.redhat.com/errata/RHSA-2018:2486",
          "https://access.redhat.com/security/cve/CVE-2017-7245",
          "https://blogs.gentoo.org/ago/2017/03/20/libpcre-two-stack-based-buffer-overflow-write-in-pcre32_copy_substring-pcre_get-c/",
          "https://security.gentoo.org/glsa/201710-25"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-7245",
        "resource": "libpcre3",
        "score": 3.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "pcre: stack-based buffer overflow write in pcre32_copy_substring",
        "vulnerabilityID": "CVE-2017-7245"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 3.7,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "Stack-based buffer overflow in the pcre32_copy_substring function in pcre_get.c in libpcre1 in PCRE 8.40 allows remote attackers to cause a denial of service (WRITE of size 268) or possibly have unspecified other impact via a crafted file.",
        "fixedVersion": "",
        "installedVersion": "2:8.39-3",
        "links": [
          "http://www.securityfocus.com/bid/97067",
          "https://access.redhat.com/errata/RHSA-2018:2486",
          "https://access.redhat.com/security/cve/CVE-2017-7246",
          "https://blogs.gentoo.org/ago/2017/03/20/libpcre-two-stack-based-buffer-overflow-write-in-pcre32_copy_substring-pcre_get-c/",
          "https://security.gentoo.org/glsa/201710-25"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-7246",
        "resource": "libpcre3",
        "score": 3.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "pcre: stack-based buffer overflow write in pcre32_copy_substring",
        "vulnerabilityID": "CVE-2017-7246"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "libpcre in PCRE before 8.43 allows a subject buffer over-read in JIT when UTF is disabled, and \\X or \\R has more than one fixed quantifier, a related issue to CVE-2019-20454.",
        "fixedVersion": "",
        "installedVersion": "2:8.39-3",
        "links": [
          "http://seclists.org/fulldisclosure/2020/Dec/32",
          "http://seclists.org/fulldisclosure/2021/Feb/14",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-20838.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14155.json",
          "https://access.redhat.com/security/cve/CVE-2019-20838",
          "https://bugs.gentoo.org/717920",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20838",
          "https://errata.almalinux.org/8/ALSA-2021-4373.html",
          "https://linux.oracle.com/cve/CVE-2019-20838.html",
          "https://linux.oracle.com/errata/ELSA-2021-4373.html",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-20838",
          "https://support.apple.com/kb/HT211931",
          "https://support.apple.com/kb/HT212147",
          "https://ubuntu.com/security/notices/USN-5425-1",
          "https://www.pcre.org/original/changelog.txt"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-20838",
        "resource": "libpcre3",
        "score": 7.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "pcre: Buffer over-read in JIT when UTF is disabled and \\X or \\R has fixed quantifier greater than 1",
        "vulnerabilityID": "CVE-2019-20838"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 3.7,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "libpng before 1.6.32 does not properly check the length of chunks against the user limit.",
        "fixedVersion": "",
        "installedVersion": "1.6.28-1+deb9u1",
        "links": [
          "http://www.securityfocus.com/bid/109269",
          "https://access.redhat.com/security/cve/CVE-2017-12652",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12652",
          "https://github.com/glennrp/libpng/blob/df7e9dae0c4aac63d55361e35709c864fa1b8363/ANNOUNCE",
          "https://linux.oracle.com/cve/CVE-2017-12652.html",
          "https://linux.oracle.com/errata/ELSA-2020-3901.html",
          "https://security.netapp.com/advisory/ntap-20220506-0003/",
          "https://support.f5.com/csp/article/K88124225",
          "https://support.f5.com/csp/article/K88124225?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/notices/USN-5432-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-12652",
        "resource": "libpng16-16",
        "score": 3.7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libpng: does not check length of chunks against user limit",
        "vulnerabilityID": "CVE-2017-12652"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "An issue has been found in libpng 1.6.34. It is a SEGV in the function png_free_data in png.c, related to the recommended error handling for png_read_image.",
        "fixedVersion": "",
        "installedVersion": "1.6.28-1+deb9u1",
        "links": [
          "http://packetstormsecurity.com/files/152561/Slackware-Security-Advisory-libpng-Updates.html",
          "http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html",
          "https://access.redhat.com/security/cve/CVE-2018-14048",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14048",
          "https://github.com/fouzhe/security/tree/master/libpng",
          "https://github.com/glennrp/libpng/issues/238",
          "https://seclists.org/bugtraq/2019/Apr/30",
          "https://security.gentoo.org/glsa/201908-02",
          "https://ubuntu.com/security/notices/USN-5432-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-14048",
        "resource": "libpng16-16",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libpng: Segmentation fault in png.c:png_free_data function causing denial of service",
        "vulnerabilityID": "CVE-2018-14048"
      },
      {
        "cvss": {
          "ghsa": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An issue has been found in third-party PNM decoding associated with libpng 1.6.35. It is a stack-based buffer overflow in the function get_token in pnm2png.c in pnm2png.",
        "fixedVersion": "",
        "installedVersion": "1.6.28-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-14550",
          "https://github.com/advisories/GHSA-qwwr-qc2p-6283",
          "https://github.com/fouzhe/security/tree/master/libpng#stack-buffer-overflow-in-png2pnm-in-function-get_token",
          "https://github.com/glennrp/libpng/issues/246",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-14550",
          "https://security.gentoo.org/glsa/201908-02",
          "https://snyk.io/vuln/SNYK-UPSTREAM-LIBPNG-1043612",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-14550",
        "resource": "libpng16-16",
        "score": 7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libpng: Stack-based buffer overflow in contrib/pngminus/pnm2png.c:get_token() potentially leading to arbitrary code execution",
        "vulnerabilityID": "CVE-2018-14550"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "** DISPUTED ** png_create_info_struct in png.c in libpng 1.6.36 has a memory leak, as demonstrated by pngcp. NOTE: a third party has stated \"I don't think it is libpng's job to free this buffer.\"",
        "fixedVersion": "",
        "installedVersion": "1.6.28-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-6129",
          "https://github.com/glennrp/libpng/issues/269",
          "https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-6129",
        "resource": "libpng16-16",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libpng: memory leak of png_info struct in pngcp.c",
        "vulnerabilityID": "CVE-2019-6129"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A heap overflow flaw was found in libpngs' pngimage.c program. This flaw allows an attacker with local network access to pass a specially crafted PNG file to the pngimage utility, causing an application to crash, leading to a denial of service.",
        "fixedVersion": "",
        "installedVersion": "1.6.28-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-4214",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2043393",
          "https://github.com/glennrp/libpng/issues/302",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-4214",
          "https://security-tracker.debian.org/tracker/CVE-2021-4214"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-4214",
        "resource": "libpng16-16",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libpng: hardcoded value leads to heap-overflow",
        "vulnerabilityID": "CVE-2021-4214"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The CIL compiler in SELinux 3.2 has a use-after-free in __cil_verify_classperms (called from __cil_verify_classpermission and __cil_pre_verify_helper).",
        "fixedVersion": "",
        "installedVersion": "2.6-2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36084.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36085.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36086.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36087.json",
          "https://access.redhat.com/security/cve/CVE-2021-36084",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=31065",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36084",
          "https://errata.almalinux.org/8/ALSA-2021-4513.html",
          "https://github.com/SELinuxProject/selinux/commit/f34d3d30c8325e4847a6b696fe7a3936a8a361f3",
          "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/selinux/OSV-2021-417.yaml",
          "https://linux.oracle.com/cve/CVE-2021-36084.html",
          "https://linux.oracle.com/errata/ELSA-2021-4513.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U7ZYR3PIJ75N6U2IONJWCKZ5L2NKJTGR/",
          "https://ubuntu.com/security/notices/USN-5391-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-36084",
        "resource": "libsepol1",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libsepol: use-after-free in __cil_verify_classperms()",
        "vulnerabilityID": "CVE-2021-36084"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The CIL compiler in SELinux 3.2 has a use-after-free in __cil_verify_classperms (called from __verify_map_perm_classperms and hashtab_map).",
        "fixedVersion": "",
        "installedVersion": "2.6-2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36084.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36085.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36086.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36087.json",
          "https://access.redhat.com/security/cve/CVE-2021-36085",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=31124",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36085",
          "https://errata.almalinux.org/8/ALSA-2021-4513.html",
          "https://github.com/SELinuxProject/selinux/commit/2d35fcc7e9e976a2346b1de20e54f8663e8a6cba",
          "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/selinux/OSV-2021-421.yaml",
          "https://linux.oracle.com/cve/CVE-2021-36085.html",
          "https://linux.oracle.com/errata/ELSA-2021-4513.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U7ZYR3PIJ75N6U2IONJWCKZ5L2NKJTGR/",
          "https://ubuntu.com/security/notices/USN-5391-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-36085",
        "resource": "libsepol1",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libsepol: use-after-free in __cil_verify_classperms()",
        "vulnerabilityID": "CVE-2021-36085"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The CIL compiler in SELinux 3.2 has a use-after-free in cil_reset_classpermission (called from cil_reset_classperms_set and cil_reset_classperms_list).",
        "fixedVersion": "",
        "installedVersion": "2.6-2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36084.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36085.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36086.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36087.json",
          "https://access.redhat.com/security/cve/CVE-2021-36086",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=32177",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36086",
          "https://errata.almalinux.org/8/ALSA-2021-4513.html",
          "https://github.com/SELinuxProject/selinux/commit/c49a8ea09501ad66e799ea41b8154b6770fec2c8",
          "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/selinux/OSV-2021-536.yaml",
          "https://linux.oracle.com/cve/CVE-2021-36086.html",
          "https://linux.oracle.com/errata/ELSA-2021-4513.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U7ZYR3PIJ75N6U2IONJWCKZ5L2NKJTGR/",
          "https://ubuntu.com/security/notices/USN-5391-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-36086",
        "resource": "libsepol1",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libsepol: use-after-free in cil_reset_classpermission()",
        "vulnerabilityID": "CVE-2021-36086"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The CIL compiler in SELinux 3.2 has a heap-based buffer over-read in ebitmap_match_any (called indirectly from cil_check_neverallow). This occurs because there is sometimes a lack of checks for invalid statements in an optional block.",
        "fixedVersion": "",
        "installedVersion": "2.6-2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36084.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36085.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36086.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-36087.json",
          "https://access.redhat.com/security/cve/CVE-2021-36087",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=32675",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36087",
          "https://errata.almalinux.org/8/ALSA-2021-4513.html",
          "https://github.com/SELinuxProject/selinux/commit/340f0eb7f3673e8aacaf0a96cbfcd4d12a405521",
          "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/selinux/OSV-2021-585.yaml",
          "https://linux.oracle.com/cve/CVE-2021-36087.html",
          "https://linux.oracle.com/errata/ELSA-2021-4513.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U7ZYR3PIJ75N6U2IONJWCKZ5L2NKJTGR/",
          "https://lore.kernel.org/selinux/CAEN2sdqJKHvDzPnxS-J8grU8fSf32DDtx=kyh84OsCq_Vm+yaQ@mail.gmail.com/T/",
          "https://ubuntu.com/security/notices/USN-5391-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-36087",
        "resource": "libsepol1",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libsepol: heap-based buffer overflow in ebitmap_match_any()",
        "vulnerabilityID": "CVE-2021-36087"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/02/27/1",
          "http://www.openwall.com/lists/oss-security/2016/02/27/2",
          "https://access.redhat.com/security/cve/CVE-2016-2779",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2779",
        "resource": "libsmartcols1",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: runuser tty hijack via TIOCSTI ioctl",
        "vulnerabilityID": "CVE-2016-2779"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-37600",
          "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
          "https://github.com/karelzak/util-linux/issues/1395",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
          "https://security.netapp.com/advisory/ntap-20210902-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-37600",
        "resource": "libsmartcols1",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
        "vulnerabilityID": "CVE-2021-37600"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0563",
          "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
          "https://security.netapp.com/advisory/ntap-20220331-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0563",
        "resource": "libsmartcols1",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
        "vulnerabilityID": "CVE-2022-0563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
        "fixedVersion": "",
        "installedVersion": "1.43.4-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1304",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
          "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1304",
          "https://ubuntu.com/security/notices/USN-5464-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1304",
        "resource": "libss2",
        "score": 5.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
        "vulnerabilityID": "CVE-2022-1304"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An exploitable code execution vulnerability exists in the quota file functionality of E2fsprogs 1.45.3. A specially crafted ext4 partition can cause an out-of-bounds write on the heap, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
        "fixedVersion": "1.43.4-2+deb9u1",
        "installedVersion": "1.43.4-2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-5094",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5094",
          "https://linux.oracle.com/cve/CVE-2019-5094.html",
          "https://linux.oracle.com/errata/ELSA-2020-4011.html",
          "https://lists.debian.org/debian-lts-announce/2019/09/msg00029.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-5094",
          "https://seclists.org/bugtraq/2019/Sep/58",
          "https://security.gentoo.org/glsa/202003-05",
          "https://security.netapp.com/advisory/ntap-20200115-0002/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0887",
          "https://ubuntu.com/security/notices/USN-4142-1",
          "https://ubuntu.com/security/notices/USN-4142-2",
          "https://usn.ubuntu.com/4142-1/",
          "https://usn.ubuntu.com/4142-2/",
          "https://www.debian.org/security/2019/dsa-4535"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5094",
        "resource": "libss2",
        "score": 6.4,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: Crafted ext4 partition leads to out-of-bounds write",
        "vulnerabilityID": "CVE-2019-5094"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.4,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H"
          }
        },
        "description": "A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
        "fixedVersion": "1.43.4-2+deb9u2",
        "installedVersion": "1.43.4-2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00004.html",
          "https://access.redhat.com/security/cve/CVE-2019-5188",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5188",
          "https://linux.oracle.com/cve/CVE-2019-5188.html",
          "https://linux.oracle.com/errata/ELSA-2020-4011.html",
          "https://lists.debian.org/debian-lts-announce/2020/03/msg00030.html",
          "https://lists.debian.org/debian-lts-announce/2020/07/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-5188",
          "https://security.netapp.com/advisory/ntap-20220506-0001/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0973",
          "https://ubuntu.com/security/notices/USN-4249-1",
          "https://usn.ubuntu.com/4249-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5188",
        "resource": "libss2",
        "score": 7.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "e2fsprogs: Out-of-bounds write in e2fsck/rehash.c",
        "vulnerabilityID": "CVE-2019-5188"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 10,
            "V2Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n). Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd).",
        "fixedVersion": "1.1.0l-1~deb9u6",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "https://access.redhat.com/errata/RHSA-2022:6224",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-1292.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-2068.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-2097.json",
          "https://access.redhat.com/security/cve/CVE-2022-1292",
          "https://bugzilla.redhat.com/2081494",
          "https://bugzilla.redhat.com/2087911",
          "https://bugzilla.redhat.com/2087913",
          "https://bugzilla.redhat.com/2097310",
          "https://bugzilla.redhat.com/2104905",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1292",
          "https://errata.almalinux.org/9/ALSA-2022-6224.html",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1ad73b4d27bd8c1b369a3cd453681d3a4f1bb9b2",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=548d3f280a6e737673f5b61fce24bb100108dfeb",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=e5fd1728ef4c7a5bf7c7a7163ca60370460a6e23",
          "https://linux.oracle.com/cve/CVE-2022-1292.html",
          "https://linux.oracle.com/errata/ELSA-2022-9751.html",
          "https://lists.debian.org/debian-lts-announce/2022/05/msg00019.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VX4KWHPMKYJL6ZLW4M5IU7E5UV5ZWJQU/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZNU5M7BXMML26G3GPYKFGQYPQDRSNKDD/",
          "https://mta.openssl.org/pipermail/openssl-announce/2022-May/000224.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1292",
          "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2022-0011",
          "https://security.gentoo.org/glsa/202210-02",
          "https://security.netapp.com/advisory/ntap-20220602-0009/",
          "https://security.netapp.com/advisory/ntap-20220729-0004/",
          "https://ubuntu.com/security/notices/USN-5402-1",
          "https://ubuntu.com/security/notices/USN-5402-2",
          "https://www.debian.org/security/2022/dsa-5139",
          "https://www.openssl.org/news/secadv/20220503.txt",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1292",
        "resource": "libssl1.1",
        "score": 6.7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: c_rehash script allows command injection",
        "vulnerabilityID": "CVE-2022-1292"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 10,
            "V2Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances where the c_rehash script does not properly sanitise shell metacharacters to prevent command injection were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other places in the script where the file names of certificates being hashed were possibly passed to a command executed through the shell. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3). Fixed in OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o). Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze).",
        "fixedVersion": "",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "https://access.redhat.com/errata/RHSA-2022:6224",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-1292.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-2068.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-2097.json",
          "https://access.redhat.com/security/cve/CVE-2022-2068",
          "https://bugzilla.redhat.com/2081494",
          "https://bugzilla.redhat.com/2087911",
          "https://bugzilla.redhat.com/2087913",
          "https://bugzilla.redhat.com/2097310",
          "https://bugzilla.redhat.com/2104905",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2068",
          "https://errata.almalinux.org/9/ALSA-2022-6224.html",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2c9c35870601b4a44d86ddbf512b38df38285cfa",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=7a9c027159fe9e1bbc2cd38a8a2914bff0d5abd9",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9639817dac8bbbaa64d09efad7464ccc405527c7",
          "https://linux.oracle.com/cve/CVE-2022-2068.html",
          "https://linux.oracle.com/errata/ELSA-2022-9751.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6WZZBKUHQFGSKGNXXKICSRPL7AMVW5M5/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VCMNWKERPBKOEBNL7CLTTX3ZZCZLH7XA/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2068",
          "https://security.netapp.com/advisory/ntap-20220707-0008/",
          "https://ubuntu.com/security/notices/USN-5488-1",
          "https://ubuntu.com/security/notices/USN-5488-2",
          "https://www.debian.org/security/2022/dsa-5169",
          "https://www.openssl.org/news/secadv/20220621.txt"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2068",
        "resource": "libssl1.1",
        "score": 6.7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: the c_rehash script allows command injection",
        "vulnerabilityID": "CVE-2022-2068"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 10,
            "V2Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "The OpenSSL 3.0.4 release introduced a serious bug in the RSA implementation for X86_64 CPUs supporting the AVX512IFMA instructions. This issue makes the RSA implementation with 2048 bit private keys incorrect on such machines and memory corruption will happen during the computation. As a consequence of the memory corruption an attacker may be able to trigger a remote code execution on the machine performing the computation. SSL/TLS servers or other servers using 2048 bit RSA private keys running on machines supporting AVX512IFMA instructions of the X86_64 architecture are affected by this issue.",
        "fixedVersion": "",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2274",
          "https://crates.io/crates/openssl-src",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=4d8a88c134df634ba610ff8db1eb8478ac5fd345",
          "https://github.com/openssl/openssl/issues/18625",
          "https://guidovranken.com/2022/06/27/notes-on-openssl-remote-memory-corruption/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2274",
          "https://rustsec.org/advisories/RUSTSEC-2022-0033.html",
          "https://security.netapp.com/advisory/ntap-20220715-0010/",
          "https://www.openssl.org/news/secadv/20220705.txt"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2274",
        "resource": "libssl1.1",
        "score": 8.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: AVX-512-specific heap buffer overflow",
        "vulnerabilityID": "CVE-2022-2274"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
          },
          "redhat": {
            "V3Score": 2.9,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
          }
        },
        "description": "ChaCha20-Poly1305 is an AEAD cipher, and requires a unique nonce input for every encryption operation. RFC 7539 specifies that the nonce value (IV) should be 96 bits (12 bytes). OpenSSL allows a variable nonce length and front pads the nonce with 0 bytes if it is less than 12 bytes. However it also incorrectly allows a nonce to be set of up to 16 bytes. In this case only the last 12 bytes are significant and any additional leading bytes are ignored. It is a requirement of using this cipher that nonce values are unique. Messages encrypted using a reused nonce value are susceptible to serious confidentiality and integrity attacks. If an application changes the default nonce length to be longer than 12 bytes and then makes a change to the leading bytes of the nonce expecting the new value to be a new unique nonce then such an application could inadvertently encrypt messages with a reused nonce. Additionally the ignored bytes in a long nonce are not covered by the integrity guarantee of this cipher. Any application that relies on the integrity of these ignored leading bytes of a long nonce may be further affected. Any OpenSSL internal use of this cipher, including in SSL/TLS, is safe because no such use sets such a long nonce value. However user applications that use this cipher directly and set a non-default nonce length to be longer than 12 bytes may be vulnerable. OpenSSL versions 1.1.1 and 1.1.0 are affected by this issue. Due to the limited scope of affected deployments this has been assessed as low severity and therefore we are not creating new releases at this time. Fixed in OpenSSL 1.1.1c (Affected 1.1.1-1.1.1b). Fixed in OpenSSL 1.1.0k (Affected 1.1.0-1.1.0j).",
        "fixedVersion": "1.1.0k-1~deb9u1",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00056.html",
          "https://access.redhat.com/errata/RHSA-2019:3700",
          "https://access.redhat.com/security/cve/CVE-2019-1543",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1543",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ee22257b1418438ebaf54df98af4e24f494d1809",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f426625b6ae9a7831010750490a5f0ad689c5ba3",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10365",
          "https://linux.oracle.com/cve/CVE-2019-1543.html",
          "https://linux.oracle.com/errata/ELSA-2019-3700.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Y3IVFGSERAZLNJCK35TEM2R4726XIH3Z/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZBEV5QGDRFUZDMNECFXUSN5FMYOZDE4V/",
          "https://seclists.org/bugtraq/2019/Jul/3",
          "https://www.debian.org/security/2019/dsa-4475",
          "https://www.openssl.org/news/secadv/20190306.txt",
          "https://www.oracle.com/security-alerts/cpuapr2020.html",
          "https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html",
          "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1543",
        "resource": "libssl1.1",
        "score": 2.9,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: ChaCha20-Poly1305 with long nonces",
        "vulnerabilityID": "CVE-2019-1543"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument in some cases where the input length is close to the maximum permissable length for an integer on the platform. In such cases the return value from the function call will be 1 (indicating success), but the output length value will be negative. This could cause applications to behave incorrectly or crash. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).",
        "fixedVersion": "1.1.0l-1~deb9u3",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-23840",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
          "https://crates.io/crates/openssl-src",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2",
          "https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10366",
          "https://linux.oracle.com/cve/CVE-2021-23840.html",
          "https://linux.oracle.com/errata/ELSA-2021-9561.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-23840",
          "https://rustsec.org/advisories/RUSTSEC-2021-0057.html",
          "https://security.gentoo.org/glsa/202103-03",
          "https://security.netapp.com/advisory/ntap-20210219-0009/",
          "https://ubuntu.com/security/notices/USN-4738-1",
          "https://ubuntu.com/security/notices/USN-5088-1",
          "https://www.debian.org/security/2021/dsa-4855",
          "https://www.openssl.org/news/secadv/20210216.txt",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html",
          "https://www.tenable.com/security/tns-2021-03",
          "https://www.tenable.com/security/tns-2021-09",
          "https://www.tenable.com/security/tns-2021-10"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-23840",
        "resource": "libssl1.1",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: integer overflow in CipherUpdate",
        "vulnerabilityID": "CVE-2021-23840"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not a strict requirement, ASN.1 strings that are parsed using OpenSSL's own \"d2i\" functions (and other similar parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array by directly setting the \"data\" and \"length\" fields in the ASN1_STRING array. This can also happen by using the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for strings that have been directly constructed. Where an application requests an ASN.1 structure to be printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the application without NUL terminating the \"data\" field, then a read buffer overrun can occur. The same thing can also occur during name constraints processing of certificates (for example if a certificate has been directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack). It could also result in the disclosure of private memory contents (such as private keys, or sensitive plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected 1.0.2-1.0.2y).",
        "fixedVersion": "1.1.0l-1~deb9u4",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2021/08/26/2",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3712.json",
          "https://access.redhat.com/security/cve/CVE-2021-3712",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-244969.pdf",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
          "https://crates.io/crates/openssl-src",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3712",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=94d23fcff9b2a7a8368dfe52214d5c2569882c11",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ccb0a11145ee72b042d10593a64eaf9e8a55ec12",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10366",
          "https://linux.oracle.com/cve/CVE-2021-3712.html",
          "https://linux.oracle.com/errata/ELSA-2022-9023.html",
          "https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E",
          "https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2021/09/msg00014.html",
          "https://lists.debian.org/debian-lts-announce/2021/09/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3712",
          "https://rustsec.org/advisories/RUSTSEC-2021-0098.html",
          "https://security.gentoo.org/glsa/202209-02",
          "https://security.gentoo.org/glsa/202210-02",
          "https://security.netapp.com/advisory/ntap-20210827-0010/",
          "https://ubuntu.com/security/notices/USN-5051-1",
          "https://ubuntu.com/security/notices/USN-5051-2",
          "https://ubuntu.com/security/notices/USN-5051-3",
          "https://ubuntu.com/security/notices/USN-5051-4 (regression only in trusty/esm)",
          "https://ubuntu.com/security/notices/USN-5088-1",
          "https://www.debian.org/security/2021/dsa-4963",
          "https://www.openssl.org/news/secadv/20210824.txt",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html",
          "https://www.tenable.com/security/tns-2021-16",
          "https://www.tenable.com/security/tns-2022-02"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3712",
        "resource": "libssl1.1",
        "score": 7.4,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: Read buffer overruns processing ASN.1 strings",
        "vulnerabilityID": "CVE-2021-3712"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).",
        "fixedVersion": "1.1.0l-1~deb9u5",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://packetstormsecurity.com/files/167344/OpenSSL-1.0.2-1.1.1-3.0-BN_mod_sqrt-Infinite-Loop.html",
          "http://seclists.org/fulldisclosure/2022/May/33",
          "http://seclists.org/fulldisclosure/2022/May/35",
          "http://seclists.org/fulldisclosure/2022/May/38",
          "https://access.redhat.com/errata/RHSA-2022:5326",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-0778.json",
          "https://access.redhat.com/security/cve/CVE-2022-0778",
          "https://bugzilla.redhat.com/2062202",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-712929.pdf",
          "https://crates.io/crates/openssl-src",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0778",
          "https://errata.almalinux.org/8/ALSA-2022-5326.html",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=3118eb64934499d93db3230748a452351d1d9a65",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=380085481c64de749a6dd25cdf0bcf4360b30f83",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=a466912611aa6cbdf550cd10601390e587451246",
          "https://linux.oracle.com/cve/CVE-2022-0778.html",
          "https://linux.oracle.com/errata/ELSA-2022-9272.html",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00023.html",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00024.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/323SNN6ZX7PRJJWP2BUAFLPUAE42XWLZ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GDB3GQVJPXJE7X5C5JN6JAA4XUDWD6E6/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/W6K3PR542DXWLEFFMFIDMME4CWMHJRMG/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
          "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2022-0002",
          "https://rustsec.org/advisories/RUSTSEC-2022-0014.html",
          "https://security.gentoo.org/glsa/202210-02",
          "https://security.netapp.com/advisory/ntap-20220321-0002/",
          "https://security.netapp.com/advisory/ntap-20220429-0005/",
          "https://support.apple.com/kb/HT213255",
          "https://support.apple.com/kb/HT213256",
          "https://support.apple.com/kb/HT213257",
          "https://ubuntu.com/security/notices/USN-5328-1",
          "https://ubuntu.com/security/notices/USN-5328-2",
          "https://www.debian.org/security/2022/dsa-5103",
          "https://www.openssl.org/news/secadv/20220315.txt",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html",
          "https://www.tenable.com/security/tns-2022-06",
          "https://www.tenable.com/security/tns-2022-07",
          "https://www.tenable.com/security/tns-2022-08",
          "https://www.tenable.com/security/tns-2022-09"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0778",
        "resource": "libssl1.1",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
        "vulnerabilityID": "CVE-2022-0778"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "OpenSSL supports creating a custom cipher via the legacy EVP_CIPHER_meth_new() function and associated function calls. This function was deprecated in OpenSSL 3.0 and application authors are instead encouraged to use the new provider mechanism in order to implement custom ciphers. OpenSSL versions 3.0.0 to 3.0.5 incorrectly handle legacy custom ciphers passed to the EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() and EVP_CipherInit_ex2() functions (as well as other similarly named encryption and decryption initialisation functions). Instead of using the custom cipher directly it incorrectly tries to fetch an equivalent cipher from the available providers. An equivalent cipher is found based on the NID passed to EVP_CIPHER_meth_new(). This NID is supposed to represent the unique NID for a given cipher. However it is possible for an application to incorrectly pass NID_undef as this value in the call to EVP_CIPHER_meth_new(). When NID_undef is used in this way the OpenSSL encryption/decryption initialisation function will match the NULL cipher as being equivalent and will fetch this from the available providers. This will succeed if the default provider has been loaded (or if a third party provider has been loaded that offers this cipher). Using the NULL cipher means that the plaintext is emitted as the ciphertext. Applications are only affected by this issue if they call EVP_CIPHER_meth_new() using NID_undef and subsequently use it in a call to an encryption/decryption initialisation function. Applications that only use SSL/TLS are not impacted by this issue. Fixed in OpenSSL 3.0.6 (Affected 3.0.0-3.0.5).",
        "fixedVersion": "",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-3358",
          "https://crates.io/crates/openssl-src",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3358",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=5485c56679d7c49b96e8fc8ca708b0b7e7c03c4b",
          "https://rustsec.org/advisories/RUSTSEC-2022-0059.html",
          "https://www.openssl.org/news/secadv/20221011.txt"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-3358",
        "resource": "libssl1.1",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: Using a Custom Cipher with NID_undef may lead to NULL encryption",
        "vulnerabilityID": "CVE-2022-3358"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "Normally in OpenSSL EC groups always have a co-factor present and this is used in side channel resistant code paths. However, in some cases, it is possible to construct a group using explicit parameters (instead of using a named curve). In those cases it is possible that such a group does not have the cofactor present. This can occur even where all the parameters match a known named curve. If such a curve is used then OpenSSL falls back to non-side channel resistant code paths which may result in full key recovery during an ECDSA signature operation. In order to be vulnerable an attacker would have to have the ability to time the creation of a large number of signatures where explicit parameters with no co-factor present are in use by an application using libcrypto. For the avoidance of doubt libssl is not vulnerable because explicit parameters are never used. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).",
        "fixedVersion": "1.1.0l-1~deb9u1",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00054.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00072.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00012.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00016.html",
          "http://packetstormsecurity.com/files/154467/Slackware-Security-Advisory-openssl-Updates.html",
          "https://access.redhat.com/security/cve/CVE-2019-1547",
          "https://arxiv.org/abs/1909.01785",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=21c856b75d81eff61aa63b4f036bb64a85bf6d46",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=30c22fa8b1d840036b8e203585738df62a03cec8",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=7c1709c2da5414f5b6133d00a03fc8c5bf996c7a",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10365",
          "https://linux.oracle.com/cve/CVE-2019-1547.html",
          "https://linux.oracle.com/errata/ELSA-2020-1840.html",
          "https://lists.debian.org/debian-lts-announce/2019/09/msg00026.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GY6SNRJP2S7Y42GIIDO3HXPNMDYN2U3A/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZN4VVQJ3JDCHGIHV4Y2YTXBYQZ6PWQ7E/",
          "https://seclists.org/bugtraq/2019/Oct/0",
          "https://seclists.org/bugtraq/2019/Oct/1",
          "https://seclists.org/bugtraq/2019/Sep/25",
          "https://security.gentoo.org/glsa/201911-04",
          "https://security.netapp.com/advisory/ntap-20190919-0002/",
          "https://security.netapp.com/advisory/ntap-20200122-0002/",
          "https://security.netapp.com/advisory/ntap-20200416-0003/",
          "https://support.f5.com/csp/article/K73422160?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/notices/USN-4376-1",
          "https://ubuntu.com/security/notices/USN-4376-2",
          "https://ubuntu.com/security/notices/USN-4504-1",
          "https://usn.ubuntu.com/4376-1/",
          "https://usn.ubuntu.com/4376-2/",
          "https://usn.ubuntu.com/4504-1/",
          "https://www.debian.org/security/2019/dsa-4539",
          "https://www.debian.org/security/2019/dsa-4540",
          "https://www.openssl.org/news/secadv/20190910.txt",
          "https://www.oracle.com/security-alerts/cpuapr2020.html",
          "https://www.oracle.com/security-alerts/cpujan2020.html",
          "https://www.oracle.com/security-alerts/cpujul2020.html",
          "https://www.oracle.com/security-alerts/cpuoct2020.html",
          "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html",
          "https://www.tenable.com/security/tns-2019-08",
          "https://www.tenable.com/security/tns-2019-09"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1547",
        "resource": "libssl1.1",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: side-channel weak encryption vulnerability",
        "vulnerabilityID": "CVE-2019-1547"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 4.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
          }
        },
        "description": "There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t).",
        "fixedVersion": "1.1.0l-1~deb9u5",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00030.html",
          "http://packetstormsecurity.com/files/155754/Slackware-Security-Advisory-openssl-Updates.html",
          "https://access.redhat.com/security/cve/CVE-2019-1551",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1551",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=419102400a2811582a7a3d4a4e317d72e5ce0a8f",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f1c5eea8a817075d31e43f5876993c6710238c98",
          "https://github.com/openssl/openssl/pull/10575",
          "https://linux.oracle.com/cve/CVE-2019-1551.html",
          "https://linux.oracle.com/errata/ELSA-2020-4514.html",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00023.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/",
          "https://seclists.org/bugtraq/2019/Dec/39",
          "https://seclists.org/bugtraq/2019/Dec/46",
          "https://security.gentoo.org/glsa/202004-10",
          "https://security.netapp.com/advisory/ntap-20191210-0001/",
          "https://ubuntu.com/security/notices/USN-4376-1",
          "https://ubuntu.com/security/notices/USN-4504-1",
          "https://usn.ubuntu.com/4376-1/",
          "https://usn.ubuntu.com/4504-1/",
          "https://www.debian.org/security/2019/dsa-4594",
          "https://www.debian.org/security/2021/dsa-4855",
          "https://www.openssl.org/news/secadv/20191206.txt",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpujan2021.html",
          "https://www.oracle.com/security-alerts/cpujul2020.html",
          "https://www.tenable.com/security/tns-2019-09",
          "https://www.tenable.com/security/tns-2020-03",
          "https://www.tenable.com/security/tns-2020-11",
          "https://www.tenable.com/security/tns-2021-10"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1551",
        "resource": "libssl1.1",
        "score": 4.8,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: Integer overflow in RSAZ modular exponentiation on x86_64",
        "vulnerabilityID": "CVE-2019-1551"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the \"-crl_download\" option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).",
        "fixedVersion": "1.1.0l-1~deb9u2",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2021/09/14/2",
          "https://access.redhat.com/security/cve/CVE-2020-1971",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f960d81215ebf3f65e03d4d5d857fb9b666d6920",
          "https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676",
          "https://linux.oracle.com/cve/CVE-2020-1971.html",
          "https://linux.oracle.com/errata/ELSA-2021-9150.html",
          "https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c@%3Cdev.tomcat.apache.org%3E",
          "https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143@%3Ccommits.pulsar.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html",
          "https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1971",
          "https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc",
          "https://security.gentoo.org/glsa/202012-13",
          "https://security.netapp.com/advisory/ntap-20201218-0005/",
          "https://security.netapp.com/advisory/ntap-20210513-0002/",
          "https://ubuntu.com/security/notices/USN-4662-1",
          "https://ubuntu.com/security/notices/USN-4745-1",
          "https://www.debian.org/security/2020/dsa-4807",
          "https://www.openssl.org/news/secadv/20201208.txt",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2021.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html",
          "https://www.tenable.com/security/tns-2020-11",
          "https://www.tenable.com/security/tns-2021-09",
          "https://www.tenable.com/security/tns-2021-10"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1971",
        "resource": "libssl1.1",
        "score": 5.9,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: EDIPARTYNAME NULL pointer de-reference",
        "vulnerabilityID": "CVE-2020-1971"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).",
        "fixedVersion": "1.1.0l-1~deb9u3",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://seclists.org/fulldisclosure/2021/May/67",
          "http://seclists.org/fulldisclosure/2021/May/68",
          "http://seclists.org/fulldisclosure/2021/May/70",
          "https://access.redhat.com/security/cve/CVE-2021-23841",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
          "https://crates.io/crates/openssl-src",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807",
          "https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846",
          "https://linux.oracle.com/cve/CVE-2021-23841.html",
          "https://linux.oracle.com/errata/ELSA-2021-9561.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-23841",
          "https://rustsec.org/advisories/RUSTSEC-2021-0058.html",
          "https://security.gentoo.org/glsa/202103-03",
          "https://security.netapp.com/advisory/ntap-20210219-0009/",
          "https://security.netapp.com/advisory/ntap-20210513-0002/",
          "https://support.apple.com/kb/HT212528",
          "https://support.apple.com/kb/HT212529",
          "https://support.apple.com/kb/HT212534",
          "https://ubuntu.com/security/notices/USN-4738-1",
          "https://ubuntu.com/security/notices/USN-4745-1",
          "https://www.debian.org/security/2021/dsa-4855",
          "https://www.openssl.org/news/secadv/20210216.txt",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html",
          "https://www.tenable.com/security/tns-2021-03",
          "https://www.tenable.com/security/tns-2021-09"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-23841",
        "resource": "libssl1.1",
        "score": 5.9,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: NULL pointer dereference in X509_issuer_and_serial_hash()",
        "vulnerabilityID": "CVE-2021-23841"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "There is a carry propagation bug in the MIPS32 and MIPS64 squaring procedure. Many EC algorithms are affected, including some of the TLS 1.3 default curves. Impact was not analyzed in detail, because the pre-requisites for attack are considered unlikely and include reusing private keys. Analysis suggests that attacks against RSA and DSA as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH are considered just feasible (although very difficult) because most of the work necessary to deduce information about a private key may be performed offline. The amount of resources required for such an attack would be significant. However, for an attack on TLS to be meaningful, the server would have to share the DH private key among multiple clients, which is no longer an option since CVE-2016-0701. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0.0. It was addressed in the releases of 1.1.1m and 3.0.1 on the 15th of December 2021. For the 1.0.2 release it is addressed in git commit 6fc1aaaf3 that is available to premium support customers only. It will be made available in 1.0.2zc when it is released. The issue only affects OpenSSL on MIPS platforms. Fixed in OpenSSL 3.0.1 (Affected 3.0.0). Fixed in OpenSSL 1.1.1m (Affected 1.1.1-1.1.1l). Fixed in OpenSSL 1.0.2zc-dev (Affected 1.0.2-1.0.2zb).",
        "fixedVersion": "",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-4160",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=3bf7b73ea7123045b8f972badc67ed6878e6c37f",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6fc1aaaf303185aa5e483e06bdfae16daa9193a7",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=e9e726506cd2a3fd9c0f12daf8cc1fe934c7dddb",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-4160",
          "https://security.gentoo.org/glsa/202210-02",
          "https://www.debian.org/security/2022/dsa-5103",
          "https://www.openssl.org/news/secadv/20220128.txt",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-4160",
        "resource": "libssl1.1",
        "score": 5.9,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: Carry propagation bug in the MIPS32 and MIPS64 squaring procedure",
        "vulnerabilityID": "CVE-2021-4160"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn't written. In the special case of \"in place\" encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p).",
        "fixedVersion": "",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "https://access.redhat.com/errata/RHSA-2022:6224",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-1292.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-2068.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-2097.json",
          "https://access.redhat.com/security/cve/CVE-2022-2097",
          "https://bugzilla.redhat.com/2081494",
          "https://bugzilla.redhat.com/2087911",
          "https://bugzilla.redhat.com/2087913",
          "https://bugzilla.redhat.com/2097310",
          "https://bugzilla.redhat.com/2104905",
          "https://crates.io/crates/openssl-src",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2097",
          "https://errata.almalinux.org/9/ALSA-2022-6224.html",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=919925673d6c9cfed3c1085497f5dfbbed5fc431",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=a98f339ddd7e8f487d6e0088d4a9a42324885a93",
          "https://linux.oracle.com/cve/CVE-2022-2097.html",
          "https://linux.oracle.com/errata/ELSA-2022-9751.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R6CK57NBQFTPUMXAPJURCGXUYT76NQAK/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/V6567JERRHHJW2GNGJGKDRNHR7SNPZK7/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VCMNWKERPBKOEBNL7CLTTX3ZZCZLH7XA/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2097",
          "https://rustsec.org/advisories/RUSTSEC-2022-0032.html",
          "https://security.gentoo.org/glsa/202210-02",
          "https://security.netapp.com/advisory/ntap-20220715-0011/",
          "https://ubuntu.com/security/notices/USN-5502-1",
          "https://www.openssl.org/news/secadv/20220705.txt"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2097",
        "resource": "libssl1.1",
        "score": 5.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: AES OCB fails to encrypt some bytes",
        "vulnerabilityID": "CVE-2022-2097"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N"
          },
          "redhat": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N"
          }
        },
        "description": "The NIST SP 800-90A default statement of the Dual Elliptic Curve Deterministic Random Bit Generation (Dual_EC_DRBG) algorithm contains point Q constants with a possible relationship to certain \"skeleton key\" values, which might allow context-dependent attackers to defeat cryptographic protection mechanisms by leveraging knowledge of those values.  NOTE: this is a preliminary CVE for Dual_EC_DRBG; future research may provide additional details about point Q and associated attacks, and could potentially lead to a RECAST or REJECT of this CVE.",
        "fixedVersion": "",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://arstechnica.com/security/2013/09/stop-using-nsa-influence-code-in-our-product-rsa-tells-customers/",
          "http://blog.cryptographyengineering.com/2013/09/rsa-warns-developers-against-its-own.html",
          "http://blog.cryptographyengineering.com/2013/09/the-many-flaws-of-dualecdrbg.html",
          "http://rump2007.cr.yp.to/15-shumow.pdf",
          "http://stream.wsj.com/story/latest-headlines/SS-2-63399/SS-2-332655/",
          "http://threatpost.com/in-wake-of-latest-crypto-revelations-everything-is-suspect",
          "http://www.securityfocus.com/bid/63657",
          "https://access.redhat.com/security/cve/CVE-2007-6755",
          "https://www.schneier.com/blog/archives/2007/11/the_strange_sto.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2007-6755",
        "resource": "libssl1.1",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "Dual_EC_DRBG: weak pseudo random number generator",
        "vulnerabilityID": "CVE-2007-6755"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:N/A:N"
          }
        },
        "description": "OpenSSL 0.9.8i on the Gaisler Research LEON3 SoC on the Xilinx Virtex-II Pro FPGA uses a Fixed Width Exponentiation (FWE) algorithm for certain signature calculations, and does not verify the signature before providing it to a caller, which makes it easier for physically proximate attackers to determine the private key via a modified supply voltage for the microprocessor, related to a \"fault-based attack.\"",
        "fixedVersion": "",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://rdist.root.org/2010/03/08/attacking-rsa-exponentiation-with-fault-injection/",
          "http://www.eecs.umich.edu/%7Evaleria/research/publications/DATE10RSA.pdf",
          "http://www.networkworld.com/news/2010/030410-rsa-security-attack.html",
          "http://www.osvdb.org/62808",
          "http://www.theregister.co.uk/2010/03/04/severe_openssl_vulnerability/",
          "https://access.redhat.com/security/cve/CVE-2010-0928",
          "https://exchange.xforce.ibmcloud.com/vulnerabilities/56750"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2010-0928",
        "resource": "libssl1.1",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: RSA authentication weakness",
        "vulnerabilityID": "CVE-2010-0928"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 3.7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 3.7,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "In situations where an attacker receives automated notification of the success or failure of a decryption attempt an attacker, after sending a very large number of messages to be decrypted, can recover a CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).",
        "fixedVersion": "1.1.0l-1~deb9u1",
        "installedVersion": "1.1.0j-1~deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00054.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00072.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00012.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00016.html",
          "http://packetstormsecurity.com/files/154467/Slackware-Security-Advisory-openssl-Updates.html",
          "https://access.redhat.com/security/cve/CVE-2019-1563",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1563",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=08229ad838c50f644d7e928e2eef147b4308ad64",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=631f94db0065c78181ca9ba5546ebc8bb3884b97",
          "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10365",
          "https://linux.oracle.com/cve/CVE-2019-1563.html",
          "https://linux.oracle.com/errata/ELSA-2020-1840.html",
          "https://lists.debian.org/debian-lts-announce/2019/09/msg00026.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GY6SNRJP2S7Y42GIIDO3HXPNMDYN2U3A/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZN4VVQJ3JDCHGIHV4Y2YTXBYQZ6PWQ7E/",
          "https://seclists.org/bugtraq/2019/Oct/0",
          "https://seclists.org/bugtraq/2019/Oct/1",
          "https://seclists.org/bugtraq/2019/Sep/25",
          "https://security.gentoo.org/glsa/201911-04",
          "https://security.netapp.com/advisory/ntap-20190919-0002/",
          "https://support.f5.com/csp/article/K97324400?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/notices/USN-4376-1",
          "https://ubuntu.com/security/notices/USN-4376-2",
          "https://ubuntu.com/security/notices/USN-4504-1",
          "https://usn.ubuntu.com/4376-1/",
          "https://usn.ubuntu.com/4376-2/",
          "https://usn.ubuntu.com/4504-1/",
          "https://www.debian.org/security/2019/dsa-4539",
          "https://www.debian.org/security/2019/dsa-4540",
          "https://www.openssl.org/news/secadv/20190910.txt",
          "https://www.oracle.com/security-alerts/cpuapr2020.html",
          "https://www.oracle.com/security-alerts/cpujan2020.html",
          "https://www.oracle.com/security-alerts/cpujul2020.html",
          "https://www.oracle.com/security-alerts/cpuoct2020.html",
          "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html",
          "https://www.tenable.com/security/tns-2019-09"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1563",
        "resource": "libssl1.1",
        "score": 3.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "openssl: information disclosure in PKCS7_dataDecode and CMS_decrypt_set1_pkey",
        "vulnerabilityID": "CVE-2019-1563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H"
          }
        },
        "description": "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
        "fixedVersion": "",
        "installedVersion": "6.3.0-18+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-12886",
          "https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379\u0026view=markup",
          "https://www.gnu.org/software/gcc/gcc-8/changes.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-12886",
        "resource": "libstdc++6",
        "score": 6.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "gcc: spilling of stack protection address in cfgexpand.c and function.c leads to stack-overflow protection bypass",
        "vulnerabilityID": "CVE-2018-12886"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A use-after-free vulnerability was found in systemd. This issue occurs due to the on_stream_io() function and dns_stream_complete() function in 'resolved-dns-stream.c' not incrementing the reference counting for the DnsStream object. Therefore, other functions and callbacks called can dereference the DNSStream object, causing the use-after-free when the reference is still used later.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/errata/RHSA-2022:6206",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-2526.json",
          "https://access.redhat.com/security/cve/CVE-2022-2526",
          "https://bugzilla.redhat.com/2109926",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2526",
          "https://errata.almalinux.org/8/ALSA-2022-6206.html",
          "https://github.com/systemd/systemd/commit/d973d94dec349fb676fdd844f6fe2ada3538f27c",
          "https://linux.oracle.com/cve/CVE-2022-2526.html",
          "https://linux.oracle.com/errata/ELSA-2022-6206.html",
          "https://ubuntu.com/security/notices/USN-5583-1",
          "https://ubuntu.com/security/notices/USN-5583-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2526",
        "resource": "libsystemd0",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd-resolved: use-after-free when dealing with DnsStream in resolved-dns-stream.c",
        "vulnerabilityID": "CVE-2022-2526"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "It was discovered that a systemd service that uses DynamicUser property can create a SUID/SGID binary that would be allowed to run as the transient service UID/GID even after the service is terminated. A local attacker may use this flaw to access resources that will be owned by a potentially different service in the future, when the UID/GID will be recycled.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://www.securityfocus.com/bid/108116",
          "https://access.redhat.com/security/cve/CVE-2019-3843",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843",
          "https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)",
          "https://linux.oracle.com/cve/CVE-2019-3843.html",
          "https://linux.oracle.com/errata/ELSA-2020-1794.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-3843",
          "https://security.netapp.com/advisory/ntap-20190619-0002/",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://usn.ubuntu.com/4269-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-3843",
        "resource": "libsystemd0",
        "score": 4.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: services with DynamicUser can create SUID/SGID binaries",
        "vulnerabilityID": "CVE-2019-3843"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "It was discovered that a systemd service that uses DynamicUser property can get new privileges through the execution of SUID binaries, which would allow to create binaries owned by the service transient group with the setgid bit set. A local attacker may use this flaw to access resources that will be owned by a potentially different service in the future, when the GID will be recycled.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://www.securityfocus.com/bid/108096",
          "https://access.redhat.com/security/cve/CVE-2019-3844",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844",
          "https://linux.oracle.com/cve/CVE-2019-3844.html",
          "https://linux.oracle.com/errata/ELSA-2020-1794.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-3844",
          "https://security.netapp.com/advisory/ntap-20190619-0002/",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://usn.ubuntu.com/4269-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-3844",
        "resource": "libsystemd0",
        "score": 4.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: services with DynamicUser can get new privileges and create SGID binaries",
        "vulnerabilityID": "CVE-2019-3844"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A heap use-after-free vulnerability was found in systemd before version v245-rc1, where asynchronous Polkit queries are performed while handling dbus messages. A local unprivileged attacker can abuse this flaw to crash systemd services or potentially execute code and elevate their privileges, by sending specially crafted dbus messages.",
        "fixedVersion": "232-25+deb9u14",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-1712",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1712",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1712",
          "https://github.com/systemd/systemd/commit/1068447e6954dc6ce52f099ed174c442cb89ed54",
          "https://github.com/systemd/systemd/commit/637486261528e8aa3da9f26a4487dc254f4b7abb",
          "https://github.com/systemd/systemd/commit/bc130b6858327b382b07b3985cf48e2aa9016b2d",
          "https://github.com/systemd/systemd/commit/ea0d0ede03c6f18dbc5036c5e9cccf97e415ccc2",
          "https://linux.oracle.com/cve/CVE-2020-1712.html",
          "https://linux.oracle.com/errata/ELSA-2020-0575.html",
          "https://lists.debian.org/debian-lts-announce/2022/06/msg00025.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1712",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://www.openwall.com/lists/oss-security/2020/02/05/1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1712",
        "resource": "libsystemd0",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: use-after-free when asynchronous polkit queries are performed",
        "vulnerabilityID": "CVE-2020-1712"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.9,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:C",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "basic/unit-name.c in systemd prior to 246.15, 247.8, 248.5, and 249.1 has a Memory Allocation with an Excessive Size Value (involving strdupa and alloca for a pathname controlled by a local attacker) that results in an operating system crash.",
        "fixedVersion": "232-25+deb9u13",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html",
          "http://www.openwall.com/lists/oss-security/2021/08/04/2",
          "http://www.openwall.com/lists/oss-security/2021/08/17/3",
          "http://www.openwall.com/lists/oss-security/2021/09/07/3",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-33910.json",
          "https://access.redhat.com/security/cve/CVE-2021-33910",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-222547.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33910",
          "https://github.com/systemd/systemd-stable/commit/4a1c5f34bd3e1daed4490e9d97918e504d19733b",
          "https://github.com/systemd/systemd-stable/commit/764b74113e36ac5219a4b82a05f311b5a92136ce",
          "https://github.com/systemd/systemd-stable/commit/b00674347337b7531c92fdb65590ab253bb57538",
          "https://github.com/systemd/systemd-stable/commit/cfd14c65374027b34dbbc4f0551456c5dc2d1f61",
          "https://github.com/systemd/systemd/commit/b34a4f0e6729de292cb3b0c03c1d48f246ad896b",
          "https://github.com/systemd/systemd/pull/20256/commits/441e0115646d54f080e5c3bb0ba477c892861ab9",
          "https://linux.oracle.com/cve/CVE-2021-33910.html",
          "https://linux.oracle.com/errata/ELSA-2021-2717.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2LSDMHAKI4LGFOCSPXNVVSEWQFAVFWR7/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-33910",
          "https://security.gentoo.org/glsa/202107-48",
          "https://security.netapp.com/advisory/ntap-20211104-0008/",
          "https://ubuntu.com/security/notices/USN-5013-1",
          "https://ubuntu.com/security/notices/USN-5013-2",
          "https://www.debian.org/security/2021/dsa-4942",
          "https://www.openwall.com/lists/oss-security/2021/07/20/2",
          "https://www.qualys.com/2021/07/20/cve-2021-33910/denial-of-service-systemd.txt"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-33910",
        "resource": "libsystemd0",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: uncontrolled allocation on the stack in function unit_name_path_escape leads to crash",
        "vulnerabilityID": "CVE-2021-33910"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A flaw was found in systemd. An uncontrolled recursion in systemd-tmpfiles may lead to a denial of service at boot time when too many nested directories are created in /tmp.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-3997",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2024639",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997",
          "https://github.com/systemd/systemd/commit/5b1cf7a9be37e20133c0208005274ce4a5b5c6a1",
          "https://ubuntu.com/security/notices/USN-5226-1",
          "https://www.openwall.com/lists/oss-security/2022/01/10/2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3997",
        "resource": "libsystemd0",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: Uncontrolled recursion in systemd-tmpfiles when removing files",
        "vulnerabilityID": "CVE-2021-3997"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 3.3,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:N"
          },
          "redhat": {
            "V2Score": 3.3,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:N"
          }
        },
        "description": "systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725357",
          "http://www.openwall.com/lists/oss-security/2013/10/01/9",
          "https://access.redhat.com/security/cve/CVE-2013-4392",
          "https://bugzilla.redhat.com/show_bug.cgi?id=859060"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2013-4392",
        "resource": "libsystemd0",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: TOCTOU race condition when updating file permissions and SELinux security contexts",
        "vulnerabilityID": "CVE-2013-4392"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 10,
            "V2Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.2,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "systemd v233 and earlier fails to safely parse usernames starting with a numeric digit (e.g. \"0day\"), running the service in question with root privileges rather than the user intended.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://www.openwall.com/lists/oss-security/2017/07/02/1",
          "http://www.securityfocus.com/bid/99507",
          "http://www.securitytracker.com/id/1038839",
          "https://access.redhat.com/security/cve/CVE-2017-1000082",
          "https://github.com/systemd/systemd/issues/6237"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-1000082",
        "resource": "libsystemd0",
        "score": 7.2,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: fails to parse usernames that start with digits",
        "vulnerabilityID": "CVE-2017-1000082"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "systemd-tmpfiles in systemd before 237 attempts to support ownership/permission changes on hardlinked files even if the fs.protected_hardlinks sysctl is turned off, which allows local users to bypass intended access restrictions via vectors involving a hard link to a file for which the user lacks write access, as demonstrated by changing the ownership of the /etc/passwd file.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://lists.opensuse.org/opensuse-updates/2018-02/msg00109.html",
          "http://packetstormsecurity.com/files/146184/systemd-Local-Privilege-Escalation.html",
          "http://www.openwall.com/lists/oss-security/2018/01/29/3",
          "https://access.redhat.com/security/cve/CVE-2017-18078",
          "https://github.com/systemd/systemd/issues/7736",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2019/04/msg00022.html",
          "https://www.exploit-db.com/exploits/43935/",
          "https://www.openwall.com/lists/oss-security/2018/01/29/4"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-18078",
        "resource": "libsystemd0",
        "score": 6.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: Unsafe handling of hard links allowing privilege escalation",
        "vulnerabilityID": "CVE-2017-18078"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "It was discovered systemd does not correctly check the content of PIDFile files before using it to kill processes. When a service is run from an unprivileged user (e.g. User field set in the service file), a local attacker who is able to write to the PIDFile of the mentioned service may use this flaw to trick systemd into killing other services and/or privileged processes. Versions before v237 are vulnerable.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/errata/RHSA-2019:2091",
          "https://access.redhat.com/security/cve/CVE-2018-16888",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16888",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16888",
          "https://linux.oracle.com/cve/CVE-2018-16888.html",
          "https://linux.oracle.com/errata/ELSA-2019-2091.html",
          "https://lists.apache.org/thread.html/5960a34a524848cd722fd7ab7e2227eac10107b0f90d9d1e9c3caa74@%3Cuser.cassandra.apache.org%3E",
          "https://security.netapp.com/advisory/ntap-20190307-0007/",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://usn.ubuntu.com/4269-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-16888",
        "resource": "libsystemd0",
        "score": 4.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: kills privileged process if unprivileged PIDFile was tampered",
        "vulnerabilityID": "CVE-2018-16888"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "systemd-tmpfiles in systemd through 237 mishandles symlinks present in non-terminal path components, which allows local users to obtain ownership of arbitrary files via vectors involving creation of a directory and a file under that directory, and later replacing that directory with a symlink. This occurs even if the fs.protected_symlinks sysctl is turned on.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00062.html",
          "https://access.redhat.com/security/cve/CVE-2018-6954",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6954",
          "https://github.com/systemd/systemd/issues/7986",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://ubuntu.com/security/notices/USN-3816-1",
          "https://ubuntu.com/security/notices/USN-3816-2",
          "https://usn.ubuntu.com/3816-1/",
          "https://usn.ubuntu.com/3816-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6954",
        "resource": "libsystemd0",
        "score": 7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: Mishandled symlinks in systemd-tmpfiles allows local users to obtain ownership of arbitrary files",
        "vulnerabilityID": "CVE-2018-6954"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 2.4,
            "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 2.4,
            "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the udevadm trigger command, a memory leak may occur.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00014.html",
          "https://access.redhat.com/security/cve/CVE-2019-20386",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20386",
          "https://github.com/systemd/systemd/commit/b2774a3ae692113e1f47a336a6c09bac9cfb49ad",
          "https://linux.oracle.com/cve/CVE-2019-20386.html",
          "https://linux.oracle.com/errata/ELSA-2020-4553.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HZPCOMW5X6IZZXASCDD2CNW2DLF3YADC/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-20386",
          "https://security.netapp.com/advisory/ntap-20200210-0002/",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://usn.ubuntu.com/4269-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-20386",
        "resource": "libsystemd0",
        "score": 2.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: memory leak in button_open() in login/logind-button.c when udev events are received",
        "vulnerabilityID": "CVE-2019-20386"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.9,
            "V2Vector": "AV:A/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H"
          }
        },
        "description": "An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://www.openwall.com/lists/oss-security/2021/08/04/2",
          "http://www.openwall.com/lists/oss-security/2021/08/17/3",
          "http://www.openwall.com/lists/oss-security/2021/09/07/3",
          "https://access.redhat.com/security/cve/CVE-2020-13529",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13529",
          "https://linux.oracle.com/cve/CVE-2020-13529.html",
          "https://linux.oracle.com/errata/ELSA-2021-4361.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/",
          "https://security.gentoo.org/glsa/202107-48",
          "https://security.netapp.com/advisory/ntap-20210625-0005/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1142",
          "https://ubuntu.com/security/notices/USN-5013-1",
          "https://ubuntu.com/security/notices/USN-5013-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-13529",
        "resource": "libsystemd0",
        "score": 6.1,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: DHCP FORCERENEW authentication not implemented can cause a system running the DHCP client to have its network reconfigured",
        "vulnerabilityID": "CVE-2020-13529"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "systemd through v245 mishandles numerical usernames such as ones composed of decimal digits or 0x followed by hex digits, as demonstrated by use of root privileges when privileges of the 0x0 user account were intended. NOTE: this issue exists because of an incomplete fix for CVE-2017-1000082.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-13776",
          "https://github.com/systemd/systemd/issues/15985",
          "https://linux.oracle.com/cve/CVE-2020-13776.html",
          "https://linux.oracle.com/errata/ELSA-2021-1611.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IYGLFEKG45EYBJ7TPQMLWROWPTZBEU63/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-13776",
          "https://security.netapp.com/advisory/ntap-20200611-0003/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-13776",
        "resource": "libsystemd0",
        "score": 6.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: Mishandles numerical usernames beginning with decimal digits or 0x followed by hexadecimal digits",
        "vulnerabilityID": "CVE-2020-13776"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L"
          }
        },
        "description": "Heap-based buffer overflow in the cpSeparateBufToContigBuf function in tiffcp.c in LibTIFF 3.9.3, 3.9.4, 3.9.5, 3.9.6, 3.9.7, 4.0.0beta7, 4.0.0alpha4, 4.0.0alpha5, 4.0.0alpha6, 4.0.0, 4.0.1, 4.0.2, 4.0.3, 4.0.4, 4.0.4beta, 4.0.5, 4.0.6, 4.0.7, 4.0.8 and 4.0.9 allows remote attackers to cause a denial of service (crash) or possibly have unspecified other impact via a crafted TIFF file.",
        "fixedVersion": "4.0.8-2+deb9u5",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2798",
          "https://access.redhat.com/errata/RHSA-2019:2053",
          "https://access.redhat.com/errata/RHSA-2019:3419",
          "https://access.redhat.com/security/cve/CVE-2018-12900",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12900",
          "https://github.com/Hack-Me/Pocs_for_Multi_Versions/tree/main/CVE-2018-12900",
          "https://linux.oracle.com/cve/CVE-2018-12900.html",
          "https://linux.oracle.com/errata/ELSA-2019-3419.html",
          "https://lists.debian.org/debian-lts-announce/2019/11/msg00027.html",
          "https://ubuntu.com/security/notices/USN-3906-1",
          "https://ubuntu.com/security/notices/USN-3906-2",
          "https://usn.ubuntu.com/3906-1/",
          "https://usn.ubuntu.com/3906-2/",
          "https://www.debian.org/security/2020/dsa-4670"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-12900",
        "resource": "libtiff5",
        "score": 5.3,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Heap-based buffer overflow in the cpSeparateBufToContigBuf function resulting in a denial of service or possibly code execution",
        "vulnerabilityID": "CVE-2018-12900"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "An issue was discovered in LibTIFF 4.0.9. There is a int32 overflow in multiply_ms in tools/ppm2tiff.c, which can cause a denial of service (crash) or possibly have unspecified other impact via a crafted image file.",
        "fixedVersion": "4.0.8-2+deb9u5",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2810",
          "https://access.redhat.com/errata/RHSA-2019:2053",
          "https://access.redhat.com/security/cve/CVE-2018-17100",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17100",
          "https://gitlab.com/libtiff/libtiff/merge_requests/33/diffs?commit_id=6da1fb3f64d43be37e640efbec60400d1f1ac39e",
          "https://linux.oracle.com/cve/CVE-2018-17100.html",
          "https://linux.oracle.com/errata/ELSA-2019-2053.html",
          "https://lists.debian.org/debian-lts-announce/2018/10/msg00019.html",
          "https://ubuntu.com/security/notices/USN-3864-1",
          "https://ubuntu.com/security/notices/USN-3906-2",
          "https://usn.ubuntu.com/3864-1/",
          "https://usn.ubuntu.com/3906-2/",
          "https://www.debian.org/security/2020/dsa-4670"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-17100",
        "resource": "libtiff5",
        "score": 4.7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Integer overflow in multiply_ms in tools/ppm2tiff.c",
        "vulnerabilityID": "CVE-2018-17100"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "tif_getimage.c in LibTIFF through 4.0.10, as used in GDAL through 3.0.1 and other products, has an integer overflow that potentially causes a heap-based buffer overflow via a crafted RGBA image, related to a \"Negative-size-param\" condition.",
        "fixedVersion": "4.0.8-2+deb9u5",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-17546",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=16443",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17546",
          "https://github.com/OSGeo/gdal/commit/21674033ee246f698887604c7af7ba1962a40ddf",
          "https://gitlab.com/libtiff/libtiff/commit/4bb584a35f87af42d6cf09d15e9ce8909a839145",
          "https://linux.oracle.com/cve/CVE-2019-17546.html",
          "https://linux.oracle.com/errata/ELSA-2020-4634.html",
          "https://lists.debian.org/debian-lts-announce/2019/11/msg00027.html",
          "https://lists.debian.org/debian-lts-announce/2020/03/msg00020.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LM5ZW7E3IEW7LT2BPJP7D3RN6OUOE3MX/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M3S4WNIMZ7XSLY2LD5FPRPZMGNUBVKOG/",
          "https://seclists.org/bugtraq/2020/Jan/32",
          "https://security.gentoo.org/glsa/202003-25",
          "https://ubuntu.com/security/notices/USN-4158-1",
          "https://www.debian.org/security/2020/dsa-4608",
          "https://www.debian.org/security/2020/dsa-4670"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17546",
        "resource": "libtiff5",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: integer overflow leading to heap-based buffer overflow in tif_getimage.c",
        "vulnerabilityID": "CVE-2019-17546"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Buffer Overflow in LibTiff v4.0.10 allows attackers to cause a denial of service via the \"invertImage()\" function in the component \"tiffcrop\".",
        "fixedVersion": "4.0.8-2+deb9u7",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://blog.topsec.com.cn/%E5%A4%A9%E8%9E%8D%E4%BF%A1%E5%85%B3%E4%BA%8Elibtiff%E4%B8%ADinvertimage%E5%87%BD%E6%95%B0%E5%A0%86%E6%BA%A2%E5%87%BA%E6%BC%8F%E6%B4%9E%E7%9A%84%E5%88%86%E6%9E%90/",
          "http://bugzilla.maptools.org/show_bug.cgi?id=2831",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-19131.json",
          "https://access.redhat.com/security/cve/CVE-2020-19131",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-19131",
          "https://errata.almalinux.org/8/ALSA-2022-1810.html",
          "https://linux.oracle.com/cve/CVE-2020-19131.html",
          "https://linux.oracle.com/errata/ELSA-2022-1810.html",
          "https://lists.debian.org/debian-lts-announce/2021/10/msg00004.html",
          "https://ubuntu.com/security/notices/USN-5523-1",
          "https://ubuntu.com/security/notices/USN-5619-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-19131",
        "resource": "libtiff5",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: a buffer overflow via the \"invertImage()\" may lead to DoS",
        "vulnerabilityID": "CVE-2020-19131"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An integer overflow flaw was found in libtiff that exists in the tif_getimage.c file. This flaw allows an attacker to inject and execute arbitrary code when a user opens a crafted TIFF file. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
        "fixedVersion": "4.0.8-2+deb9u6",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-35523",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1932040",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35523",
          "https://gitlab.com/libtiff/libtiff/-/commit/c8d613ef497058fe653c467fc84c70a62a4a71b2",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/160",
          "https://linux.oracle.com/cve/CVE-2020-35523.html",
          "https://linux.oracle.com/errata/ELSA-2021-4241.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00023.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BMHBYFMX3D5VGR6Y3RXTTH3Q4NF4E6IG/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-35523",
          "https://security.gentoo.org/glsa/202104-06",
          "https://security.netapp.com/advisory/ntap-20210521-0009/",
          "https://ubuntu.com/security/notices/USN-4755-1",
          "https://www.debian.org/security/2021/dsa-4869"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-35523",
        "resource": "libtiff5",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Integer overflow in tif_getimage.c",
        "vulnerabilityID": "CVE-2020-35523"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A heap-based buffer overflow flaw was found in libtiff in the handling of TIFF images in libtiff's TIFF2PDF tool. A specially crafted TIFF file can lead to arbitrary code execution. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
        "fixedVersion": "4.0.8-2+deb9u6",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-35524",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1932044",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35524",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/159",
          "https://gitlab.com/rzkn/libtiff/-/commit/7be2e452ddcf6d7abca88f41d3761e6edab72b22",
          "https://linux.oracle.com/cve/CVE-2020-35524.html",
          "https://linux.oracle.com/errata/ELSA-2021-4241.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00023.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BMHBYFMX3D5VGR6Y3RXTTH3Q4NF4E6IG/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-35524",
          "https://security.gentoo.org/glsa/202104-06",
          "https://security.netapp.com/advisory/ntap-20210521-0009/",
          "https://ubuntu.com/security/notices/USN-4755-1",
          "https://www.debian.org/security/2021/dsa-4869"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-35524",
        "resource": "libtiff5",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Heap-based buffer overflow in TIFF2PDF tool",
        "vulnerabilityID": "CVE-2020-35524"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "A heap buffer overflow in ExtractImageSection function in tiffcrop.c in libtiff library Version 4.3.0 allows attacker to trigger unsafe or out of bounds memory access via crafted TIFF image file which could result into application crash, potential information disclosure or any other context-dependent impact",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0891",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0891",
          "https://gitlab.com/freedesktop-sdk/mirrors/gitlab/libtiff/libtiff/-/commit/232282fd8f9c21eefe8d2d2b96cdbbb172fe7b7c",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-0891.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/232282fd8f9c21eefe8d2d2b96cdbbb172fe7b7c",
          "https://gitlab.com/libtiff/libtiff/-/issues/380",
          "https://gitlab.com/libtiff/libtiff/-/issues/382",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNT2GFNRLOMKJ5KXM6JIHKBNBFDVZPD3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZQ4E654ZYUUUQNBKYQFXNK2CV3CPWTM2/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0891",
          "https://ubuntu.com/security/notices/USN-5421-1",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0891",
        "resource": "libtiff5",
        "score": 6.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: heap buffer overflow in extractImageSection",
        "vulnerabilityID": "CVE-2022-0891"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L"
          }
        },
        "description": "libtiff's tiffcrop utility has a uint32_t underflow that can lead to out of bounds read and write. An attacker who supplies a crafted file to tiffcrop (likely via tricking a user to run tiffcrop on it with certain parameters) could cause a crash or in some cases, further exploitation.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2867",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2118847",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2867",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2867",
          "https://ubuntu.com/security/notices/USN-5604-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2867",
        "resource": "libtiff5",
        "score": 7.3,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: uint32_t underflow leads to out of bounds read and write in tiffcrop.c",
        "vulnerabilityID": "CVE-2022-2867"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.4,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          }
        },
        "description": "libtiff's tiffcrop utility has a improper input validation flaw that can lead to out of bounds read and ultimately cause a crash if an attacker is able to supply a crafted file to tiffcrop.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2868",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2118863",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2868",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2868",
          "https://ubuntu.com/security/notices/USN-5604-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2868",
        "resource": "libtiff5",
        "score": 4.4,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Invalid crop_width and/or crop_length could cause an out-of-bounds read in reverseSamples16bits()",
        "vulnerabilityID": "CVE-2022-2868"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L"
          }
        },
        "description": "libtiff's tiffcrop tool has a uint32_t underflow which leads to out of bounds read and write in the extractContigSamples8bits routine. An attacker who supplies a crafted file to tiffcrop could trigger this flaw, most likely by tricking a user into opening the crafted file with tiffcrop. Triggering this flaw could cause a crash or potentially further exploitation.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2869",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2118869",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2869",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2869",
          "https://ubuntu.com/security/notices/USN-5604-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2869",
        "resource": "libtiff5",
        "score": 7.3,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: tiffcrop.c has uint32_t underflow which leads to out of bounds read and write in extractContigSamples8bits()",
        "vulnerabilityID": "CVE-2022-2869"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A NULL pointer dereference in the function _TIFFmemcmp at tif_unix.c (called from TIFFWriteDirectoryTagTransferfunction) in LibTIFF 4.0.9 allows an attacker to cause a denial-of-service through a crafted tiff file. This vulnerability can be triggered by the executable tiffcp.",
        "fixedVersion": "4.0.8-2+deb9u5",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2811",
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00041.html",
          "http://www.securityfocus.com/bid/105342",
          "https://access.redhat.com/security/cve/CVE-2018-17000",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17000",
          "https://lists.debian.org/debian-lts-announce/2019/02/msg00026.html",
          "https://ubuntu.com/security/notices/USN-3906-1",
          "https://usn.ubuntu.com/3906-1/",
          "https://www.debian.org/security/2020/dsa-4670"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-17000",
        "resource": "libtiff5",
        "score": 4.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: NULL pointer dereference in function _TIFFmemcmp at tif_unix.c",
        "vulnerabilityID": "CVE-2018-17000"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In LibTIFF 4.0.9, there is a NULL pointer dereference in the TIFFWriteDirectorySec function in tif_dirwrite.c that will lead to a denial of service attack, as demonstrated by tiffset.",
        "fixedVersion": "4.0.8-2+deb9u5",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2820",
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00041.html",
          "http://packetstormsecurity.com/files/155095/Slackware-Security-Advisory-libtiff-Updates.html",
          "http://www.securityfocus.com/bid/105932",
          "https://access.redhat.com/security/cve/CVE-2018-19210",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19210",
          "https://lists.debian.org/debian-lts-announce/2019/02/msg00026.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/C6IL2QFKE6MGVUTOPU2UUWITTE36KRDF/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TX5UEYHGMTNEHJB4FHE7HCJ75UQDNKGB/",
          "https://seclists.org/bugtraq/2019/Nov/5",
          "https://security.gentoo.org/glsa/202003-25",
          "https://ubuntu.com/security/notices/USN-3906-1",
          "https://usn.ubuntu.com/3906-1/",
          "https://www.debian.org/security/2020/dsa-4670"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-19210",
        "resource": "libtiff5",
        "score": 3.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: NULL pointer dereference in TIFFWriteDirectorySec function in tif_dirwrite.c",
        "vulnerabilityID": "CVE-2018-19210"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"
          }
        },
        "description": "_TIFFCheckMalloc and _TIFFCheckRealloc in tif_aux.c in LibTIFF through 4.0.10 mishandle Integer Overflow checks because they rely on compiler behavior that is undefined by the applicable C standards. This can, for example, lead to an application crash.",
        "fixedVersion": "4.0.8-2+deb9u5",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00102.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00023.html",
          "http://packetstormsecurity.com/files/155095/Slackware-Security-Advisory-libtiff-Updates.html",
          "https://access.redhat.com/security/cve/CVE-2019-14973",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14973",
          "https://gitlab.com/libtiff/libtiff/merge_requests/90",
          "https://linux.oracle.com/cve/CVE-2019-14973.html",
          "https://linux.oracle.com/errata/ELSA-2020-3902.html",
          "https://lists.debian.org/debian-lts-announce/2019/08/msg00031.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/63BVT6N5KQPHWOWM4B3I7Z3ODBXUVNPS/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ADNPG7JJTRRK22GUVTAFH3GJ6WGKUZJB/",
          "https://seclists.org/bugtraq/2019/Nov/5",
          "https://seclists.org/bugtraq/2020/Jan/32",
          "https://ubuntu.com/security/notices/USN-4158-1",
          "https://www.debian.org/security/2020/dsa-4608",
          "https://www.debian.org/security/2020/dsa-4670"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-14973",
        "resource": "libtiff5",
        "score": 4.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: integer overflow in _TIFFCheckMalloc and _TIFFCheckRealloc in tif_aux.c",
        "vulnerabilityID": "CVE-2019-14973"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "An Invalid Address dereference was discovered in TIFFWriteDirectoryTagTransferfunction in libtiff/tif_dirwrite.c in LibTIFF 4.0.10, affecting the cpSeparateBufToContigBuf function in tiffcp.c. Remote attackers could leverage this vulnerability to cause a denial-of-service via a crafted tiff file. This is different from CVE-2018-12900.",
        "fixedVersion": "4.0.8-2+deb9u5",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2833",
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00041.html",
          "https://access.redhat.com/security/cve/CVE-2019-7663",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7663",
          "https://gitlab.com/libtiff/libtiff/commit/802d3cbf3043be5dce5317e140ccb1c17a6a2d39",
          "https://lists.debian.org/debian-lts-announce/2019/02/msg00026.html",
          "https://security.gentoo.org/glsa/202003-25",
          "https://ubuntu.com/security/notices/USN-3906-1",
          "https://ubuntu.com/security/notices/USN-3906-2",
          "https://usn.ubuntu.com/3906-1/",
          "https://usn.ubuntu.com/3906-2/",
          "https://www.debian.org/security/2020/dsa-4670"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-7663",
        "resource": "libtiff5",
        "score": 6.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: integer overflow in libtiff/tif_dirwrite.c resulting in an invalid pointer dereference",
        "vulnerabilityID": "CVE-2019-7663"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Buffer Overflow in LibTiff v4.0.10 allows attackers to cause a denial of service via the 'in _TIFFmemcpy' funtion in the component 'tif_unix.c'.",
        "fixedVersion": "4.0.8-2+deb9u7",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2852",
          "https://access.redhat.com/security/cve/CVE-2020-19144",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-19144",
          "https://gitlab.com/libtiff/libtiff/-/issues/159",
          "https://lists.debian.org/debian-lts-announce/2021/10/msg00004.html",
          "https://security.netapp.com/advisory/ntap-20211004-0005/",
          "https://ubuntu.com/security/notices/USN-5523-1",
          "https://ubuntu.com/security/notices/USN-5619-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-19144",
        "resource": "libtiff5",
        "score": 7.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: heap-based buffer overflow in _TIFFmemcpy() in tif_unix.c",
        "vulnerabilityID": "CVE-2020-19144"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Null source pointer passed as an argument to memcpy() function within TIFFFetchStripThing() in tif_dirread.c in libtiff versions from 3.9.0 to 4.3.0 could lead to Denial of Service via crafted TIFF file. For users that compile libtiff from sources, the fix is available with commit eecb0712.",
        "fixedVersion": "4.0.8-2+deb9u8",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0561",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0561",
          "https://gitlab.com/freedesktop-sdk/mirrors/gitlab/libtiff/libtiff/-/commit/eecb0712f4c3a5b449f70c57988260a667ddbdef",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-0561.json",
          "https://gitlab.com/libtiff/libtiff/-/issues/362",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00001.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DZEHZ35XVO2VBZ4HHCMM6J6TQIDSBQOM/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0561",
          "https://security.netapp.com/advisory/ntap-20220318-0001/",
          "https://ubuntu.com/security/notices/USN-5421-1",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0561",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Denial of Service via crafted TIFF file",
        "vulnerabilityID": "CVE-2022-0561"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Null source pointer passed as an argument to memcpy() function within TIFFReadDirectory() in tif_dirread.c in libtiff versions from 4.0 to 4.3.0 could lead to Denial of Service via crafted TIFF file. For users that compile libtiff from sources, a fix is available with commit 561599c.",
        "fixedVersion": "4.0.8-2+deb9u8",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0562",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0562",
          "https://gitlab.com/gitlab-org/build/omnibus-mirror/libtiff/-/commit/561599c99f987dc32ae110370cfdd7df7975586b",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-0562.json",
          "https://gitlab.com/libtiff/libtiff/-/issues/362",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00001.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DZEHZ35XVO2VBZ4HHCMM6J6TQIDSBQOM/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0562",
          "https://security.netapp.com/advisory/ntap-20220318-0001/",
          "https://ubuntu.com/security/notices/USN-5421-1",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0562",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Null source pointer lead to Denial of Service via crafted TIFF file",
        "vulnerabilityID": "CVE-2022-0562"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.2,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Reachable Assertion in tiffcp in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 5e180045.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0865",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0865",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-0865.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/a1c933dabd0e1c54a412f3f84ae0aa58115c6067",
          "https://gitlab.com/libtiff/libtiff/-/issues/385",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/306",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNT2GFNRLOMKJ5KXM6JIHKBNBFDVZPD3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZQ4E654ZYUUUQNBKYQFXNK2CV3CPWTM2/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0865",
          "https://ubuntu.com/security/notices/USN-5421-1",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0865",
        "resource": "libtiff5",
        "score": 6.2,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: reachable assertion",
        "vulnerabilityID": "CVE-2022-0865"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Unchecked Return Value to NULL Pointer Dereference in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f2b656e2.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0907",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0907",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-0907.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/40b00cfb32256d377608b4d4cd30fac338d0a0bc",
          "https://gitlab.com/libtiff/libtiff/-/issues/392",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/314",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNT2GFNRLOMKJ5KXM6JIHKBNBFDVZPD3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZQ4E654ZYUUUQNBKYQFXNK2CV3CPWTM2/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0907",
          "https://security.netapp.com/advisory/ntap-20220506-0002/",
          "https://ubuntu.com/security/notices/USN-5523-1",
          "https://ubuntu.com/security/notices/USN-5523-2",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0907",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tiff: NULL Pointer Dereference in tiffcrop",
        "vulnerabilityID": "CVE-2022-0907"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Null source pointer passed as an argument to memcpy() function within TIFFFetchNormalTag () in tif_dirread.c in libtiff versions up to 4.3.0 could lead to Denial of Service via crafted TIFF file.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0908",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0908",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-0908.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/a95b799f65064e4ba2e2dfc206808f86faf93e85",
          "https://gitlab.com/libtiff/libtiff/-/issues/383",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNT2GFNRLOMKJ5KXM6JIHKBNBFDVZPD3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZQ4E654ZYUUUQNBKYQFXNK2CV3CPWTM2/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0908",
          "https://security.netapp.com/advisory/ntap-20220506-0002/",
          "https://ubuntu.com/security/notices/USN-5523-1",
          "https://ubuntu.com/security/notices/USN-5523-2",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0908",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tiff: Null source pointer passed as an argument to memcpy in TIFFFetchNormalTag() in tif_dirread.c",
        "vulnerabilityID": "CVE-2022-0908"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Divide By Zero error in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f8d0f9aa.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0909",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0909",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-0909.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/32ea0722ee68f503b7a3f9b2d557acb293fc8cde",
          "https://gitlab.com/libtiff/libtiff/-/issues/393",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/310",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNT2GFNRLOMKJ5KXM6JIHKBNBFDVZPD3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZQ4E654ZYUUUQNBKYQFXNK2CV3CPWTM2/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0909",
          "https://security.netapp.com/advisory/ntap-20220506-0002/",
          "https://ubuntu.com/security/notices/USN-5523-1",
          "https://ubuntu.com/security/notices/USN-5523-2",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0909",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tiff: Divide By Zero error in tiffcrop",
        "vulnerabilityID": "CVE-2022-0909"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "Out-of-bounds Read error in tiffcp in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 408976c4.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0924",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0924",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-0924.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/88d79a45a31c74cba98c697892fed5f7db8b963a",
          "https://gitlab.com/libtiff/libtiff/-/issues/278",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/311",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNT2GFNRLOMKJ5KXM6JIHKBNBFDVZPD3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZQ4E654ZYUUUQNBKYQFXNK2CV3CPWTM2/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0924",
          "https://security.netapp.com/advisory/ntap-20220506-0002/",
          "https://ubuntu.com/security/notices/USN-5523-1",
          "https://ubuntu.com/security/notices/USN-5523-2",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0924",
        "resource": "libtiff5",
        "score": 6.1,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Out-of-bounds Read error in tiffcp",
        "vulnerabilityID": "CVE-2022-0924"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A heap buffer overflow flaw was found in Libtiffs' tiffinfo.c in TIFFReadRawDataStriped() function. This flaw allows an attacker to pass a crafted TIFF file to the tiffinfo tool, triggering a heap buffer overflow issue and causing a crash that leads to a denial of service.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1354",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2074404",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1354",
          "https://gitlab.com/libtiff/libtiff/-/commit/87f580f39011109b3bb5f6eca13fac543a542798",
          "https://gitlab.com/libtiff/libtiff/-/issues/319",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1354",
          "https://security.netapp.com/advisory/ntap-20221014-0007/",
          "https://ubuntu.com/security/notices/USN-5619-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1354",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: heap-buffer-overflow in TIFFReadRawDataStriped() in tiffinfo.c",
        "vulnerabilityID": "CVE-2022-1354"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H"
          },
          "redhat": {
            "V3Score": 6.6,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H"
          }
        },
        "description": "A stack buffer overflow flaw was found in Libtiffs' tiffcp.c in main() function. This flaw allows an attacker to pass a crafted TIFF file to the tiffcp tool, triggering a stack buffer overflow issue, possibly corrupting the memory, and causing a crash that leads to a denial of service.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1355",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2074415",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1355",
          "https://gitlab.com/libtiff/libtiff/-/issues/400",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/323",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1355",
          "https://security.netapp.com/advisory/ntap-20221014-0007/",
          "https://ubuntu.com/security/notices/USN-5619-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1355",
        "resource": "libtiff5",
        "score": 6.6,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: stack-buffer-overflow in tiffcp.c in main()",
        "vulnerabilityID": "CVE-2022-1355"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "LibTIFF master branch has an out-of-bounds read in LZWDecode in libtiff/tif_lzw.c:619, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit b4e79bfa.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1622",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1622.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/b4e79bfa0c7d2d08f6f1e7ec38143fc8cb11394a",
          "https://gitlab.com/libtiff/libtiff/-/issues/410",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/C7IWZTB4J2N4F5OR5QY4VHDSKWKZSWN3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UXAFOP6QQRNZD3HPZ6BMCEZZOM4YIZMK/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1622",
          "https://security.netapp.com/advisory/ntap-20220616-0005/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1622",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: out-of-bounds read in LZWDecode",
        "vulnerabilityID": "CVE-2022-1622"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "LibTIFF master branch has an out-of-bounds read in LZWDecode in libtiff/tif_lzw.c:624, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit b4e79bfa.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1623",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1623.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/b4e79bfa0c7d2d08f6f1e7ec38143fc8cb11394a",
          "https://gitlab.com/libtiff/libtiff/-/issues/410",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/C7IWZTB4J2N4F5OR5QY4VHDSKWKZSWN3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UXAFOP6QQRNZD3HPZ6BMCEZZOM4YIZMK/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1623",
          "https://security.netapp.com/advisory/ntap-20220616-0005/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1623",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: out-of-bounds read in LZWDecode",
        "vulnerabilityID": "CVE-2022-1623"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Divide By Zero error in tiffcrop in libtiff 4.4.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f3a5e010.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2056",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2056",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2056.json",
          "https://gitlab.com/libtiff/libtiff/-/issues/415",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/346",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4TSS7MJ7OO7JO5BNKCRYSFU7UAYOKLA2/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OXUMJXVEAYFWRO3U3YHKSULHIVDOLEQS/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2056",
          "https://security.netapp.com/advisory/ntap-20220826-0001/",
          "https://ubuntu.com/security/notices/USN-5619-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2056",
        "resource": "libtiff5",
        "score": 5.1,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "LibTiff: DoS from Divide By Zero Error",
        "vulnerabilityID": "CVE-2022-2056"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Divide By Zero error in tiffcrop in libtiff 4.4.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f3a5e010.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2057",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2057",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2057.json",
          "https://gitlab.com/libtiff/libtiff/-/issues/427",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/346",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4TSS7MJ7OO7JO5BNKCRYSFU7UAYOKLA2/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OXUMJXVEAYFWRO3U3YHKSULHIVDOLEQS/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2057",
          "https://security.netapp.com/advisory/ntap-20220826-0001/",
          "https://ubuntu.com/security/notices/USN-5619-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2057",
        "resource": "libtiff5",
        "score": 5.1,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "LibTiff: DoS from Divide By Zero Error",
        "vulnerabilityID": "CVE-2022-2057"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Divide By Zero error in tiffcrop in libtiff 4.4.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f3a5e010.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2058",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2058",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2058.json",
          "https://gitlab.com/libtiff/libtiff/-/issues/428",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/346",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4TSS7MJ7OO7JO5BNKCRYSFU7UAYOKLA2/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OXUMJXVEAYFWRO3U3YHKSULHIVDOLEQS/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2058",
          "https://security.netapp.com/advisory/ntap-20220826-0001/",
          "https://ubuntu.com/security/notices/USN-5619-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2058",
        "resource": "libtiff5",
        "score": 5.1,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "LibTiff: DoS from Divide By Zero Error",
        "vulnerabilityID": "CVE-2022-2058"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "LibTIFF 4.3.0 has an out-of-bounds read in _TIFFmemcpy in tif_unix.c in certain situations involving a custom tag and 0x0200 as the second word of the DE field.",
        "fixedVersion": "4.0.8-2+deb9u8",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-22844",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22844",
          "https://gitlab.com/libtiff/libtiff/-/issues/355",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/287",
          "https://lists.debian.org/debian-lts-announce/2022/03/msg00001.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-22844",
          "https://security.netapp.com/advisory/ntap-20220311-0002/",
          "https://ubuntu.com/security/notices/USN-5523-1",
          "https://ubuntu.com/security/notices/USN-5523-2",
          "https://www.debian.org/security/2022/dsa-5108"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-22844",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: out-of-bounds read in _TIFFmemcpy() in tif_unix.c",
        "vulnerabilityID": "CVE-2022-22844"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A stack overflow was discovered in the _TIFFVGetField function of Tiffsplit v4.4.0. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted TIFF file.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-34526",
          "https://gitlab.com/libtiff/libtiff/-/issues/433",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FC6LWPAEKYJ57LSHX4SBFMLRMLOZTHIJ/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-34526",
          "https://security.netapp.com/advisory/ntap-20220930-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-34526",
        "resource": "libtiff5",
        "score": 6.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: A stack overflow was discovered in the _TIFFVGetField function of Tiffsplit",
        "vulnerabilityID": "CVE-2022-34526"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The _TIFFmalloc function in tif_unix.c in LibTIFF 4.0.3 does not reject a zero size, which allows remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted TIFF image that is mishandled by the TIFFWriteScanline function in tif_write.c, as demonstrated by tiffdither.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2483",
          "http://lists.apple.com/archives/security-announce/2015/Jun/msg00001.html",
          "http://lists.apple.com/archives/security-announce/2015/Jun/msg00002.html",
          "http://openwall.com/lists/oss-security/2015/01/24/15",
          "http://rhn.redhat.com/errata/RHSA-2016-1546.html",
          "http://rhn.redhat.com/errata/RHSA-2016-1547.html",
          "http://support.apple.com/kb/HT204941",
          "http://support.apple.com/kb/HT204942",
          "http://www.conostix.com/pub/adv/CVE-2014-8130-LibTIFF-Division_By_Zero.txt",
          "http://www.securityfocus.com/bid/72353",
          "http://www.securitytracker.com/id/1032760",
          "https://access.redhat.com/security/cve/CVE-2014-8130",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1185817",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8130",
          "https://github.com/vadz/libtiff/commit/3c5eb8b1be544e41d2c336191bc4936300ad7543",
          "https://linux.oracle.com/cve/CVE-2014-8130.html",
          "https://linux.oracle.com/errata/ELSA-2016-1547.html",
          "https://security.gentoo.org/glsa/201701-16",
          "https://ubuntu.com/security/notices/USN-2553-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2014-8130",
        "resource": "libtiff5",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: divide by zero in the tiffdither tool",
        "vulnerabilityID": "CVE-2014-8130"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "** DISPUTED ** LibTIFF 4.0.8 has multiple memory leak vulnerabilities, which allow attackers to cause a denial of service (memory consumption), as demonstrated by tif_open.c, tif_lzw.c, and tif_aux.c. NOTE: Third parties were unable to reproduce the issue.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2018-01/msg00036.html",
          "http://lists.opensuse.org/opensuse-security-announce/2018-01/msg00041.html",
          "http://packetstormsecurity.com/files/150896/LibTIFF-4.0.8-Memory-Leak.html",
          "http://seclists.org/fulldisclosure/2018/Dec/32",
          "http://seclists.org/fulldisclosure/2018/Dec/47",
          "http://www.openwall.com/lists/oss-security/2017/11/01/11",
          "http://www.openwall.com/lists/oss-security/2017/11/01/3",
          "http://www.openwall.com/lists/oss-security/2017/11/01/7",
          "http://www.openwall.com/lists/oss-security/2017/11/01/8",
          "http://www.securityfocus.com/bid/101696",
          "https://access.redhat.com/security/cve/CVE-2017-16232"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-16232",
        "resource": "libtiff5",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Memory leaks in tif_open.c, tif_lzw.c, and tif_aux.c",
        "vulnerabilityID": "CVE-2017-16232"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** In LibTIFF 4.0.8, there is a heap-based use-after-free in the t2p_writeproc function in tiff2pdf.c. NOTE: there is a third-party report of inability to reproduce this issue.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2769",
          "http://www.securityfocus.com/bid/102331",
          "https://access.redhat.com/security/cve/CVE-2017-17973",
          "https://bugzilla.novell.com/show_bug.cgi?id=1074318",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1530912"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-17973",
        "resource": "libtiff5",
        "score": 7.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: heap-based use after free in tiff2pdf.c:t2p_writeproc",
        "vulnerabilityID": "CVE-2017-17973"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L"
          }
        },
        "description": "LibTIFF version 4.0.7 is vulnerable to a heap-based buffer over-read in tif_lzw.c resulting in DoS or code execution via a crafted bmp image to tools/bmp2tiff.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2664",
          "http://www.securityfocus.com/bid/95705",
          "https://access.redhat.com/security/cve/CVE-2017-5563",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5563",
          "https://security.gentoo.org/glsa/201709-27",
          "https://ubuntu.com/security/notices/USN-3606-1",
          "https://usn.ubuntu.com/3606-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-5563",
        "resource": "libtiff5",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Heap-buffer overflow in LZWEncode tif_lzw.c",
        "vulnerabilityID": "CVE-2017-5563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In LibTIFF 4.0.7, the program processes BMP images without verifying that biWidth and biHeight in the bitmap-information header match the actual input, leading to a heap-based buffer over-read in bmp2tiff.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2690",
          "http://www.securityfocus.com/bid/98581",
          "https://access.redhat.com/security/cve/CVE-2017-9117",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9117",
          "https://ubuntu.com/security/notices/USN-3606-1",
          "https://usn.ubuntu.com/3606-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-9117",
        "resource": "libtiff5",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Heap-based buffer over-read in bmp2tiff",
        "vulnerabilityID": "CVE-2017-9117"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "LibTIFF 4.0.9 has a NULL pointer dereference in the jpeg_fdct_16x16 function in jfdctint.c.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2786",
          "https://access.redhat.com/security/cve/CVE-2018-10126",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10126",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-10126",
        "resource": "libtiff5",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: NULL pointer dereference in the jpeg_fdct_16x16 function in jfdctint.c",
        "vulnerabilityID": "CVE-2018-10126"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "An issue was discovered in LibTIFF 4.0.9. There is a NULL pointer dereference in the function LZWDecode in the file tif_lzw.c.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2819",
          "http://www.securityfocus.com/bid/105762",
          "https://access.redhat.com/errata/RHSA-2019:2053",
          "https://access.redhat.com/security/cve/CVE-2018-18661",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18661",
          "https://linux.oracle.com/cve/CVE-2018-18661.html",
          "https://linux.oracle.com/errata/ELSA-2019-2053.html",
          "https://lists.debian.org/debian-lts-announce/2019/11/msg00027.html",
          "https://ubuntu.com/security/notices/USN-3864-1",
          "https://usn.ubuntu.com/3864-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-18661",
        "resource": "libtiff5",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: tiff2bw tool failed memory allocation leads to crash",
        "vulnerabilityID": "CVE-2018-18661"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "The TIFFFdOpen function in tif_unix.c in LibTIFF 4.0.10 has a memory leak, as demonstrated by pal2rgb.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "http://bugzilla.maptools.org/show_bug.cgi?id=2836",
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00041.html",
          "http://packetstormsecurity.com/files/155095/Slackware-Security-Advisory-libtiff-Updates.html",
          "https://access.redhat.com/security/cve/CVE-2019-6128",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6128",
          "https://gitlab.com/libtiff/libtiff/commit/0c74a9f49b8d7a36b17b54a7428b3526d20f88a8",
          "https://lists.debian.org/debian-lts-announce/2019/11/msg00027.html",
          "https://seclists.org/bugtraq/2019/Nov/5",
          "https://security.gentoo.org/glsa/202003-25",
          "https://ubuntu.com/security/notices/USN-3906-1",
          "https://ubuntu.com/security/notices/USN-3906-2",
          "https://usn.ubuntu.com/3906-1/",
          "https://usn.ubuntu.com/3906-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-6128",
        "resource": "libtiff5",
        "score": 8.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: memory leak in TIFFFdOpen function in tif_unix.c when using pal2rgb",
        "vulnerabilityID": "CVE-2019-6128"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A flaw was found in libtiff. Due to a memory allocation failure in tif_read.c, a crafted TIFF file can lead to an abort, resulting in denial of service.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-35521",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1932034",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35521",
          "https://linux.oracle.com/cve/CVE-2020-35521.html",
          "https://linux.oracle.com/errata/ELSA-2021-4241.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BMHBYFMX3D5VGR6Y3RXTTH3Q4NF4E6IG/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-35521",
          "https://security.gentoo.org/glsa/202104-06",
          "https://security.netapp.com/advisory/ntap-20210521-0009/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-35521",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Memory allocation failure in tiff2rgba",
        "vulnerabilityID": "CVE-2020-35521"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In LibTIFF, there is a memory malloc failure in tif_pixarlog.c. A crafted TIFF document can lead to an abort, resulting in a remote denial of service attack.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-35522",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1932037",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35522",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/165",
          "https://linux.oracle.com/cve/CVE-2020-35522.html",
          "https://linux.oracle.com/errata/ELSA-2021-4241.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BMHBYFMX3D5VGR6Y3RXTTH3Q4NF4E6IG/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-35522",
          "https://security.gentoo.org/glsa/202104-06",
          "https://security.netapp.com/advisory/ntap-20210521-0009/",
          "https://ubuntu.com/security/notices/USN-5421-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-35522",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Memory allocation failure in tiff2rgba",
        "vulnerabilityID": "CVE-2020-35522"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "Out-of-bounds Read error in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 46dc8fcd.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1056",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1056.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/232282fd8f9c21eefe8d2d2b96cdbbb172fe7b7c",
          "https://gitlab.com/libtiff/libtiff/-/issues/391",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/307",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1056"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1056",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "Out-of-bounds Read error in tiffcrop in libtiff 4.3.0 allows attackers ...",
        "vulnerabilityID": "CVE-2022-1056"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.3,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "A vulnerability classified as problematic was found in LibTIFF 4.3.0. Affected by this vulnerability is the TIFF File Handler of tiff2ps. Opening a malicious file leads to a denial of service. The attack can be launched remotely but requires user interaction. The exploit has been disclosed to the public and may be used.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-1210",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1210",
          "https://gitlab.com/libtiff/libtiff/-/issues/402",
          "https://gitlab.com/libtiff/libtiff/uploads/c3da94e53cf1e1e8e6d4d3780dc8c42f/example.tiff",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-1210",
          "https://security.netapp.com/advisory/ntap-20220513-0005/",
          "https://vuldb.com/?id.196363"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-1210",
        "resource": "libtiff5",
        "score": 4.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tiff: Malicious file leads to a denial of service in TIFF File Handler",
        "vulnerabilityID": "CVE-2022-1210"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "There is a double free or corruption in rotateImage() at tiffcrop.c:8839 found in libtiff 4.4.0rc1",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2519",
          "https://gitlab.com/libtiff/libtiff/-/issues/423",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/378",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2519"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2519",
        "resource": "libtiff5",
        "score": 6.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Double free or corruption in rotateImage() function at tiffcrop.c",
        "vulnerabilityID": "CVE-2022-2519"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A flaw was found in libtiff 4.4.0rc1. There is a sysmalloc assertion fail in rotateImage() at tiffcrop.c:8621 that can cause program crash when reading a crafted input.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2520",
          "https://gitlab.com/libtiff/libtiff/-/issues/424",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/378",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2520"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2520",
        "resource": "libtiff5",
        "score": 6.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Assertion fail in rotateImage() function at tiffcrop.c",
        "vulnerabilityID": "CVE-2022-2520"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "It was found in libtiff 4.4.0rc1 that there is an invalid pointer free operation in TIFFClose() at tif_close.c:131 called by tiffcrop.c:2522 that can cause a program crash and denial of service while processing crafted input.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2521",
          "https://gitlab.com/libtiff/libtiff/-/issues/422",
          "https://gitlab.com/libtiff/libtiff/-/merge_requests/378",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2521"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2521",
        "resource": "libtiff5",
        "score": 6.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: Invalid pointer free operation in TIFFClose() at tif_close.c",
        "vulnerabilityID": "CVE-2022-2521"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "LibTIFF 4.4.0 has an out-of-bounds read in extractImageSection in tools/tiffcrop.c:6905, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 48d6ece8.",
        "fixedVersion": "",
        "installedVersion": "4.0.8-2+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-2953",
          "https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2953.json",
          "https://gitlab.com/libtiff/libtiff/-/commit/48d6ece8389b01129e7d357f0985c8f938ce3da3",
          "https://gitlab.com/libtiff/libtiff/-/issues/414",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-2953",
          "https://security.netapp.com/advisory/ntap-20221014-0008/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2953",
        "resource": "libtiff5",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libtiff: tiffcrop: heap-buffer-overflow in extractImageSection in tiffcrop.c",
        "vulnerabilityID": "CVE-2022-2953"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-29458",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29458",
          "https://invisible-island.net/ncurses/NEWS.html#t20220416",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00014.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00016.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-29458",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-29458",
        "resource": "libtinfo5",
        "score": 6.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: segfaulting OOB read",
        "vulnerabilityID": "CVE-2022-29458"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In ncurses 6.1, there is a NULL pointer dereference at function _nc_parse_entry in parse_entry.c that will lead to a denial of service attack. The product proceeds to the dereference code path even after a \"dubious character `*' in name or alias field\" detection.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-19211",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1643754",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19211",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-19211",
        "resource": "libtinfo5",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: Null pointer dereference at function _nc_parse_entry in parse_entry.c",
        "vulnerabilityID": "CVE-2018-19211"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the _nc_find_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17594",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17594",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17594.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00017.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17594",
        "resource": "libtinfo5",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the _nc_find_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17594"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          },
          "redhat": {
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the fmt_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17595",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17595",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17595.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00013.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17595",
        "resource": "libtinfo5",
        "score": 5.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the fmt_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17595"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
          "https://access.redhat.com/security/cve/CVE-2021-39537",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39537",
          "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-39537",
        "resource": "libtinfo5",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
        "vulnerabilityID": "CVE-2021-39537"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A use-after-free vulnerability was found in systemd. This issue occurs due to the on_stream_io() function and dns_stream_complete() function in 'resolved-dns-stream.c' not incrementing the reference counting for the DnsStream object. Therefore, other functions and callbacks called can dereference the DNSStream object, causing the use-after-free when the reference is still used later.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/errata/RHSA-2022:6206",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-2526.json",
          "https://access.redhat.com/security/cve/CVE-2022-2526",
          "https://bugzilla.redhat.com/2109926",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2526",
          "https://errata.almalinux.org/8/ALSA-2022-6206.html",
          "https://github.com/systemd/systemd/commit/d973d94dec349fb676fdd844f6fe2ada3538f27c",
          "https://linux.oracle.com/cve/CVE-2022-2526.html",
          "https://linux.oracle.com/errata/ELSA-2022-6206.html",
          "https://ubuntu.com/security/notices/USN-5583-1",
          "https://ubuntu.com/security/notices/USN-5583-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-2526",
        "resource": "libudev1",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd-resolved: use-after-free when dealing with DnsStream in resolved-dns-stream.c",
        "vulnerabilityID": "CVE-2022-2526"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "It was discovered that a systemd service that uses DynamicUser property can create a SUID/SGID binary that would be allowed to run as the transient service UID/GID even after the service is terminated. A local attacker may use this flaw to access resources that will be owned by a potentially different service in the future, when the UID/GID will be recycled.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://www.securityfocus.com/bid/108116",
          "https://access.redhat.com/security/cve/CVE-2019-3843",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843",
          "https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)",
          "https://linux.oracle.com/cve/CVE-2019-3843.html",
          "https://linux.oracle.com/errata/ELSA-2020-1794.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-3843",
          "https://security.netapp.com/advisory/ntap-20190619-0002/",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://usn.ubuntu.com/4269-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-3843",
        "resource": "libudev1",
        "score": 4.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: services with DynamicUser can create SUID/SGID binaries",
        "vulnerabilityID": "CVE-2019-3843"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "It was discovered that a systemd service that uses DynamicUser property can get new privileges through the execution of SUID binaries, which would allow to create binaries owned by the service transient group with the setgid bit set. A local attacker may use this flaw to access resources that will be owned by a potentially different service in the future, when the GID will be recycled.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://www.securityfocus.com/bid/108096",
          "https://access.redhat.com/security/cve/CVE-2019-3844",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844",
          "https://linux.oracle.com/cve/CVE-2019-3844.html",
          "https://linux.oracle.com/errata/ELSA-2020-1794.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-3844",
          "https://security.netapp.com/advisory/ntap-20190619-0002/",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://usn.ubuntu.com/4269-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-3844",
        "resource": "libudev1",
        "score": 4.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: services with DynamicUser can get new privileges and create SGID binaries",
        "vulnerabilityID": "CVE-2019-3844"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A heap use-after-free vulnerability was found in systemd before version v245-rc1, where asynchronous Polkit queries are performed while handling dbus messages. A local unprivileged attacker can abuse this flaw to crash systemd services or potentially execute code and elevate their privileges, by sending specially crafted dbus messages.",
        "fixedVersion": "232-25+deb9u14",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-1712",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1712",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1712",
          "https://github.com/systemd/systemd/commit/1068447e6954dc6ce52f099ed174c442cb89ed54",
          "https://github.com/systemd/systemd/commit/637486261528e8aa3da9f26a4487dc254f4b7abb",
          "https://github.com/systemd/systemd/commit/bc130b6858327b382b07b3985cf48e2aa9016b2d",
          "https://github.com/systemd/systemd/commit/ea0d0ede03c6f18dbc5036c5e9cccf97e415ccc2",
          "https://linux.oracle.com/cve/CVE-2020-1712.html",
          "https://linux.oracle.com/errata/ELSA-2020-0575.html",
          "https://lists.debian.org/debian-lts-announce/2022/06/msg00025.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1712",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://www.openwall.com/lists/oss-security/2020/02/05/1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1712",
        "resource": "libudev1",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: use-after-free when asynchronous polkit queries are performed",
        "vulnerabilityID": "CVE-2020-1712"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.9,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:C",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "basic/unit-name.c in systemd prior to 246.15, 247.8, 248.5, and 249.1 has a Memory Allocation with an Excessive Size Value (involving strdupa and alloca for a pathname controlled by a local attacker) that results in an operating system crash.",
        "fixedVersion": "232-25+deb9u13",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html",
          "http://www.openwall.com/lists/oss-security/2021/08/04/2",
          "http://www.openwall.com/lists/oss-security/2021/08/17/3",
          "http://www.openwall.com/lists/oss-security/2021/09/07/3",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-33910.json",
          "https://access.redhat.com/security/cve/CVE-2021-33910",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-222547.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33910",
          "https://github.com/systemd/systemd-stable/commit/4a1c5f34bd3e1daed4490e9d97918e504d19733b",
          "https://github.com/systemd/systemd-stable/commit/764b74113e36ac5219a4b82a05f311b5a92136ce",
          "https://github.com/systemd/systemd-stable/commit/b00674347337b7531c92fdb65590ab253bb57538",
          "https://github.com/systemd/systemd-stable/commit/cfd14c65374027b34dbbc4f0551456c5dc2d1f61",
          "https://github.com/systemd/systemd/commit/b34a4f0e6729de292cb3b0c03c1d48f246ad896b",
          "https://github.com/systemd/systemd/pull/20256/commits/441e0115646d54f080e5c3bb0ba477c892861ab9",
          "https://linux.oracle.com/cve/CVE-2021-33910.html",
          "https://linux.oracle.com/errata/ELSA-2021-2717.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2LSDMHAKI4LGFOCSPXNVVSEWQFAVFWR7/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-33910",
          "https://security.gentoo.org/glsa/202107-48",
          "https://security.netapp.com/advisory/ntap-20211104-0008/",
          "https://ubuntu.com/security/notices/USN-5013-1",
          "https://ubuntu.com/security/notices/USN-5013-2",
          "https://www.debian.org/security/2021/dsa-4942",
          "https://www.openwall.com/lists/oss-security/2021/07/20/2",
          "https://www.qualys.com/2021/07/20/cve-2021-33910/denial-of-service-systemd.txt"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-33910",
        "resource": "libudev1",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: uncontrolled allocation on the stack in function unit_name_path_escape leads to crash",
        "vulnerabilityID": "CVE-2021-33910"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A flaw was found in systemd. An uncontrolled recursion in systemd-tmpfiles may lead to a denial of service at boot time when too many nested directories are created in /tmp.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-3997",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2024639",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997",
          "https://github.com/systemd/systemd/commit/5b1cf7a9be37e20133c0208005274ce4a5b5c6a1",
          "https://ubuntu.com/security/notices/USN-5226-1",
          "https://www.openwall.com/lists/oss-security/2022/01/10/2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3997",
        "resource": "libudev1",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: Uncontrolled recursion in systemd-tmpfiles when removing files",
        "vulnerabilityID": "CVE-2021-3997"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 3.3,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:N"
          },
          "redhat": {
            "V2Score": 3.3,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:N"
          }
        },
        "description": "systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725357",
          "http://www.openwall.com/lists/oss-security/2013/10/01/9",
          "https://access.redhat.com/security/cve/CVE-2013-4392",
          "https://bugzilla.redhat.com/show_bug.cgi?id=859060"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2013-4392",
        "resource": "libudev1",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: TOCTOU race condition when updating file permissions and SELinux security contexts",
        "vulnerabilityID": "CVE-2013-4392"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 10,
            "V2Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.2,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "systemd v233 and earlier fails to safely parse usernames starting with a numeric digit (e.g. \"0day\"), running the service in question with root privileges rather than the user intended.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://www.openwall.com/lists/oss-security/2017/07/02/1",
          "http://www.securityfocus.com/bid/99507",
          "http://www.securitytracker.com/id/1038839",
          "https://access.redhat.com/security/cve/CVE-2017-1000082",
          "https://github.com/systemd/systemd/issues/6237"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-1000082",
        "resource": "libudev1",
        "score": 7.2,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: fails to parse usernames that start with digits",
        "vulnerabilityID": "CVE-2017-1000082"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "systemd-tmpfiles in systemd before 237 attempts to support ownership/permission changes on hardlinked files even if the fs.protected_hardlinks sysctl is turned off, which allows local users to bypass intended access restrictions via vectors involving a hard link to a file for which the user lacks write access, as demonstrated by changing the ownership of the /etc/passwd file.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://lists.opensuse.org/opensuse-updates/2018-02/msg00109.html",
          "http://packetstormsecurity.com/files/146184/systemd-Local-Privilege-Escalation.html",
          "http://www.openwall.com/lists/oss-security/2018/01/29/3",
          "https://access.redhat.com/security/cve/CVE-2017-18078",
          "https://github.com/systemd/systemd/issues/7736",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2019/04/msg00022.html",
          "https://www.exploit-db.com/exploits/43935/",
          "https://www.openwall.com/lists/oss-security/2018/01/29/4"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-18078",
        "resource": "libudev1",
        "score": 6.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: Unsafe handling of hard links allowing privilege escalation",
        "vulnerabilityID": "CVE-2017-18078"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "It was discovered systemd does not correctly check the content of PIDFile files before using it to kill processes. When a service is run from an unprivileged user (e.g. User field set in the service file), a local attacker who is able to write to the PIDFile of the mentioned service may use this flaw to trick systemd into killing other services and/or privileged processes. Versions before v237 are vulnerable.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/errata/RHSA-2019:2091",
          "https://access.redhat.com/security/cve/CVE-2018-16888",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16888",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16888",
          "https://linux.oracle.com/cve/CVE-2018-16888.html",
          "https://linux.oracle.com/errata/ELSA-2019-2091.html",
          "https://lists.apache.org/thread.html/5960a34a524848cd722fd7ab7e2227eac10107b0f90d9d1e9c3caa74@%3Cuser.cassandra.apache.org%3E",
          "https://security.netapp.com/advisory/ntap-20190307-0007/",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://usn.ubuntu.com/4269-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-16888",
        "resource": "libudev1",
        "score": 4.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: kills privileged process if unprivileged PIDFile was tampered",
        "vulnerabilityID": "CVE-2018-16888"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "systemd-tmpfiles in systemd through 237 mishandles symlinks present in non-terminal path components, which allows local users to obtain ownership of arbitrary files via vectors involving creation of a directory and a file under that directory, and later replacing that directory with a symlink. This occurs even if the fs.protected_symlinks sysctl is turned on.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00062.html",
          "https://access.redhat.com/security/cve/CVE-2018-6954",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6954",
          "https://github.com/systemd/systemd/issues/7986",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://ubuntu.com/security/notices/USN-3816-1",
          "https://ubuntu.com/security/notices/USN-3816-2",
          "https://usn.ubuntu.com/3816-1/",
          "https://usn.ubuntu.com/3816-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6954",
        "resource": "libudev1",
        "score": 7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: Mishandled symlinks in systemd-tmpfiles allows local users to obtain ownership of arbitrary files",
        "vulnerabilityID": "CVE-2018-6954"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 2.4,
            "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 2.4,
            "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the udevadm trigger command, a memory leak may occur.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00014.html",
          "https://access.redhat.com/security/cve/CVE-2019-20386",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20386",
          "https://github.com/systemd/systemd/commit/b2774a3ae692113e1f47a336a6c09bac9cfb49ad",
          "https://linux.oracle.com/cve/CVE-2019-20386.html",
          "https://linux.oracle.com/errata/ELSA-2020-4553.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HZPCOMW5X6IZZXASCDD2CNW2DLF3YADC/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-20386",
          "https://security.netapp.com/advisory/ntap-20200210-0002/",
          "https://ubuntu.com/security/notices/USN-4269-1",
          "https://usn.ubuntu.com/4269-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-20386",
        "resource": "libudev1",
        "score": 2.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: memory leak in button_open() in login/logind-button.c when udev events are received",
        "vulnerabilityID": "CVE-2019-20386"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.9,
            "V2Vector": "AV:A/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H"
          }
        },
        "description": "An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "http://www.openwall.com/lists/oss-security/2021/08/04/2",
          "http://www.openwall.com/lists/oss-security/2021/08/17/3",
          "http://www.openwall.com/lists/oss-security/2021/09/07/3",
          "https://access.redhat.com/security/cve/CVE-2020-13529",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13529",
          "https://linux.oracle.com/cve/CVE-2020-13529.html",
          "https://linux.oracle.com/errata/ELSA-2021-4361.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/",
          "https://security.gentoo.org/glsa/202107-48",
          "https://security.netapp.com/advisory/ntap-20210625-0005/",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1142",
          "https://ubuntu.com/security/notices/USN-5013-1",
          "https://ubuntu.com/security/notices/USN-5013-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-13529",
        "resource": "libudev1",
        "score": 6.1,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: DHCP FORCERENEW authentication not implemented can cause a system running the DHCP client to have its network reconfigured",
        "vulnerabilityID": "CVE-2020-13529"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "systemd through v245 mishandles numerical usernames such as ones composed of decimal digits or 0x followed by hex digits, as demonstrated by use of root privileges when privileges of the 0x0 user account were intended. NOTE: this issue exists because of an incomplete fix for CVE-2017-1000082.",
        "fixedVersion": "",
        "installedVersion": "232-25+deb9u11",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-13776",
          "https://github.com/systemd/systemd/issues/15985",
          "https://linux.oracle.com/cve/CVE-2020-13776.html",
          "https://linux.oracle.com/errata/ELSA-2021-1611.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IYGLFEKG45EYBJ7TPQMLWROWPTZBEU63/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-13776",
          "https://security.netapp.com/advisory/ntap-20200611-0003/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-13776",
        "resource": "libudev1",
        "score": 6.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "systemd: Mishandles numerical usernames beginning with decimal digits or 0x followed by hexadecimal digits",
        "vulnerabilityID": "CVE-2020-13776"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/02/27/1",
          "http://www.openwall.com/lists/oss-security/2016/02/27/2",
          "https://access.redhat.com/security/cve/CVE-2016-2779",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2779",
        "resource": "libuuid1",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: runuser tty hijack via TIOCSTI ioctl",
        "vulnerabilityID": "CVE-2016-2779"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-37600",
          "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
          "https://github.com/karelzak/util-linux/issues/1395",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
          "https://security.netapp.com/advisory/ntap-20210902-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-37600",
        "resource": "libuuid1",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
        "vulnerabilityID": "CVE-2021-37600"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0563",
          "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
          "https://security.netapp.com/advisory/ntap-20220331-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0563",
        "resource": "libuuid1",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
        "vulnerabilityID": "CVE-2022-0563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in GetLE16().",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25009.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25010.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25012.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25013.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25014.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36330.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36331.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36332.json",
          "https://access.redhat.com/security/cve/CVE-2018-25009",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9100",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956917",
          "https://chromium.googlesource.com/webm/libwebp/+/95fd65070662e01cc9170c4444f5c0859a710097",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25009",
          "https://linux.oracle.com/cve/CVE-2018-25009.html",
          "https://linux.oracle.com/errata/ELSA-2021-4231.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-25009",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-25009",
        "resource": "libwebp6",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: out-of-bounds read in WebPMuxCreateInternal",
        "vulnerabilityID": "CVE-2018-25009"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in ApplyFilter().",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25009.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25010.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25012.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25013.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25014.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36330.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36331.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36332.json",
          "https://access.redhat.com/security/cve/CVE-2018-25010",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9105",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956918",
          "https://chromium.googlesource.com/webm/libwebp/+/1344a2e947c749d231141a295327e5b99b444d63",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25010",
          "https://linux.oracle.com/cve/CVE-2018-25010.html",
          "https://linux.oracle.com/errata/ELSA-2021-4231.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-25010",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-25010",
        "resource": "libwebp6",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: out-of-bounds read in ApplyFilter()",
        "vulnerabilityID": "CVE-2018-25010"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in PutLE16().",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25011.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36328.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36329.json",
          "https://access.redhat.com/security/cve/CVE-2018-25011",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9119",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956919",
          "https://chromium.googlesource.com/webm/libwebp/+/v1.0.1",
          "https://chromium.googlesource.com/webm/libwebp/+log/be738c6d396fa5a272c1b209be4379a7532debfe..29fb8562c60b5a919a75d904ff7366af423f8ab9?pretty=fuller\u0026n=10000",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25011",
          "https://linux.oracle.com/cve/CVE-2018-25011.html",
          "https://linux.oracle.com/errata/ELSA-2021-2354.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-25011",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-25011",
        "resource": "libwebp6",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: heap-based buffer overflow in PutLE16()",
        "vulnerabilityID": "CVE-2018-25011"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in GetLE24().",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25009.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25010.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25012.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25013.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25014.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36330.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36331.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36332.json",
          "https://access.redhat.com/security/cve/CVE-2018-25012",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9123",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956922",
          "https://chromium.googlesource.com/webm/libwebp/+/95fd65070662e01cc9170c4444f5c0859a710097",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25012",
          "https://linux.oracle.com/cve/CVE-2018-25012.html",
          "https://linux.oracle.com/errata/ELSA-2021-4231.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-25012",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-25012",
        "resource": "libwebp6",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: out-of-bounds read in WebPMuxCreateInternal()",
        "vulnerabilityID": "CVE-2018-25012"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in ShiftBytes().",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25009.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25010.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25012.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25013.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25014.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36330.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36331.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36332.json",
          "https://access.redhat.com/security/cve/CVE-2018-25013",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9417",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956926",
          "https://chromium.googlesource.com/webm/libwebp/+/907208f97ead639bd521cf355a2f203f462eade6",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25013",
          "https://linux.oracle.com/cve/CVE-2018-25013.html",
          "https://linux.oracle.com/errata/ELSA-2021-4231.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-25013",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-25013",
        "resource": "libwebp6",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: out-of-bounds read in ShiftBytes()",
        "vulnerabilityID": "CVE-2018-25013"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A use of uninitialized value was found in libwebp in versions before 1.0.1 in ReadSymbol().",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25009.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25010.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25012.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25013.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25014.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36330.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36331.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36332.json",
          "https://access.redhat.com/security/cve/CVE-2018-25014",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9496",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956927",
          "https://chromium.googlesource.com/webm/libwebp/+log/78ad57a36ad69a9c22874b182d49d64125c380f2..907208f97ead639bd52",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25014",
          "https://linux.oracle.com/cve/CVE-2018-25014.html",
          "https://linux.oracle.com/errata/ELSA-2021-4231.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-25014",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-25014",
        "resource": "libwebp6",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: use of uninitialized value in ReadSymbol()",
        "vulnerabilityID": "CVE-2018-25014"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A flaw was found in libwebp in versions before 1.0.1. A heap-based buffer overflow in function WebPDecodeRGBInto is possible due to an invalid check for buffer size. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "http://seclists.org/fulldisclosure/2021/Jul/54",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25011.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36328.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36329.json",
          "https://access.redhat.com/security/cve/CVE-2020-36328",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956829",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36328",
          "https://linux.oracle.com/cve/CVE-2020-36328.html",
          "https://linux.oracle.com/errata/ELSA-2021-2354.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00005.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00006.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-36328",
          "https://security.netapp.com/advisory/ntap-20211112-0001/",
          "https://support.apple.com/kb/HT212601",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2",
          "https://www.debian.org/security/2021/dsa-4930"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-36328",
        "resource": "libwebp6",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: heap-based buffer overflow in WebPDecode*Into functions",
        "vulnerabilityID": "CVE-2020-36328"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A flaw was found in libwebp in versions before 1.0.1. A use-after-free was found due to a thread being killed too early. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "http://seclists.org/fulldisclosure/2021/Jul/54",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25011.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36328.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36329.json",
          "https://access.redhat.com/security/cve/CVE-2020-36329",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956843",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36329",
          "https://linux.oracle.com/cve/CVE-2020-36329.html",
          "https://linux.oracle.com/errata/ELSA-2021-2354.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00005.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00006.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-36329",
          "https://security.netapp.com/advisory/ntap-20211112-0001/",
          "https://support.apple.com/kb/HT212601",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2",
          "https://www.debian.org/security/2021/dsa-4930"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-36329",
        "resource": "libwebp6",
        "score": 9.8,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: use-after-free in EmitFancyRGB() in dec/io_dec.c",
        "vulnerabilityID": "CVE-2020-36329"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function ChunkVerifyAndAssign. The highest threat from this vulnerability is to data confidentiality and to the service availability.",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "http://seclists.org/fulldisclosure/2021/Jul/54",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25009.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25010.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25012.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25013.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25014.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36330.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36331.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36332.json",
          "https://access.redhat.com/security/cve/CVE-2020-36330",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956853",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36330",
          "https://linux.oracle.com/cve/CVE-2020-36330.html",
          "https://linux.oracle.com/errata/ELSA-2021-4231.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00005.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00006.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-36330",
          "https://security.netapp.com/advisory/ntap-20211104-0004/",
          "https://support.apple.com/kb/HT212601",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2",
          "https://www.debian.org/security/2021/dsa-4930"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-36330",
        "resource": "libwebp6",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: out-of-bounds read in ChunkVerifyAndAssign() in mux/muxread.c",
        "vulnerabilityID": "CVE-2020-36330"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function ChunkAssignData. The highest threat from this vulnerability is to data confidentiality and to the service availability.",
        "fixedVersion": "0.5.2-1+deb9u1",
        "installedVersion": "0.5.2-1",
        "links": [
          "http://seclists.org/fulldisclosure/2021/Jul/54",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25009.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25010.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25012.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25013.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25014.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36330.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36331.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36332.json",
          "https://access.redhat.com/security/cve/CVE-2020-36331",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956856",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36331",
          "https://linux.oracle.com/cve/CVE-2020-36331.html",
          "https://linux.oracle.com/errata/ELSA-2021-4231.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00005.html",
          "https://lists.debian.org/debian-lts-announce/2021/06/msg00006.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-36331",
          "https://security.netapp.com/advisory/ntap-20211112-0001/",
          "https://support.apple.com/kb/HT212601",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://ubuntu.com/security/notices/USN-4971-2",
          "https://www.debian.org/security/2021/dsa-4930"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-36331",
        "resource": "libwebp6",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: out-of-bounds read in ChunkAssignData() in mux/muxinternal.c",
        "vulnerabilityID": "CVE-2020-36331"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A flaw was found in libwebp in versions before 1.0.1. When reading a file libwebp allocates an excessive amount of memory. The highest threat from this vulnerability is to the service availability.",
        "fixedVersion": "",
        "installedVersion": "0.5.2-1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25009.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25010.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25012.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25013.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25014.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36330.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36331.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-36332.json",
          "https://access.redhat.com/security/cve/CVE-2020-36332",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956868",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36332",
          "https://linux.oracle.com/cve/CVE-2020-36332.html",
          "https://linux.oracle.com/errata/ELSA-2021-4231.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-36332",
          "https://security.netapp.com/advisory/ntap-20211104-0004/",
          "https://ubuntu.com/security/notices/USN-4971-1",
          "https://www.debian.org/security/2021/dsa-4930"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-36332",
        "resource": "libwebp6",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: excessive memory allocation when reading a file",
        "vulnerabilityID": "CVE-2020-36332"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "Multiple integer overflows in libwebp allows attackers to have unspecified impact via unknown vectors.",
        "fixedVersion": "",
        "installedVersion": "0.5.2-1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/10/27/3",
          "http://www.securityfocus.com/bid/93928",
          "https://access.redhat.com/security/cve/CVE-2016-9085",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1389338",
          "https://chromium.googlesource.com/webm/libwebp/+/e2affacc35f1df6cc3b1a9fa0ceff5ce2d0cce83",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LG5Q42J7EJDKQKWTTHCO4YZMOMP74YPQ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PTR2ZW67TMT7KC24RBENIF25KWUJ7VPD/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SH6X3MWD5AHZC5JT4625PGFHAYLR7YW7/",
          "https://security.gentoo.org/glsa/201701-61"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-9085",
        "resource": "libwebp6",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libwebp: Several integer overflows",
        "vulnerabilityID": "CVE-2016-9085"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "LookupCol.c in X.Org X through X11R7.7 and libX11 before 1.7.1 might allow remote attackers to execute arbitrary code. The libX11 XLookupColor request (intended for server-side color lookup) contains a flaw allowing a client to send color-name requests with a name longer than the maximum size allowed by the protocol (and also longer than the maximum packet size for normal-sized packets). The user-controlled data exceeding the maximum size is then interpreted by the server as additional X protocol requests and executed, e.g., to disable X server authorization completely. For example, if the victim encounters malicious terminal control sequences for color codes, then the attacker may be able to take full control of the running graphical session.",
        "fixedVersion": "2:1.6.4-3+deb9u4",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "http://packetstormsecurity.com/files/162737/libX11-Insufficient-Length-Check-Injection.html",
          "http://seclists.org/fulldisclosure/2021/May/52",
          "http://www.openwall.com/lists/oss-security/2021/05/18/2",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-31535.json",
          "https://access.redhat.com/security/cve/CVE-2021-31535",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31535",
          "https://gitlab.freedesktop.org/xorg/lib/libx11/-/commit/8d2e02ae650f00c4a53deb625211a0527126c605",
          "https://linux.oracle.com/cve/CVE-2021-31535.html",
          "https://linux.oracle.com/errata/ELSA-2021-4326.html",
          "https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2021/05/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TEOT4RLB76RVPJQKGGTIKTBIOLHX2NR6/",
          "https://lists.freedesktop.org/archives/xorg/",
          "https://lists.x.org/archives/xorg-announce/2021-May/003088.html",
          "https://security.gentoo.org/glsa/202105-16",
          "https://security.netapp.com/advisory/ntap-20210813-0001/",
          "https://ubuntu.com/security/notices/USN-4966-1",
          "https://ubuntu.com/security/notices/USN-4966-2",
          "https://unparalleled.eu/blog/2021/20210518-using-xterm-to-navigate-the-huge-color-space/",
          "https://unparalleled.eu/publications/2021/advisory-unpar-2021-1.txt",
          "https://www.debian.org/security/2021/dsa-4920",
          "https://www.openwall.com/lists/oss-security/2021/05/18/2",
          "https://www.openwall.com/lists/oss-security/2021/05/18/3"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-31535",
        "resource": "libx11-6",
        "score": 8.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: missing request length checks",
        "vulnerabilityID": "CVE-2021-31535"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An integer overflow vulnerability leading to a double-free was found in libX11. This flaw allows a local privileged attacker to cause an application compiled with libX11 to crash, or in some cases, result in arbitrary code execution. The highest threat from this flaw is to confidentiality, integrity as well as system availability.",
        "fixedVersion": "2:1.6.4-3+deb9u3",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14344.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14345.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14346.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14347.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14360.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14361.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14362.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14363.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-25712.json",
          "https://access.redhat.com/security/cve/CVE-2020-14363",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-14363",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14363",
          "https://github.com/Ruia-ruia/Exploits/blob/master/DFX11details.txt",
          "https://github.com/Ruia-ruia/Exploits/blob/master/x11doublefree.sh",
          "https://linux.oracle.com/cve/CVE-2020-14363.html",
          "https://linux.oracle.com/errata/ELSA-2021-1804.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7AVXCQOSCAPKYYHFIJAZ6E2C7LJBTLXF/",
          "https://lists.x.org/archives/xorg-announce/2020-August/003056.html",
          "https://ubuntu.com/security/notices/USN-4487-1",
          "https://ubuntu.com/security/notices/USN-4487-2",
          "https://usn.ubuntu.com/4487-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-14363",
        "resource": "libx11-6",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: integer overflow leads to double free in locale handling",
        "vulnerabilityID": "CVE-2020-14363"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A vulnerability has been found in X.org libX11 and classified as problematic. This vulnerability affects the function _XimRegisterIMInstantiateCallback of the file modules/im/ximcp/imsClbk.c. The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211054 is the identifier assigned to this vulnerability.",
        "fixedVersion": "",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-3554",
          "https://cgit.freedesktop.org/xorg/lib/libX11/commit/?id=1d11822601fd24a396b354fa616b04ed3df8b4ef",
          "https://vuldb.com/?id.211054"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-3554",
        "resource": "libx11-6",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: memory leak in _XimRegisterIMInstantiateCallback() of modules/im/ximcp/imsClbk.c",
        "vulnerabilityID": "CVE-2022-3554"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A vulnerability was found in X.org libX11 and classified as problematic. This issue affects the function _XFreeX11XCBStructure of the file xcb_disp.c. The manipulation of the argument dpy leads to memory leak. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211055.",
        "fixedVersion": "",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-3555",
          "https://cgit.freedesktop.org/xorg/lib/libX11/commit/?id=8a368d808fec166b5fb3dfe6312aab22c7ee20af",
          "https://vuldb.com/?id.211055"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-3555",
        "resource": "libx11-6",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: memory leak in _XFreeX11XCBStructure() of xcb_disp.c",
        "vulnerabilityID": "CVE-2022-3555"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An integer overflow leading to a heap-buffer overflow was found in The X Input Method (XIM) client was implemented in libX11 before version 1.6.10. As per upstream this is security relevant when setuid programs call XIM client functions while running with elevated privileges. No such programs are shipped with Red Hat Enterprise Linux.",
        "fixedVersion": "2:1.6.4-3+deb9u2",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00014.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00015.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00024.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00031.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14344.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14345.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14346.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14347.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14360.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14361.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14362.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14363.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-25712.json",
          "https://access.redhat.com/security/cve/CVE-2020-14344",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-14344",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14344",
          "https://linux.oracle.com/cve/CVE-2020-14344.html",
          "https://linux.oracle.com/errata/ELSA-2021-1804.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4VDDSAYV7XGNRCXE7HCU23645MG74OFF/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7AVXCQOSCAPKYYHFIJAZ6E2C7LJBTLXF/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XY4H2SIEF2362AMNX5ZKWAELGU7LKFJB/",
          "https://lists.x.org/archives/xorg-announce/2020-July/003050.html",
          "https://security.gentoo.org/glsa/202008-18",
          "https://ubuntu.com/security/notices/USN-4487-1",
          "https://ubuntu.com/security/notices/USN-4487-2",
          "https://usn.ubuntu.com/4487-1/",
          "https://usn.ubuntu.com/4487-2/",
          "https://www.openwall.com/lists/oss-security/2020/07/31/1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-14344",
        "resource": "libx11-6",
        "score": 6.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: Heap overflow in the X input method client",
        "vulnerabilityID": "CVE-2020-14344"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "LookupCol.c in X.Org X through X11R7.7 and libX11 before 1.7.1 might allow remote attackers to execute arbitrary code. The libX11 XLookupColor request (intended for server-side color lookup) contains a flaw allowing a client to send color-name requests with a name longer than the maximum size allowed by the protocol (and also longer than the maximum packet size for normal-sized packets). The user-controlled data exceeding the maximum size is then interpreted by the server as additional X protocol requests and executed, e.g., to disable X server authorization completely. For example, if the victim encounters malicious terminal control sequences for color codes, then the attacker may be able to take full control of the running graphical session.",
        "fixedVersion": "2:1.6.4-3+deb9u4",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "http://packetstormsecurity.com/files/162737/libX11-Insufficient-Length-Check-Injection.html",
          "http://seclists.org/fulldisclosure/2021/May/52",
          "http://www.openwall.com/lists/oss-security/2021/05/18/2",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-31535.json",
          "https://access.redhat.com/security/cve/CVE-2021-31535",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31535",
          "https://gitlab.freedesktop.org/xorg/lib/libx11/-/commit/8d2e02ae650f00c4a53deb625211a0527126c605",
          "https://linux.oracle.com/cve/CVE-2021-31535.html",
          "https://linux.oracle.com/errata/ELSA-2021-4326.html",
          "https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2021/05/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TEOT4RLB76RVPJQKGGTIKTBIOLHX2NR6/",
          "https://lists.freedesktop.org/archives/xorg/",
          "https://lists.x.org/archives/xorg-announce/2021-May/003088.html",
          "https://security.gentoo.org/glsa/202105-16",
          "https://security.netapp.com/advisory/ntap-20210813-0001/",
          "https://ubuntu.com/security/notices/USN-4966-1",
          "https://ubuntu.com/security/notices/USN-4966-2",
          "https://unparalleled.eu/blog/2021/20210518-using-xterm-to-navigate-the-huge-color-space/",
          "https://unparalleled.eu/publications/2021/advisory-unpar-2021-1.txt",
          "https://www.debian.org/security/2021/dsa-4920",
          "https://www.openwall.com/lists/oss-security/2021/05/18/2",
          "https://www.openwall.com/lists/oss-security/2021/05/18/3"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-31535",
        "resource": "libx11-data",
        "score": 8.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: missing request length checks",
        "vulnerabilityID": "CVE-2021-31535"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An integer overflow vulnerability leading to a double-free was found in libX11. This flaw allows a local privileged attacker to cause an application compiled with libX11 to crash, or in some cases, result in arbitrary code execution. The highest threat from this flaw is to confidentiality, integrity as well as system availability.",
        "fixedVersion": "2:1.6.4-3+deb9u3",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14344.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14345.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14346.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14347.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14360.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14361.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14362.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14363.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-25712.json",
          "https://access.redhat.com/security/cve/CVE-2020-14363",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-14363",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14363",
          "https://github.com/Ruia-ruia/Exploits/blob/master/DFX11details.txt",
          "https://github.com/Ruia-ruia/Exploits/blob/master/x11doublefree.sh",
          "https://linux.oracle.com/cve/CVE-2020-14363.html",
          "https://linux.oracle.com/errata/ELSA-2021-1804.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7AVXCQOSCAPKYYHFIJAZ6E2C7LJBTLXF/",
          "https://lists.x.org/archives/xorg-announce/2020-August/003056.html",
          "https://ubuntu.com/security/notices/USN-4487-1",
          "https://ubuntu.com/security/notices/USN-4487-2",
          "https://usn.ubuntu.com/4487-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-14363",
        "resource": "libx11-data",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: integer overflow leads to double free in locale handling",
        "vulnerabilityID": "CVE-2020-14363"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A vulnerability has been found in X.org libX11 and classified as problematic. This vulnerability affects the function _XimRegisterIMInstantiateCallback of the file modules/im/ximcp/imsClbk.c. The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211054 is the identifier assigned to this vulnerability.",
        "fixedVersion": "",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-3554",
          "https://cgit.freedesktop.org/xorg/lib/libX11/commit/?id=1d11822601fd24a396b354fa616b04ed3df8b4ef",
          "https://vuldb.com/?id.211054"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-3554",
        "resource": "libx11-data",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: memory leak in _XimRegisterIMInstantiateCallback() of modules/im/ximcp/imsClbk.c",
        "vulnerabilityID": "CVE-2022-3554"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A vulnerability was found in X.org libX11 and classified as problematic. This issue affects the function _XFreeX11XCBStructure of the file xcb_disp.c. The manipulation of the argument dpy leads to memory leak. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211055.",
        "fixedVersion": "",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-3555",
          "https://cgit.freedesktop.org/xorg/lib/libX11/commit/?id=8a368d808fec166b5fb3dfe6312aab22c7ee20af",
          "https://vuldb.com/?id.211055"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-3555",
        "resource": "libx11-data",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: memory leak in _XFreeX11XCBStructure() of xcb_disp.c",
        "vulnerabilityID": "CVE-2022-3555"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An integer overflow leading to a heap-buffer overflow was found in The X Input Method (XIM) client was implemented in libX11 before version 1.6.10. As per upstream this is security relevant when setuid programs call XIM client functions while running with elevated privileges. No such programs are shipped with Red Hat Enterprise Linux.",
        "fixedVersion": "2:1.6.4-3+deb9u2",
        "installedVersion": "2:1.6.4-3+deb9u1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00014.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00015.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00024.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00031.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14344.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14345.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14346.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14347.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14360.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14361.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14362.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-14363.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-25712.json",
          "https://access.redhat.com/security/cve/CVE-2020-14344",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-14344",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14344",
          "https://linux.oracle.com/cve/CVE-2020-14344.html",
          "https://linux.oracle.com/errata/ELSA-2021-1804.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4VDDSAYV7XGNRCXE7HCU23645MG74OFF/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7AVXCQOSCAPKYYHFIJAZ6E2C7LJBTLXF/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XY4H2SIEF2362AMNX5ZKWAELGU7LKFJB/",
          "https://lists.x.org/archives/xorg-announce/2020-July/003050.html",
          "https://security.gentoo.org/glsa/202008-18",
          "https://ubuntu.com/security/notices/USN-4487-1",
          "https://ubuntu.com/security/notices/USN-4487-2",
          "https://usn.ubuntu.com/4487-1/",
          "https://usn.ubuntu.com/4487-2/",
          "https://www.openwall.com/lists/oss-security/2020/07/31/1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-14344",
        "resource": "libx11-data",
        "score": 6.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libX11: Heap overflow in the X input method client",
        "vulnerabilityID": "CVE-2020-14344"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          }
        },
        "description": "The htmlParseTryOrFinish function in HTMLparser.c in libxml2 2.9.4 allows attackers to cause a denial of service (buffer over-read) or information disclosure.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u3",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2017-8872",
          "https://bugzilla.gnome.org/show_bug.cgi?id=775200",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8872",
          "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
          "https://ubuntu.com/security/notices/USN-4991-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-8872",
        "resource": "libxml2",
        "score": 5.4,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Out-of-bounds read in htmlParseTryOrFinish",
        "vulnerabilityID": "CVE-2017-8872"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "parser.c in libxml2 before 2.9.5 does not prevent infinite recursion in parameter entities.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u6",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://xmlsoft.org/news.html",
          "https://access.redhat.com/security/cve/CVE-2017-16932",
          "https://blog.clamav.net/2018/07/clamav-01001-has-been-released.html",
          "https://bugzilla.gnome.org/show_bug.cgi?id=759579",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16932",
          "https://github.com/GNOME/libxml2/commit/899a5d9f0ed13b8e32449a08a361e0de127dd961",
          "https://github.com/sparklemotion/nokogiri/issues/1714",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2017/11/msg00041.html",
          "https://lists.debian.org/debian-lts-announce/2022/04/msg00004.html",
          "https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-16932.html",
          "https://ubuntu.com/security/notices/USN-3504-1",
          "https://ubuntu.com/security/notices/USN-3504-2",
          "https://ubuntu.com/security/notices/USN-3739-1",
          "https://usn.ubuntu.com/3739-1/",
          "https://usn.ubuntu.com/usn/usn-3504-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-16932",
        "resource": "libxml2",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Infinite recursion in parameter entities",
        "vulnerabilityID": "CVE-2017-16932"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An integer overflow in xmlmemory.c in libxml2 before 2.9.5, as used in Google Chrome prior to 62.0.3202.62 and other products, allowed a remote attacker to potentially exploit heap corruption via a crafted XML file.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u6",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://bugzilla.gnome.org/show_bug.cgi?id=783026",
          "http://www.securityfocus.com/bid/101482",
          "https://access.redhat.com/errata/RHSA-2017:2997",
          "https://access.redhat.com/security/cve/CVE-2017-5130",
          "https://chromereleases.googleblog.com/2017/10/stable-channel-update-for-desktop.html",
          "https://crbug.com/722079",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5130",
          "https://git.gnome.org/browse/libxml2/commit/?id=897dffbae322b46b83f99a607d527058a72c51ed",
          "https://lists.debian.org/debian-lts-announce/2017/11/msg00034.html",
          "https://lists.debian.org/debian-lts-announce/2022/04/msg00004.html",
          "https://security.gentoo.org/glsa/201710-24",
          "https://security.netapp.com/advisory/ntap-20190719-0001/",
          "https://www.oracle.com/security-alerts/cpuapr2020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-5130",
        "resource": "libxml2",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "chromium-browser: heap overflow in libxml2",
        "vulnerabilityID": "CVE-2017-5130"
      },
      {
        "cvss": {
          "ghsa": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A NULL pointer dereference vulnerability exists in the xpath.c:xmlXPathCompOpEval() function of libxml2 through 2.9.8 when parsing an invalid XPath expression in the XPATH_OP_AND or XPATH_OP_OR case. Applications processing untrusted XSL format inputs with the use of the libxml2 library may be vulnerable to a denial of service attack due to a crash of the application.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u3",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "https://access.redhat.com/errata/RHSA-2019:1543",
          "https://access.redhat.com/security/cve/CVE-2018-14404",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=901817",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1595985",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14404",
          "https://github.com/advisories/GHSA-6qvp-r6r3-9p7h",
          "https://github.com/sparklemotion/nokogiri/issues/1785",
          "https://gitlab.gnome.org/GNOME/libxml2/commit/2240fbf5912054af025fb6e01e26375100275e74",
          "https://gitlab.gnome.org/GNOME/libxml2/commit/a436374994c47b12d5de1b8b1d191a098fa23594",
          "https://gitlab.gnome.org/GNOME/libxml2/issues/10",
          "https://groups.google.com/forum/#!msg/ruby-security-ann/uVrmO2HjqQw/Fw3ocLI0BQAJ",
          "https://linux.oracle.com/cve/CVE-2018-14404.html",
          "https://linux.oracle.com/errata/ELSA-2020-1827.html",
          "https://lists.debian.org/debian-lts-announce/2018/09/msg00035.html",
          "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-14404",
          "https://security.netapp.com/advisory/ntap-20190719-0002/",
          "https://ubuntu.com/security/notices/USN-3739-1",
          "https://ubuntu.com/security/notices/USN-3739-2",
          "https://usn.ubuntu.com/3739-1/",
          "https://usn.ubuntu.com/3739-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-14404",
        "resource": "libxml2",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: NULL pointer dereference in xmlXPathCompOpEval() function in xpath.c",
        "vulnerabilityID": "CVE-2018-14404"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "xmlParseBalancedChunkMemoryRecover in parser.c in libxml2 before 2.9.10 has a memory leak related to newDoc-\u003eoldNs.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u3",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00047.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00005.html",
          "https://access.redhat.com/security/cve/CVE-2019-19956",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-292794.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19956",
          "https://gitlab.gnome.org/GNOME/libxml2/commit/5a02583c7e683896d84878bd90641d8d9b0d0549",
          "https://linux.oracle.com/cve/CVE-2019-19956.html",
          "https://linux.oracle.com/errata/ELSA-2020-4479.html",
          "https://lists.debian.org/debian-lts-announce/2019/12/msg00032.html",
          "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5R55ZR52RMBX24TQTWHCIWKJVRV6YAWI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JDPF3AAVKUAKDYFMFKSIQSVVS3EEFPQH/",
          "https://security.netapp.com/advisory/ntap-20200114-0002/",
          "https://ubuntu.com/security/notices/USN-4274-1",
          "https://us-cert.cisa.gov/ics/advisories/icsa-21-103-08",
          "https://usn.ubuntu.com/4274-1/",
          "https://www.oracle.com/security-alerts/cpujul2020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-19956",
        "resource": "libxml2",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: memory leak in xmlParseBalancedChunkMemoryRecover in parser.c",
        "vulnerabilityID": "CVE-2019-19956"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "xmlSchemaPreRun in xmlschemas.c in libxml2 2.9.10 allows an xmlSchemaValidateStream memory leak.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u3",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00047.html",
          "https://access.redhat.com/security/cve/CVE-2019-20388",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20388",
          "https://gitlab.gnome.org/GNOME/libxml2/merge_requests/68",
          "https://linux.oracle.com/cve/CVE-2019-20388.html",
          "https://linux.oracle.com/errata/ELSA-2020-4479.html",
          "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/545SPOI3ZPPNPX4TFRIVE4JVRTJRKULL/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5R55ZR52RMBX24TQTWHCIWKJVRV6YAWI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JDPF3AAVKUAKDYFMFKSIQSVVS3EEFPQH/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-20388",
          "https://security.gentoo.org/glsa/202010-04",
          "https://security.netapp.com/advisory/ntap-20200702-0005/",
          "https://ubuntu.com/security/notices/USN-4991-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujul2020.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-20388",
        "resource": "libxml2",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: memory leak in xmlSchemaPreRun in xmlschemas.c",
        "vulnerabilityID": "CVE-2019-20388"
      },
      {
        "cvss": {
          "ghsa": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file situation.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u3",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00047.html",
          "https://access.redhat.com/security/cve/CVE-2020-7595",
          "https://cert-portal.siemens.com/productcert/pdf/ssa-292794.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7595",
          "https://github.com/advisories/GHSA-7553-jr98-vx47",
          "https://github.com/sparklemotion/nokogiri/issues/1992",
          "https://gitlab.gnome.org/GNOME/libxml2/commit/0e1a49c89076",
          "https://linux.oracle.com/cve/CVE-2020-7595.html",
          "https://linux.oracle.com/errata/ELSA-2020-4479.html",
          "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/545SPOI3ZPPNPX4TFRIVE4JVRTJRKULL/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5R55ZR52RMBX24TQTWHCIWKJVRV6YAWI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JDPF3AAVKUAKDYFMFKSIQSVVS3EEFPQH/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-7595",
          "https://security.gentoo.org/glsa/202010-04",
          "https://security.netapp.com/advisory/ntap-20200702-0005/",
          "https://ubuntu.com/security/notices/USN-4274-1",
          "https://us-cert.cisa.gov/ics/advisories/icsa-21-103-08",
          "https://usn.ubuntu.com/4274-1/",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujul2020.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-7595",
        "resource": "libxml2",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: infinite loop in xmlStringLenDecodeEntities in some end-of-file situations",
        "vulnerabilityID": "CVE-2020-7595"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to confidentiality, integrity, and availability.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u4",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3516.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3517.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3518.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3537.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3541.json",
          "https://access.redhat.com/security/cve/CVE-2021-3516",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1954225",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3516",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/1358d157d0bd83be1dfe356a69213df9fac0b539",
          "https://gitlab.gnome.org/GNOME/libxml2/-/issues/230",
          "https://linux.oracle.com/cve/CVE-2021-3516.html",
          "https://linux.oracle.com/errata/ELSA-2021-2569.html",
          "https://lists.debian.org/debian-lts-announce/2021/05/msg00008.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BZOMV5J4PMZAORVT64BKLV6YIZAFDGX6/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QVM4UJ3376I6ZVOYMHBNX4GY3NIV52WV/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3516",
          "https://security.gentoo.org/glsa/202107-05",
          "https://security.netapp.com/advisory/ntap-20210716-0005/",
          "https://ubuntu.com/security/notices/USN-4991-1",
          "https://www.oracle.com/security-alerts/cpujan2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3516",
        "resource": "libxml2",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Use-after-free in xmlEncodeEntitiesInternal() in entities.c",
        "vulnerabilityID": "CVE-2021-3516"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"
          },
          "redhat": {
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "There is a flaw in the xml entity encoding functionality of libxml2 in versions before 2.9.11. An attacker who is able to supply a crafted file to be processed by an application linked with the affected functionality of libxml2 could trigger an out-of-bounds read. The most likely impact of this flaw is to application availability, with some potential impact to confidentiality and integrity if an attacker is able to use memory information to further exploit the application.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u4",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3516.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3517.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3518.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3537.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3541.json",
          "https://access.redhat.com/security/cve/CVE-2021-3517",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1954232",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3517",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2",
          "https://gitlab.gnome.org/GNOME/libxml2/-/issues/235",
          "https://linux.oracle.com/cve/CVE-2021-3517.html",
          "https://linux.oracle.com/errata/ELSA-2021-2569.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2021/05/msg00008.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BZOMV5J4PMZAORVT64BKLV6YIZAFDGX6/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QVM4UJ3376I6ZVOYMHBNX4GY3NIV52WV/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3517",
          "https://security.gentoo.org/glsa/202107-05",
          "https://security.netapp.com/advisory/ntap-20210625-0002/",
          "https://security.netapp.com/advisory/ntap-20211022-0004/",
          "https://ubuntu.com/security/notices/USN-4991-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3517",
        "resource": "libxml2",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Heap-based buffer overflow in xmlEncodeEntitiesInternal() in entities.c",
        "vulnerabilityID": "CVE-2021-3517"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "There's a flaw in libxml2 in versions before 2.9.11. An attacker who is able to submit a crafted file to be processed by an application linked with libxml2 could trigger a use-after-free. The greatest impact from this flaw is to confidentiality, integrity, and availability.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u4",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://seclists.org/fulldisclosure/2021/Jul/54",
          "http://seclists.org/fulldisclosure/2021/Jul/55",
          "http://seclists.org/fulldisclosure/2021/Jul/58",
          "http://seclists.org/fulldisclosure/2021/Jul/59",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3516.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3517.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3518.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3537.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3541.json",
          "https://access.redhat.com/security/cve/CVE-2021-3518",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1954242",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3518",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/1098c30a040e72a4654968547f415be4e4c40fe7",
          "https://gitlab.gnome.org/GNOME/libxml2/-/issues/237",
          "https://linux.oracle.com/cve/CVE-2021-3518.html",
          "https://linux.oracle.com/errata/ELSA-2021-2569.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2021/05/msg00008.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BZOMV5J4PMZAORVT64BKLV6YIZAFDGX6/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QVM4UJ3376I6ZVOYMHBNX4GY3NIV52WV/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3518",
          "https://security.gentoo.org/glsa/202107-05",
          "https://security.netapp.com/advisory/ntap-20210625-0002/",
          "https://support.apple.com/kb/HT212601",
          "https://support.apple.com/kb/HT212602",
          "https://support.apple.com/kb/HT212604",
          "https://support.apple.com/kb/HT212605",
          "https://ubuntu.com/security/notices/USN-4991-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3518",
        "resource": "libxml2",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Use-after-free in xmlXIncludeDoProcess() in xinclude.c",
        "vulnerabilityID": "CVE-2021-3518"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "valid.c in libxml2 before 2.9.13 has a use-after-free of ID and IDREF attributes.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u6",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://seclists.org/fulldisclosure/2022/May/33",
          "http://seclists.org/fulldisclosure/2022/May/34",
          "http://seclists.org/fulldisclosure/2022/May/35",
          "http://seclists.org/fulldisclosure/2022/May/36",
          "http://seclists.org/fulldisclosure/2022/May/37",
          "http://seclists.org/fulldisclosure/2022/May/38",
          "https://access.redhat.com/security/cve/CVE-2022-23308",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23308",
          "https://github.com/GNOME/libxml2/commit/652dd12a858989b14eed4e84e453059cd3ba340e",
          "https://gitlab.gnome.org/GNOME/libxml2/-/blob/v2.9.13/NEWS",
          "https://linux.oracle.com/cve/CVE-2022-23308.html",
          "https://linux.oracle.com/errata/ELSA-2022-0899.html",
          "https://lists.debian.org/debian-lts-announce/2022/04/msg00004.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LA3MWWAYZADWJ5F6JOUBX65UZAMQB7RF/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23308",
          "https://security.gentoo.org/glsa/202210-03",
          "https://security.netapp.com/advisory/ntap-20220331-0008/",
          "https://support.apple.com/kb/HT213253",
          "https://support.apple.com/kb/HT213254",
          "https://support.apple.com/kb/HT213255",
          "https://support.apple.com/kb/HT213256",
          "https://support.apple.com/kb/HT213257",
          "https://support.apple.com/kb/HT213258",
          "https://ubuntu.com/security/notices/USN-5324-1",
          "https://ubuntu.com/security/notices/USN-5422-1",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23308",
        "resource": "libxml2",
        "score": 8.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Use-after-free of ID and IDREF attributes",
        "vulnerabilityID": "CVE-2022-23308"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
          }
        },
        "description": "Possible cross-site scripting vulnerability in libxml after commit 960f0e2.",
        "fixedVersion": "",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2016-3709",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3709",
          "https://mail.gnome.org/archives/xml/2018-January/msg00010.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2016-3709",
          "https://ubuntu.com/security/notices/USN-5548-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-3709",
        "resource": "libxml2",
        "score": 6.1,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Incorrect server side include parsing can lead to XSS",
        "vulnerabilityID": "CVE-2016-3709"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 6.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:L"
          }
        },
        "description": "libxml2 2.9.4 and earlier, as used in XMLSec 1.2.23 and earlier and other products, does not offer a flag directly indicating that the current document may be read but other files may not be opened, which makes it easier for remote attackers to conduct XML External Entity (XXE) attacks via a crafted document.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u6",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://www.securityfocus.com/bid/94347",
          "https://access.redhat.com/security/cve/CVE-2016-9318",
          "https://bugzilla.gnome.org/show_bug.cgi?id=772726",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9318",
          "https://github.com/lsh123/xmlsec/issues/43",
          "https://lists.debian.org/debian-lts-announce/2022/04/msg00004.html",
          "https://security.gentoo.org/glsa/201711-01",
          "https://ubuntu.com/security/notices/USN-3739-1",
          "https://ubuntu.com/security/notices/USN-3739-2",
          "https://usn.ubuntu.com/3739-1/",
          "https://usn.ubuntu.com/3739-2/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-9318",
        "resource": "libxml2",
        "score": 6.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: XML External Entity vulnerability",
        "vulnerabilityID": "CVE-2016-9318"
      },
      {
        "cvss": {
          "ghsa": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The xz_head function in xzlib.c in libxml2 before 2.9.6 allows remote attackers to cause a denial of service (memory consumption) via a crafted LZMA file, because the decoder functionality does not restrict memory usage to what is required for a legitimate file.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u3",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2017-18258",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18258",
          "https://git.gnome.org/browse/libxml2/commit/?id=e2a9122b8dde53d320750451e9907a7dcb2ca8bb",
          "https://github.com/advisories/GHSA-882p-jqgm-f45g",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10284",
          "https://linux.oracle.com/cve/CVE-2017-18258.html",
          "https://linux.oracle.com/errata/ELSA-2020-1190.html",
          "https://lists.debian.org/debian-lts-announce/2018/09/msg00035.html",
          "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2017-18258",
          "https://security.netapp.com/advisory/ntap-20190719-0001/",
          "https://ubuntu.com/security/notices/USN-3739-1",
          "https://usn.ubuntu.com/3739-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-18258",
        "resource": "libxml2",
        "score": 3.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Unrestricted memory usage in xz_head() function in xzlib.c",
        "vulnerabilityID": "CVE-2017-18258"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.6,
            "V2Vector": "AV:N/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** libxml2 2.9.4, when used in recover mode, allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted XML document.  NOTE: The maintainer states \"I would disagree of a CVE with the Recover parsing option which should only be used for manual recovery at least for XML parser.\"",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u6",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/11/05/3",
          "http://www.openwall.com/lists/oss-security/2017/02/13/1",
          "http://www.securityfocus.com/bid/96188",
          "https://access.redhat.com/security/cve/CVE-2017-5969",
          "https://bugzilla.gnome.org/show_bug.cgi?id=778519",
          "https://lists.debian.org/debian-lts-announce/2022/04/msg00004.html",
          "https://security.gentoo.org/glsa/201711-01"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-5969",
        "resource": "libxml2",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Null pointer dereference in xmlSaveDoc implementation",
        "vulnerabilityID": "CVE-2017-5969"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "libxml2 2.9.8, if --with-lzma is used, allows remote attackers to cause a denial of service (infinite loop) via a crafted XML file that triggers LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint, a different vulnerability than CVE-2015-8035 and CVE-2018-9251.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u3",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://www.securityfocus.com/bid/105198",
          "https://access.redhat.com/security/cve/CVE-2018-14567",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14567",
          "https://gitlab.gnome.org/GNOME/libxml2/commit/2240fbf5912054af025fb6e01e26375100275e74",
          "https://linux.oracle.com/cve/CVE-2018-14567.html",
          "https://linux.oracle.com/errata/ELSA-2020-1190.html",
          "https://lists.debian.org/debian-lts-announce/2018/09/msg00035.html",
          "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
          "https://ubuntu.com/security/notices/USN-3739-1",
          "https://usn.ubuntu.com/3739-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-14567",
        "resource": "libxml2",
        "score": 4.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Infinite loop caused by incorrect error detection during LZMA decompression",
        "vulnerabilityID": "CVE-2018-14567"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "GNOME project libxml2 v2.9.10 has a global buffer over-read vulnerability in xmlEncodeEntitiesInternal at libxml2/entities.c. The issue has been fixed in commit 50f06b3e.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u3",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00036.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00061.html",
          "https://access.redhat.com/security/cve/CVE-2020-24977",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24977",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/50f06b3efb638efb0abd95dc62dca05ae67882c2",
          "https://gitlab.gnome.org/GNOME/libxml2/-/issues/178",
          "https://linux.oracle.com/cve/CVE-2020-24977.html",
          "https://linux.oracle.com/errata/ELSA-2021-1597.html",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2NQ5GTDYOVH26PBCPYXXMGW5ZZXWMGZC/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5KTUAGDLEHTH6HU66HBFAFTSQ3OKRAN3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/674LQPJO2P2XTBTREFR5LOZMBTZ4PZAY/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7KQXOHIE3MNY3VQXEN7LDQUJNIHOVHAW/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ENEHQIBMSI6TZVS35Y6I4FCTYUQDLJVP/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/H3IQ7OQXBKWD3YP7HO6KCNOMLE5ZO2IR/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/J3ICASXZI2UQYFJAOQWHSTNWGED3VXOE/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JCHXIWR5DHYO3RSO7RAHEC6VJKXD2EH2/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/O7MEWYKIKMV2SKMGH4IDWVU3ZGJXBCPQ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RIQAMBA2IJUTQG5VOP5LZVIZRNCKXHEQ/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-24977",
          "https://security.gentoo.org/glsa/202107-05",
          "https://security.netapp.com/advisory/ntap-20200924-0001/",
          "https://ubuntu.com/security/notices/USN-4991-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-24977",
        "resource": "libxml2",
        "score": 6.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Buffer overflow vulnerability in xmlEncodeEntitiesInternal() in entities.c",
        "vulnerabilityID": "CVE-2020-24977"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A vulnerability found in libxml2 in versions before 2.9.11 shows that it did not propagate errors while parsing XML mixed content, causing a NULL dereference. If an untrusted XML document was parsed in recovery mode and post-validated, the flaw could be used to crash the application. The highest threat from this vulnerability is to system availability.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u4",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3516.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3517.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3518.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3537.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3541.json",
          "https://access.redhat.com/security/cve/CVE-2021-3537",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1956522",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3537",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/babe75030c7f64a37826bb3342317134568bef61",
          "https://gitlab.gnome.org/GNOME/libxml2/-/issues/243",
          "https://gitlab.gnome.org/GNOME/libxml2/-/issues/244",
          "https://gitlab.gnome.org/GNOME/libxml2/-/issues/245",
          "https://linux.oracle.com/cve/CVE-2021-3537.html",
          "https://linux.oracle.com/errata/ELSA-2021-2569.html",
          "https://lists.debian.org/debian-lts-announce/2021/05/msg00008.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BZOMV5J4PMZAORVT64BKLV6YIZAFDGX6/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QVM4UJ3376I6ZVOYMHBNX4GY3NIV52WV/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3537",
          "https://security.gentoo.org/glsa/202107-05",
          "https://security.netapp.com/advisory/ntap-20210625-0002/",
          "https://ubuntu.com/security/notices/USN-4991-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujul2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3537",
        "resource": "libxml2",
        "score": 7.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: NULL pointer dereference when post-validating mixed content parsed in recovery mode",
        "vulnerabilityID": "CVE-2021-3537"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4,
            "V2Vector": "AV:N/AC:L/Au:S/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "A flaw was found in libxml2. Exponential entity expansion attack its possible bypassing all existing protection mechanisms and leading to denial of service.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u5",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3516.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3517.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3518.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3537.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3541.json",
          "https://access.redhat.com/security/cve/CVE-2021-3541",
          "https://blog.hartwork.org/posts/cve-2021-3541-parameter-laughs-fixed-in-libxml2-2-9-11/",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1950515",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3541",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/8598060bacada41a0eb09d95c97744ff4e428f8e",
          "https://gitlab.gnome.org/GNOME/libxml2/-/issues/228 (currently private)",
          "https://linux.oracle.com/cve/CVE-2021-3541.html",
          "https://linux.oracle.com/errata/ELSA-2021-2569.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3541",
          "https://security.netapp.com/advisory/ntap-20210805-0007/",
          "https://ubuntu.com/security/notices/USN-4991-1",
          "https://www.oracle.com/security-alerts/cpujan2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3541",
        "resource": "libxml2",
        "score": 6.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: Exponential entity expansion attack bypasses all existing protection mechanisms",
        "vulnerabilityID": "CVE-2021-3541"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"
          }
        },
        "description": "In libxml2 before 2.9.14, several buffer handling functions in buf.c (xmlBuf*) and tree.c (xmlBuffer*) don't check for integer overflows. This can result in out-of-bounds memory writes. Exploitation requires a victim to open a crafted, multi-gigabyte XML file. Other software using libxml2's buffer functions, for example libxslt through 1.1.35, is affected as well.",
        "fixedVersion": "2.9.4+dfsg1-2.2+deb9u7",
        "installedVersion": "2.9.4+dfsg1-2.2+deb9u2",
        "links": [
          "http://packetstormsecurity.com/files/167345/libxml2-xmlBufAdd-Heap-Buffer-Overflow.html",
          "https://access.redhat.com/security/cve/CVE-2022-29824",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29824",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/2554a2408e09f13652049e5ffb0d26196b02ebab",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/2554a2408e09f13652049e5ffb0d26196b02ebab (v2.9.14)",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/6c283d83eccd940bcde15634ac8c7f100e3caefd",
          "https://gitlab.gnome.org/GNOME/libxml2/-/commit/6c283d83eccd940bcde15634ac8c7f100e3caefd (master)",
          "https://gitlab.gnome.org/GNOME/libxml2/-/tags/v2.9.14",
          "https://gitlab.gnome.org/GNOME/libxslt/-/tags",
          "https://linux.oracle.com/cve/CVE-2022-29824.html",
          "https://linux.oracle.com/errata/ELSA-2022-5317.html",
          "https://lists.debian.org/debian-lts-announce/2022/05/msg00023.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FZOBT5Y6Y2QLDDX2HZGMV7MJMWGXORKK/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/P3NVZVWFRBXBI3AKZZWUWY6INQQPQVSF/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/P5363EDV5VHZ5C77ODA43RYDCPMA7ARM/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-29824",
          "https://security.gentoo.org/glsa/202210-03",
          "https://security.netapp.com/advisory/ntap-20220715-0006/",
          "https://ubuntu.com/security/notices/USN-5422-1",
          "https://www.debian.org/security/2022/dsa-5142",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-29824",
        "resource": "libxml2",
        "score": 7.4,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxml2: integer overflows in xmlBuf and xmlBuffer lead to out-of-bounds write",
        "vulnerabilityID": "CVE-2022-29824"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L"
          }
        },
        "description": "libxslt through 1.1.33 allows bypass of a protection mechanism because callers of xsltCheckRead and xsltCheckWrite permit access even upon receiving a -1 error code. xsltCheckRead can return -1 for a crafted URL that is not actually invalid and is subsequently loaded.",
        "fixedVersion": "1.1.29-2.1+deb9u1",
        "installedVersion": "1.1.29-2.1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00048.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00052.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00053.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00025.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00001.html",
          "http://www.openwall.com/lists/oss-security/2019/04/22/1",
          "http://www.openwall.com/lists/oss-security/2019/04/23/5",
          "https://access.redhat.com/security/cve/CVE-2019-11068",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11068",
          "https://github.com/sparklemotion/nokogiri/issues/1892",
          "https://gitlab.gnome.org/GNOME/libxslt/commit/e03553605b45c88f0b4b2980adfbbb8f6fca2fd6",
          "https://groups.google.com/forum/#!msg/ruby-security-ann/_y80o1zZlOs/k4SDX6hoAAAJ",
          "https://linux.oracle.com/cve/CVE-2019-11068.html",
          "https://linux.oracle.com/errata/ELSA-2020-4464.html",
          "https://lists.debian.org/debian-lts-announce/2019/04/msg00016.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/36TEYN37XCCKN2XUMRTBBW67BPNMSW4K/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GCOAX2IHUMKCM3ILHTMGLHCDSBTLP2JU/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SK4YNISS22MJY22YX5I6V2U63QZAUEHA/",
          "https://security.netapp.com/advisory/ntap-20191017-0001/",
          "https://ubuntu.com/security/notices/USN-3947-1",
          "https://ubuntu.com/security/notices/USN-3947-2",
          "https://usn.ubuntu.com/3947-1/",
          "https://usn.ubuntu.com/3947-2/",
          "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-11068",
        "resource": "libxslt1.1",
        "score": 6.3,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxslt: xsltCheckRead and xsltCheckWrite routines security bypass by crafted URL",
        "vulnerabilityID": "CVE-2019-11068"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.1,
            "V2Vector": "AV:N/AC:H/Au:N/C:P/I:P/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In xsltCopyText in transform.c in libxslt 1.1.33, a pointer variable isn't reset under certain circumstances. If the relevant memory area happened to be freed and reused in a certain way, a bounds check could fail and memory outside a buffer could be written to, or uninitialized data could be disclosed.",
        "fixedVersion": "1.1.29-2.1+deb9u2",
        "installedVersion": "1.1.29-2.1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00010.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00015.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00025.html",
          "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00062.html",
          "http://www.openwall.com/lists/oss-security/2019/11/17/2",
          "https://access.redhat.com/errata/RHSA-2020:0514",
          "https://access.redhat.com/security/cve/CVE-2019-18197",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15746",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15768",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15914",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18197",
          "https://gitlab.gnome.org/GNOME/libxslt/commit/2232473733b7313d67de8836ea3b29eec6e8e285",
          "https://linux.oracle.com/cve/CVE-2019-18197.html",
          "https://linux.oracle.com/errata/ELSA-2020-4464.html",
          "https://lists.debian.org/debian-lts-announce/2019/10/msg00037.html",
          "https://security.netapp.com/advisory/ntap-20191031-0004/",
          "https://security.netapp.com/advisory/ntap-20200416-0004/",
          "https://ubuntu.com/security/notices/USN-4164-1",
          "https://usn.ubuntu.com/4164-1/",
          "https://www.oracle.com/security-alerts/cpuapr2020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-18197",
        "resource": "libxslt1.1",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxslt: use after free in xsltCopyText in transform.c could lead to information disclosure",
        "vulnerabilityID": "CVE-2019-18197"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
          }
        },
        "description": "Type confusion in xsltNumberFormatGetMultipleLevel prior to libxslt 1.1.33 could allow attackers to potentially exploit heap corruption via crafted XML data.",
        "fixedVersion": "",
        "installedVersion": "1.1.29-2.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-5815",
          "https://bugs.chromium.org/p/chromium/issues/detail?id=930663",
          "https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_23.html",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5815",
          "https://gitlab.gnome.org/GNOME/libxslt/commit/08b62c25871b38d5d573515ca8a065b4b8f64f6b",
          "https://lists.debian.org/debian-devel/2022/07/msg00287.html",
          "https://lists.debian.org/debian-lts-announce/2022/09/msg00010.html",
          "https://ubuntu.com/security/notices/USN-5575-1",
          "https://ubuntu.com/security/notices/USN-5575-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-5815",
        "resource": "libxslt1.1",
        "score": 6.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "chromium-browser: Heap buffer overflow in Blink",
        "vulnerabilityID": "CVE-2019-5815"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "Use after free in Blink XSLT in Google Chrome prior to 91.0.4472.164 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.",
        "fixedVersion": "",
        "installedVersion": "1.1.29-2.1",
        "links": [
          "https://chromereleases.googleblog.com/2021/07/stable-channel-update-for-desktop.html",
          "https://crbug.com/1219209",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30560",
          "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-fq42-c5rg-92c2",
          "https://lists.debian.org/debian-devel/2022/07/msg00287.html",
          "https://lists.debian.org/debian-lts-announce/2022/09/msg00010.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-30560",
          "https://ubuntu.com/security/notices/USN-5575-1",
          "https://ubuntu.com/security/notices/USN-5575-2",
          "https://www.debian.org/security/2022/dsa-5216"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-30560",
        "resource": "libxslt1.1",
        "score": 8.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "Use after free in Blink XSLT in Google Chrome prior to 91.0.4472.164 a ...",
        "vulnerabilityID": "CVE-2021-30560"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 4,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
          }
        },
        "description": "In libxslt 1.1.29 and earlier, the EXSLT math.random function was not initialized with a random seed during startup, which could cause usage of this function to produce predictable outputs.",
        "fixedVersion": "",
        "installedVersion": "1.1.29-2.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2015-9019",
          "https://bugzilla.gnome.org/show_bug.cgi?id=758400",
          "https://bugzilla.suse.com/show_bug.cgi?id=934119"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2015-9019",
        "resource": "libxslt1.1",
        "score": 4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxslt: math.random() in xslt uses unseeded randomness",
        "vulnerabilityID": "CVE-2015-9019"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "In numbers.c in libxslt 1.1.33, an xsl:number with certain format strings could lead to a uninitialized read in xsltNumberFormatInsertNumbers. This could allow an attacker to discern whether a byte on the stack contains the characters A, a, I, i, or 0, or any other character.",
        "fixedVersion": "1.1.29-2.1+deb9u1",
        "installedVersion": "1.1.29-2.1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00062.html",
          "http://www.openwall.com/lists/oss-security/2019/11/17/2",
          "https://access.redhat.com/security/cve/CVE-2019-13117",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=14471",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13117",
          "https://github.com/sparklemotion/nokogiri/issues/1943",
          "https://gitlab.gnome.org/GNOME/libxslt/commit/2232473733b7313d67de8836ea3b29eec6e8e285",
          "https://gitlab.gnome.org/GNOME/libxslt/commit/6ce8de69330783977dd14f6569419489875fb71b",
          "https://gitlab.gnome.org/GNOME/libxslt/commit/c5eb6cf3aba0af048596106ed839b4ae17ecbcb1",
          "https://groups.google.com/d/msg/ruby-security-ann/-Wq4aouIA3Q/yc76ZHemBgAJ",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2019/07/msg00020.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IOYJKXPQCUNBMMQJWYXOR6QRUJZHEDRZ/",
          "https://oss-fuzz.com/testcase-detail/5631739747106816",
          "https://security.netapp.com/advisory/ntap-20190806-0004/",
          "https://security.netapp.com/advisory/ntap-20200122-0003/",
          "https://ubuntu.com/security/notices/USN-4164-1",
          "https://usn.ubuntu.com/4164-1/",
          "https://www.oracle.com/security-alerts/cpujan2020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-13117",
        "resource": "libxslt1.1",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxslt: an xsl number with certain format strings could lead to a uninitialized read in xsltNumberFormatInsertNumbers",
        "vulnerabilityID": "CVE-2019-13117"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 4,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "In numbers.c in libxslt 1.1.33, a type holding grouping characters of an xsl:number instruction was too narrow and an invalid character/length combination could be passed to xsltNumberFormatDecimal, leading to a read of uninitialized stack data.",
        "fixedVersion": "1.1.29-2.1+deb9u1",
        "installedVersion": "1.1.29-2.1",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00062.html",
          "http://seclists.org/fulldisclosure/2019/Aug/11",
          "http://seclists.org/fulldisclosure/2019/Aug/13",
          "http://seclists.org/fulldisclosure/2019/Aug/14",
          "http://seclists.org/fulldisclosure/2019/Aug/15",
          "http://seclists.org/fulldisclosure/2019/Jul/22",
          "http://seclists.org/fulldisclosure/2019/Jul/23",
          "http://seclists.org/fulldisclosure/2019/Jul/24",
          "http://seclists.org/fulldisclosure/2019/Jul/26",
          "http://seclists.org/fulldisclosure/2019/Jul/31",
          "http://seclists.org/fulldisclosure/2019/Jul/37",
          "http://seclists.org/fulldisclosure/2019/Jul/38",
          "http://www.openwall.com/lists/oss-security/2019/11/17/2",
          "https://access.redhat.com/security/cve/CVE-2019-13118",
          "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15069",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13118",
          "https://gitlab.gnome.org/GNOME/libxslt/commit/6ce8de69330783977dd14f6569419489875fb71b",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2019/07/msg00020.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IOYJKXPQCUNBMMQJWYXOR6QRUJZHEDRZ/",
          "https://oss-fuzz.com/testcase-detail/5197371471822848",
          "https://seclists.org/bugtraq/2019/Aug/21",
          "https://seclists.org/bugtraq/2019/Aug/22",
          "https://seclists.org/bugtraq/2019/Aug/23",
          "https://seclists.org/bugtraq/2019/Aug/25",
          "https://seclists.org/bugtraq/2019/Jul/35",
          "https://seclists.org/bugtraq/2019/Jul/36",
          "https://seclists.org/bugtraq/2019/Jul/37",
          "https://seclists.org/bugtraq/2019/Jul/40",
          "https://seclists.org/bugtraq/2019/Jul/41",
          "https://seclists.org/bugtraq/2019/Jul/42",
          "https://security.netapp.com/advisory/ntap-20190806-0004/",
          "https://security.netapp.com/advisory/ntap-20200122-0003/",
          "https://support.apple.com/kb/HT210346",
          "https://support.apple.com/kb/HT210348",
          "https://support.apple.com/kb/HT210351",
          "https://support.apple.com/kb/HT210353",
          "https://support.apple.com/kb/HT210356",
          "https://support.apple.com/kb/HT210357",
          "https://support.apple.com/kb/HT210358",
          "https://ubuntu.com/security/notices/USN-4164-1",
          "https://usn.ubuntu.com/4164-1/",
          "https://www.oracle.com/security-alerts/cpujan2020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-13118",
        "resource": "libxslt1.1",
        "score": 4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "libxslt: read of uninitialized stack data due to too narrow xsl:number instruction and an invalid character",
        "vulnerabilityID": "CVE-2019-13118"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "In shadow before 4.5, the newusers tool could be made to manipulate internal data structures in ways unintended by the authors. Malformed input may lead to crashes (with a buffer overflow or other memory corruption) or other unspecified behaviors. This crosses a privilege boundary in, for example, certain web-hosting environments in which a Control Panel allows an unprivileged user account to create subaccounts.",
        "fixedVersion": "1:4.4-4.1+deb9u1",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2017-12424",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=756630",
          "https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1266675",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12424",
          "https://github.com/shadow-maint/shadow/commit/954e3d2e7113e9ac06632aee3c69b8d818cc8952",
          "https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html",
          "https://security.gentoo.org/glsa/201710-16",
          "https://ubuntu.com/security/notices/USN-5254-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-12424",
        "resource": "login",
        "score": 4.5,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "shadow-utils: Buffer overflow via newusers tool",
        "vulnerabilityID": "CVE-2017-12424"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "The Debian shadow package before 1:4.5-1 for Shadow incorrectly lists pts/0 and pts/1 as physical terminals in /etc/securetty. This allows local users to login as password-less users even if they are connected by non-physical means such as SSH (hence bypassing PAM's nullok_secure configuration). This notably affects environments such as virtual machines automatically generated with a default blank root password, allowing all local users to escalate privileges.",
        "fixedVersion": "1:4.4-4.1+deb9u1",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877374",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=914957",
          "https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-20002",
        "resource": "login",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "The Debian shadow package before 1:4.5-1 for Shadow incorrectly lists  ...",
        "vulnerabilityID": "CVE-2017-20002"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.9,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:N/A:N"
          }
        },
        "description": "initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.",
        "fixedVersion": "",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "http://secunia.com/advisories/27215",
          "http://www.securityfocus.com/archive/1/482129/100/100/threaded",
          "http://www.securityfocus.com/archive/1/482857/100/0/threaded",
          "http://www.securityfocus.com/bid/26048",
          "http://www.vupen.com/english/advisories/2007/3474",
          "https://issues.rpath.com/browse/RPL-1825"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2007-5686",
        "resource": "login",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "initscripts in rPath Linux 1 sets insecure permissions for the /var/lo ...",
        "vulnerabilityID": "CVE-2007-5686"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 3.3,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:P",
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N"
          },
          "redhat": {
            "V2Score": 3.7,
            "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
            "V3Score": 4.4,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N"
          }
        },
        "description": "shadow: TOCTOU (time-of-check time-of-use) race condition when copying and removing directory trees",
        "fixedVersion": "",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2013-4235",
          "https://access.redhat.com/security/cve/cve-2013-4235",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4235",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4235",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://security-tracker.debian.org/tracker/CVE-2013-4235"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2013-4235",
        "resource": "login",
        "score": 4.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "shadow-utils: TOCTOU race conditions by copying and removing directory trees",
        "vulnerabilityID": "CVE-2013-4235"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 4.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
          }
        },
        "description": "An issue was discovered in shadow 4.5. newgidmap (in shadow-utils) is setuid and allows an unprivileged user to be placed in a user namespace where setgroups(2) is permitted. This allows an attacker to remove themselves from a supplementary group, which may allow access to certain filesystem paths if the administrator has used \"group blacklisting\" (e.g., chmod g-rwx) to restrict access to paths. This flaw effectively reverts a security feature in the kernel (in particular, the /proc/self/setgroups knob) to prevent this sort of privilege escalation.",
        "fixedVersion": "",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-7169",
          "https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1729357",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7169",
          "https://github.com/shadow-maint/shadow/pull/97",
          "https://security.gentoo.org/glsa/201805-09",
          "https://ubuntu.com/security/notices/USN-5254-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-7169",
        "resource": "login",
        "score": 4.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "shadow-utils: newgidmap allows unprivileged user to drop supplementary groups potentially allowing privilege escalation",
        "vulnerabilityID": "CVE-2018-7169"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "shadow 4.8, in certain circumstances affecting at least Gentoo, Arch Linux, and Void Linux, allows local users to obtain root access because setuid programs are misconfigured. Specifically, this affects shadow 4.8 when compiled using --with-libpam but without explicitly passing --disable-account-tools-setuid, and without a PAM configuration suitable for use with setuid account management tools. This combination leads to account management tools (groupadd, groupdel, groupmod, useradd, userdel, usermod) that can easily be used by unprivileged local users to escalate privileges to root in multiple ways. This issue became much more relevant in approximately December 2019 when an unrelated bug was fixed (i.e., the chmod calls to suidusbins were fixed in the upstream Makefile which is now included in the release version 4.8).",
        "fixedVersion": "",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-19882",
          "https://bugs.archlinux.org/task/64836",
          "https://bugs.gentoo.org/702252",
          "https://github.com/shadow-maint/shadow/commit/edf7547ad5aa650be868cf2dac58944773c12d75",
          "https://github.com/shadow-maint/shadow/pull/199",
          "https://github.com/void-linux/void-packages/pull/17580",
          "https://security.gentoo.org/glsa/202008-09"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-19882",
        "resource": "login",
        "score": 7.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "shadow-utils: local users can obtain root access because setuid programs are misconfigured",
        "vulnerabilityID": "CVE-2019-19882"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/02/27/1",
          "http://www.openwall.com/lists/oss-security/2016/02/27/2",
          "https://access.redhat.com/security/cve/CVE-2016-2779",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2779",
        "resource": "mount",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: runuser tty hijack via TIOCSTI ioctl",
        "vulnerabilityID": "CVE-2016-2779"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-37600",
          "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
          "https://github.com/karelzak/util-linux/issues/1395",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
          "https://security.netapp.com/advisory/ntap-20210902-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-37600",
        "resource": "mount",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
        "vulnerabilityID": "CVE-2021-37600"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0563",
          "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
          "https://security.netapp.com/advisory/ntap-20220331-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0563",
        "resource": "mount",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
        "vulnerabilityID": "CVE-2022-0563"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "An integer overflow in the implementation of the posix_memalign in memalign functions in the GNU C Library (aka glibc or libc6) 2.26 and earlier could cause these functions to return a pointer to a heap area that is too small, potentially leading to heap corruption.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://bugs.debian.org/878159",
          "http://www.securityfocus.com/bid/102912",
          "https://access.redhat.com/errata/RHBA-2019:0327",
          "https://access.redhat.com/errata/RHSA-2018:3092",
          "https://access.redhat.com/security/cve/CVE-2018-6485",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485",
          "https://linux.oracle.com/cve/CVE-2018-6485.html",
          "https://linux.oracle.com/errata/ELSA-2018-3092.html",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22343",
          "https://ubuntu.com/security/notices/USN-4218-1",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4218-1/",
          "https://usn.ubuntu.com/4416-1/",
          "https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6485",
        "resource": "multiarch-support",
        "score": 5.3,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Integer overflow in posix_memalign in memalign functions",
        "vulnerabilityID": "CVE-2018-6485"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "The malloc implementation in the GNU C Library (aka glibc or libc6), from version 2.24 to 2.26 on powerpc, and only in version 2.26 on i386, did not properly handle malloc calls with arguments close to SIZE_MAX and could return a pointer to a heap region that is smaller than requested, eventually leading to heap corruption.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-6551",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22774",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-6551",
        "resource": "multiarch-support",
        "score": 5.3,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: integer overflow in malloc functions",
        "vulnerabilityID": "CVE-2018-6551"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 6.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, proceed_next_node in posix/regexec.c has a heap-based buffer over-read via an attempted case-insensitive regular-expression match.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/107160",
          "https://access.redhat.com/security/cve/CVE-2019-9169",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142",
          "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10278",
          "https://linux.oracle.com/cve/CVE-2019-9169.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-9169",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24114",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9",
          "https://support.f5.com/csp/article/K54823184",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-9169",
        "resource": "multiarch-support",
        "score": 6.5,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: regular-expression match via proceed_next_node in posix/regexec.c leads to heap-based buffer over-read",
        "vulnerabilityID": "CVE-2019-9169"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The mq_notify function in the GNU C Library (aka glibc) versions 2.32 and 2.33 has a use-after-free. It may use the notification thread attributes object (passed through its struct sigevent parameter) after it has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified other impact.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-33574",
          "https://linux.oracle.com/cve/CVE-2021-33574.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-33574",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210629-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27896",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-33574",
        "resource": "multiarch-support",
        "score": 5.9,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: mq_notify does not handle separately allocated thread attributes",
        "vulnerabilityID": "CVE-2021-33574"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 9.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
          }
        },
        "description": "The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in a denial of service or disclosure of information. This occurs because atoi was used but strtoul should have been used to ensure correct calculations.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json",
          "https://access.redhat.com/security/cve/CVE-2021-35942",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942",
          "https://linux.oracle.com/cve/CVE-2021-35942.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-35942",
          "https://security.gentoo.org/glsa/202208-24",
          "https://security.netapp.com/advisory/ntap-20210827-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28011",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c",
          "https://sourceware.org/glibc/wiki/Security%20Exceptions",
          "https://ubuntu.com/security/notices/USN-5310-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-35942",
        "resource": "multiarch-support",
        "score": 9.1,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Arbitrary read in wordexp()",
        "vulnerabilityID": "CVE-2021-35942"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "The deprecated compatibility function svcunix_create in the sunrpc module of the GNU C Library (aka glibc) through 2.34 copies its path argument on the stack without validating its length, which may result in a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a stack protector enabled) arbitrary code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-23218",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218",
          "https://linux.oracle.com/cve/CVE-2022-23218.html",
          "https://linux.oracle.com/errata/ELSA-2022-9421.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23218",
          "https://security.gentoo.org/glsa/202208-24",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28768",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23218",
        "resource": "multiarch-support",
        "score": 7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Stack-based buffer overflow in svcunix_create via long pathnames",
        "vulnerabilityID": "CVE-2022-23218"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "The deprecated compatibility function clnt_create in the sunrpc module of the GNU C Library (aka glibc) through 2.34 copies its hostname argument on the stack without validating its length, which may result in a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a stack protector enabled) arbitrary code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-23219",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219",
          "https://linux.oracle.com/cve/CVE-2022-23219.html",
          "https://linux.oracle.com/errata/ELSA-2022-9421.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-23219",
          "https://security.gentoo.org/glsa/202208-24",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22542",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-23219",
        "resource": "multiarch-support",
        "score": 7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Stack-based buffer overflow in sunrpc clnt_create via a long pathname",
        "vulnerabilityID": "CVE-2022-23219"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272",
          "https://access.redhat.com/security/cve/CVE-2009-5155",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=11053",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672",
          "https://support.f5.com/csp/article/K64119434",
          "https://support.f5.com/csp/article/K64119434?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/notices/USN-4954-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2009-5155",
        "resource": "multiarch-support",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: parse_reg_exp in posix/regcomp.c misparses alternatives leading to denial of service or trigger incorrect result",
        "vulnerabilityID": "CVE-2009-5155"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "In glibc 2.26 and earlier there is confusion in the usage of getcwd() by realpath() which can be used to write before the destination buffer leading to a buffer underflow and potential code execution.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://seclists.org/oss-sec/2018/q1/38",
          "http://www.openwall.com/lists/oss-security/2018/01/11/5",
          "http://www.securityfocus.com/bid/102525",
          "http://www.securitytracker.com/id/1040162",
          "https://access.redhat.com/errata/RHSA-2018:0805",
          "https://access.redhat.com/security/cve/CVE-2018-1000001",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001",
          "https://linux.oracle.com/cve/CVE-2018-1000001.html",
          "https://linux.oracle.com/errata/ELSA-2018-0805.html",
          "https://lists.samba.org/archive/rsync/2018-February/031478.html",
          "https://security.netapp.com/advisory/ntap-20190404-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=18203",
          "https://ubuntu.com/security/notices/USN-3534-1",
          "https://ubuntu.com/security/notices/USN-3536-1",
          "https://usn.ubuntu.com/3534-1/",
          "https://usn.ubuntu.com/3536-1/",
          "https://www.exploit-db.com/exploits/43775/",
          "https://www.exploit-db.com/exploits/44889/",
          "https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-1000001",
        "resource": "multiarch-support",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: realpath() buffer underflow when getcwd() returns relative path allows privilege escalation",
        "vulnerabilityID": "CVE-2018-1000001"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:C",
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the frame address, resulting in a denial of service or potential code execution. The highest threat from this vulnerability is to system availability.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-1751",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751",
          "https://linux.oracle.com/cve/CVE-2020-1751.html",
          "https://linux.oracle.com/errata/ELSA-2020-4444.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1751",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20200430-0002/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25423",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1751",
        "resource": "multiarch-support",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: array overflow in backtrace functions for powerpc",
        "vulnerabilityID": "CVE-2020-1751"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 3.7,
            "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A use-after-free vulnerability introduced in glibc upstream version 2.14 was found in the way the tilde expansion was carried out. Directory paths containing an initial tilde followed by a valid username were affected by this issue. A local attacker could exploit this flaw by creating a specially crafted path that, when processed by the glob function, would potentially lead to arbitrary code execution. This was fixed in version 2.32.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-1752",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752",
          "https://linux.oracle.com/cve/CVE-2020-1752.html",
          "https://linux.oracle.com/errata/ELSA-2020-4444.html",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-1752",
          "https://security.gentoo.org/glsa/202101-20",
          "https://security.netapp.com/advisory/ntap-20200511-0005/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25414",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-1752",
        "resource": "multiarch-support",
        "score": 7,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: use-after-free in glob() function when expanding ~user",
        "vulnerabilityID": "CVE-2020-1752"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid input sequences in the ISO-2022-JP-3 encoding, fails an assertion in the code path and aborts the program, potentially resulting in a denial of service.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.openwall.com/lists/oss-security/2021/01/28/2",
          "https://access.redhat.com/security/cve/CVE-2021-3326",
          "https://bugs.chromium.org/p/project-zero/issues/detail?id=2146",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326",
          "https://linux.oracle.com/cve/CVE-2021-3326.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3326",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210304-0007/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27256",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888",
          "https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3326",
        "resource": "multiarch-support",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters",
        "vulnerabilityID": "CVE-2021-3326"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "A flaw was found in glibc. An off-by-one buffer overflow and underflow in getcwd() may lead to memory corruption when the size of the buffer is exactly 1. A local attacker who can control the input buffer and size passed to getcwd() in a setuid program could use this flaw to potentially execute arbitrary code and escalate their privileges on the system.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3999.json",
          "https://access.redhat.com/security/cve/CVE-2021-3999",
          "https://bugzilla.redhat.com/show_bug.cgi?id=2024637",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999",
          "https://linux.oracle.com/cve/CVE-2021-3999.html",
          "https://linux.oracle.com/errata/ELSA-2022-9234.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3999",
          "https://security-tracker.debian.org/tracker/CVE-2021-3999",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=28769",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=23e0e8f5f1fb5ed150253d986ecccdc90c2dcd5e",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://ubuntu.com/security/notices/USN-5310-2",
          "https://www.openwall.com/lists/oss-security/2022/01/24/4"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3999",
        "resource": "multiarch-support",
        "score": 7.4,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Off-by-one buffer overflow/underflow in getcwd()",
        "vulnerabilityID": "CVE-2021-3999"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          },
          "redhat": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.28, the getaddrinfo function would successfully parse a string that contained an IPv4 address followed by whitespace and arbitrary characters, which could lead applications to incorrectly assume that it had parsed a valid string, without the possibility of embedded HTTP headers or other potentially dangerous substrings.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html",
          "http://www.securityfocus.com/bid/106672",
          "https://access.redhat.com/errata/RHSA-2019:2118",
          "https://access.redhat.com/errata/RHSA-2019:3513",
          "https://access.redhat.com/security/cve/CVE-2016-10739",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1347549",
          "https://linux.oracle.com/cve/CVE-2016-10739.html",
          "https://linux.oracle.com/errata/ELSA-2019-3513.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2016-10739",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=20018"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-10739",
        "resource": "multiarch-support",
        "score": 5.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: getaddrinfo should reject IP addresses with trailing characters",
        "vulnerabilityID": "CVE-2016-10739"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"
          },
          "redhat": {
            "V3Score": 3,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N"
          }
        },
        "description": "The DNS stub resolver in the GNU C Library (aka glibc or libc6) before version 2.26, when EDNS support is enabled, will solicit large UDP responses from name servers, potentially simplifying off-path DNS spoofing attacks due to IP fragmentation.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/100598",
          "https://access.redhat.com/errata/RHSA-2018:0805",
          "https://access.redhat.com/security/cve/CVE-2017-12132",
          "https://arxiv.org/pdf/1205.4011.pdf",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12132",
          "https://linux.oracle.com/cve/CVE-2017-12132.html",
          "https://linux.oracle.com/errata/ELSA-2018-0805.html",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=21361"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-12132",
        "resource": "multiarch-support",
        "score": 3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Fragmentation attacks possible when EDNS0 is enabled",
        "vulnerabilityID": "CVE-2017-12132"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.1,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:C",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv feature in the GNU C Library (aka glibc or libc6) through 2.32, when processing invalid multi-byte input sequences in the EUC-KR encoding, may have a buffer over-read.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-25013",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013",
          "https://linux.oracle.com/cve/CVE-2019-25013.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E",
          "https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-25013",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210205-0004/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24973",
          "https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-25013",
        "resource": "multiarch-support",
        "score": 4.8,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: buffer over-read in iconv when processing invalid multi-byte input sequences in the EUC-KR encoding",
        "vulnerabilityID": "CVE-2019-25013"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H"
          }
        },
        "description": "The GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to sysdeps/ieee754/ldbl-96/e_rem_pio2l.c.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html",
          "https://access.redhat.com/security/cve/CVE-2020-10029",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029",
          "https://linux.oracle.com/cve/CVE-2020-10029.html",
          "https://linux.oracle.com/errata/ELSA-2021-0348.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-10029",
          "https://security.gentoo.org/glsa/202006-04",
          "https://security.netapp.com/advisory/ntap-20200327-0003/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25487",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-10029",
        "resource": "multiarch-support",
        "score": 5.7,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: stack corruption from crafted input in cosl, sinl, sincosl, and tanl functions",
        "vulnerabilityID": "CVE-2020-10029"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid multi-byte input sequences in IBM1364, IBM1371, IBM1388, IBM1390, and IBM1399 encodings, fails to advance the input state, which could lead to an infinite loop in applications, resulting in a denial of service, a different vulnerability from CVE-2016-10228.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-27618",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618",
          "https://linux.oracle.com/cve/CVE-2020-27618.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-27618",
          "https://security.gentoo.org/glsa/202107-07",
          "https://security.netapp.com/advisory/ntap-20210401-0006/",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=26224",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-27618",
        "resource": "multiarch-support",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: iconv when processing invalid multi-byte input sequences fails to advance the input state, which could result in an infinite loop",
        "vulnerabilityID": "CVE-2020-27618"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4,
            "V2Vector": "AV:N/AC:L/Au:S/C:N/I:N/A:P"
          },
          "redhat": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P"
          }
        },
        "description": "The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://cxib.net/stuff/glob-0day.c",
          "http://securityreason.com/achievement_securityalert/89",
          "http://securityreason.com/exploitalert/9223",
          "https://access.redhat.com/security/cve/CVE-2010-4756",
          "https://bugzilla.redhat.com/show_bug.cgi?id=681681",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-4756",
          "https://nvd.nist.gov/vuln/detail/CVE-2010-4756"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2010-4756",
        "resource": "multiarch-support",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions",
        "vulnerabilityID": "CVE-2010-4756"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P"
          }
        },
        "description": "The pop_fail_stack function in the GNU C Library (aka glibc or libc6) allows context-dependent attackers to cause a denial of service (assertion failure and application crash) via vectors related to extended regular expression processing.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.openwall.com/lists/oss-security/2017/02/14/9",
          "http://www.securityfocus.com/bid/76916",
          "https://access.redhat.com/security/cve/CVE-2015-8985",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=779392",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8985",
          "https://security.gentoo.org/glsa/201908-06",
          "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=bc680b336971305cb39896b30d72dc7101b62242"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2015-8985",
        "resource": "multiarch-support",
        "score": 5.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: potential denial of service in pop_fail_stack()",
        "vulnerabilityID": "CVE-2015-8985"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.9,
            "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The iconv program in the GNU C Library (aka glibc or libc6) 2.31 and earlier, when invoked with multiple suffixes in the destination encoding (TRANSLATE or IGNORE) along with the -c option, enters an infinite loop when processing invalid multi-byte input sequences, leading to a denial of service.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://openwall.com/lists/oss-security/2017/03/01/10",
          "http://www.securityfocus.com/bid/96525",
          "https://access.redhat.com/security/cve/CVE-2016-10228",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10228",
          "https://linux.oracle.com/cve/CVE-2016-10228.html",
          "https://linux.oracle.com/errata/ELSA-2021-9344.html",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://security.gentoo.org/glsa/202101-20",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=26224",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.oracle.com/security-alerts/cpuapr2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-10228",
        "resource": "multiarch-support",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: iconv program can hang when invoked with the -c option",
        "vulnerabilityID": "CVE-2016-10228"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\\227|)(\\\\1\\\\1|t1|\\\\\\2537)+' in grep.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/107160",
          "https://access.redhat.com/security/cve/CVE-2018-20796",
          "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34141",
          "https://lists.gnu.org/archive/html/bug-gnulib/2019-01/msg00108.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-20796",
          "https://security.netapp.com/advisory/ntap-20190315-0002/",
          "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp;utm_medium=RSS"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-20796",
        "resource": "multiarch-support",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
        "vulnerabilityID": "CVE-2018-20796"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-1010022",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010022",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22850",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22850#c3",
          "https://ubuntu.com/security/CVE-2019-1010022"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010022",
        "resource": "multiarch-support",
        "score": 9.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: stack guard protection bypass",
        "vulnerabilityID": "CVE-2019-1010022"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/109167",
          "https://access.redhat.com/security/cve/CVE-2019-1010023",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010023",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22851",
          "https://support.f5.com/csp/article/K11932200?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010023"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010023",
        "resource": "multiarch-support",
        "score": 7.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: running ldd on malicious ELF leads to code execution because of wrong size computation",
        "vulnerabilityID": "CVE-2019-1010023"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/109162",
          "https://access.redhat.com/security/cve/CVE-2019-1010024",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010024",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22852",
          "https://support.f5.com/csp/article/K06046097",
          "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010024"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010024",
        "resource": "multiarch-support",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: ASLR bypass using cache of thread stack and heap",
        "vulnerabilityID": "CVE-2019-1010024"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 2.9,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "** DISPUTED ** GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is \"ASLR bypass itself is not a vulnerability.\"",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-1010025",
          "https://security-tracker.debian.org/tracker/CVE-2019-1010025",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=22853",
          "https://support.f5.com/csp/article/K06046097",
          "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp;utm_medium=RSS",
          "https://ubuntu.com/security/CVE-2019-1010025"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-1010025",
        "resource": "multiarch-support",
        "score": 2.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: information disclosure of heap addresses of pthread_created thread",
        "vulnerabilityID": "CVE-2019-1010025"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 2.9,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
          }
        },
        "description": "On the x86-64 architecture, the GNU C Library (aka glibc) before 2.31 fails to ignore the LD_PREFER_MAP_32BIT_EXEC environment variable during program execution after a security transition, allowing local attackers to restrict the possible mapping addresses for loaded libraries and thus bypass ASLR for a setuid program.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-19126",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19126",
          "https://linux.oracle.com/cve/CVE-2019-19126.html",
          "https://linux.oracle.com/errata/ELSA-2020-3861.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4FQ5LC6JOYSOYFPRUZ4S45KL6IP3RPPZ/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZFJ5E7NWOL6ROE5QVICHKIOUGCPFJVUH/",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-19126",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25204",
          "https://sourceware.org/ml/libc-alpha/2019-11/msg00649.html",
          "https://ubuntu.com/security/notices/USN-4416-1",
          "https://usn.ubuntu.com/4416-1/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-19126",
        "resource": "multiarch-support",
        "score": 2.9,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: LD_PREFER_MAP_32BIT_EXEC not ignored in setuid binaries",
        "vulnerabilityID": "CVE-2019-19126"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "The string component in the GNU C Library (aka glibc or libc6) through 2.28, when running on the x32 architecture, incorrectly attempts to use a 64-bit register for size_t in assembly codes, which can lead to a segmentation fault or possibly unspecified other impact, as demonstrated by a crash in __memmove_avx_unaligned_erms in sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S during a memcpy.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/106671",
          "https://access.redhat.com/security/cve/CVE-2019-6488",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-6488",
          "https://security.gentoo.org/glsa/202006-04",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24097"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-6488",
        "resource": "multiarch-support",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Incorrect attempt to use a 64-bit register for size_t in assembly codes results in segmentation fault",
        "vulnerabilityID": "CVE-2019-6488"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 2.1,
            "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "In the GNU C Library (aka glibc or libc6) through 2.29, the memcmp function for the x32 architecture can incorrectly return zero (indicating that the inputs are equal) because the RDX most significant bit is mishandled.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "http://www.securityfocus.com/bid/106835",
          "https://access.redhat.com/security/cve/CVE-2019-7309",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-7309",
          "https://security.gentoo.org/glsa/202006-04",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24155",
          "https://sourceware.org/ml/libc-alpha/2019-02/msg00041.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-7309",
        "resource": "multiarch-support",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: memcmp function incorrectly returns zero",
        "vulnerabilityID": "CVE-2019-7309"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 2.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "** DISPUTED ** In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\\\1\\\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-9192",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-9192",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=24269",
          "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp;utm_medium=RSS"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-9192",
        "resource": "multiarch-support",
        "score": 2.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
        "vulnerabilityID": "CVE-2019-9192"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 8.1,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "An exploitable signed comparison vulnerability exists in the ARMv7 memcpy() implementation of GNU glibc 2.30.9000. Calling memcpy() (on ARMv7 targets that utilize the GNU glibc implementation) with a negative value for the 'num' parameter results in a signed comparison vulnerability. If an attacker underflows the 'num' parameter to memcpy(), this vulnerability could lead to undefined behavior such as writing to out-of-bounds memory and potentially remote code execution. Furthermore, this memcpy() implementation allows for program execution to continue in scenarios where a segmentation fault or crash should have occurred. The dangers occur in that subsequent execution and iterations of this code will be executed with this corrupted data.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2020-6096",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-6096",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SPYXTDOOB4PQGTYAMZAZNJIB3FF6YQXI/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/URXOIA2LDUKHQXK4BE55BQBRI6ZZG3Y6/",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-6096",
          "https://security.gentoo.org/glsa/202101-20",
          "https://sourceware.org/bugzilla/attachment.cgi?id=12334",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=25620",
          "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1019",
          "https://ubuntu.com/security/notices/USN-4954-1",
          "https://ubuntu.com/security/notices/USN-5310-1",
          "https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1019"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-6096",
        "resource": "multiarch-support",
        "score": 8.1,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: signed comparison vulnerability in the ARMv7 memcpy function",
        "vulnerabilityID": "CVE-2020-6096"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 2.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L"
          },
          "redhat": {
            "V3Score": 2.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L"
          }
        },
        "description": "The nameserver caching daemon (nscd) in the GNU C Library (aka glibc or libc6) 2.29 through 2.33, when processing a request for netgroup lookup, may crash due to a double-free, potentially resulting in degraded service or Denial of Service on the local system. This is related to netgroupcache.c.",
        "fixedVersion": "",
        "installedVersion": "2.24-11+deb9u4",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-27645",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27645",
          "https://linux.oracle.com/cve/CVE-2021-27645.html",
          "https://linux.oracle.com/errata/ELSA-2021-9560.html",
          "https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7LZNT6KTMCCWPWXEOGSHD3YLYZKUGMH5/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I7TS26LIZSOBLGJEZMJX4PXT5BQDE2WS/",
          "https://security.gentoo.org/glsa/202107-07",
          "https://sourceware.org/bugzilla/show_bug.cgi?id=27462",
          "https://ubuntu.com/security/notices/USN-5310-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-27645",
        "resource": "multiarch-support",
        "score": 2.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "glibc: Use-after-free in addgetnetgrentX function in netgroupcache.c",
        "vulnerabilityID": "CVE-2021-27645"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-29458",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29458",
          "https://invisible-island.net/ncurses/NEWS.html#t20220416",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00014.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00016.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-29458",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-29458",
        "resource": "ncurses-base",
        "score": 6.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: segfaulting OOB read",
        "vulnerabilityID": "CVE-2022-29458"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In ncurses 6.1, there is a NULL pointer dereference at function _nc_parse_entry in parse_entry.c that will lead to a denial of service attack. The product proceeds to the dereference code path even after a \"dubious character `*' in name or alias field\" detection.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-19211",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1643754",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19211",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-19211",
        "resource": "ncurses-base",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: Null pointer dereference at function _nc_parse_entry in parse_entry.c",
        "vulnerabilityID": "CVE-2018-19211"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the _nc_find_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17594",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17594",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17594.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00017.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17594",
        "resource": "ncurses-base",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the _nc_find_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17594"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          },
          "redhat": {
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the fmt_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17595",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17595",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17595.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00013.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17595",
        "resource": "ncurses-base",
        "score": 5.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the fmt_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17595"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
          "https://access.redhat.com/security/cve/CVE-2021-39537",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39537",
          "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-39537",
        "resource": "ncurses-base",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
        "vulnerabilityID": "CVE-2021-39537"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 7.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"
          },
          "redhat": {
            "V3Score": 6.1,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
          }
        },
        "description": "ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-29458",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29458",
          "https://invisible-island.net/ncurses/NEWS.html#t20220416",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00014.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2022-04/msg00016.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-29458",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-29458",
        "resource": "ncurses-bin",
        "score": 6.1,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: segfaulting OOB read",
        "vulnerabilityID": "CVE-2022-29458"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "In ncurses 6.1, there is a NULL pointer dereference at function _nc_parse_entry in parse_entry.c that will lead to a denial of service attack. The product proceeds to the dereference code path even after a \"dubious character `*' in name or alias field\" detection.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-19211",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1643754",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19211",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-19211",
        "resource": "ncurses-bin",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: Null pointer dereference at function _nc_parse_entry in parse_entry.c",
        "vulnerabilityID": "CVE-2018-19211"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          },
          "redhat": {
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the _nc_find_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17594",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17594",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17594.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00017.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17594",
        "resource": "ncurses-bin",
        "score": 5.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the _nc_find_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17594"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:P",
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L"
          },
          "redhat": {
            "V3Score": 5.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L"
          }
        },
        "description": "There is a heap-based buffer over-read in the fmt_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00059.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00061.html",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17594.json",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-17595.json",
          "https://access.redhat.com/security/cve/CVE-2019-17595",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17595",
          "https://errata.almalinux.org/8/ALSA-2021-4426.html",
          "https://linux.oracle.com/cve/CVE-2019-17595.html",
          "https://linux.oracle.com/errata/ELSA-2021-4426.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00013.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2019-10/msg00045.html",
          "https://security.gentoo.org/glsa/202101-28",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-17595",
        "resource": "ncurses-bin",
        "score": 5.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in the fmt_entry function in tinfo/comp_hash.c",
        "vulnerabilityID": "CVE-2019-17595"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 8.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
        "fixedVersion": "",
        "installedVersion": "6.0+20161126-1+deb9u2",
        "links": [
          "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
          "https://access.redhat.com/security/cve/CVE-2021-39537",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39537",
          "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
          "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
          "https://ubuntu.com/security/notices/USN-5477-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-39537",
        "resource": "ncurses-bin",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
        "vulnerabilityID": "CVE-2021-39537"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
          },
          "redhat": {
            "V3Score": 7.4,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
          }
        },
        "description": "ALPACA is an application layer protocol content confusion attack, exploiting TLS servers implementing different protocols but using compatible certificates, such as multi-domain or wildcard certificates. A MiTM attacker having access to victim's traffic at the TCP/IP layer can redirect traffic from one subdomain to another, resulting in a valid TLS session. This breaks the authentication of TLS and cross-protocol attacks may be possible where the behavior of one protocol service may compromise the other at the application layer.",
        "fixedVersion": "",
        "installedVersion": "1.15.12-1~stretch",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-3618",
          "https://alpaca-attack.com/",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1975623",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3618",
          "https://lists.exim.org/lurker/message/20210609.200324.f0e073ed.el.html",
          "https://marc.info/?l=sendmail-announce\u0026m=159394546814125\u0026w=2",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-3618",
          "https://security.appspot.com/vsftpd/Changelog.txt",
          "https://ubuntu.com/security/notices/USN-5371-1",
          "https://ubuntu.com/security/notices/USN-5371-2"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-3618",
        "resource": "nginx",
        "score": 7.4,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ALPACA: Application Layer Protocol Confusion - Analyzing and Mitigating Cracks in TLS Authentication",
        "vulnerabilityID": "CVE-2021-3618"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
          }
        },
        "description": "ngx_http_lua_module (aka lua-nginx-module) before 0.10.16 in OpenResty allows unsafe characters in an argument when using the API to mutate a URI, or a request or response header.",
        "fixedVersion": "",
        "installedVersion": "1.15.12-1~stretch",
        "links": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36309",
          "https://github.com/openresty/lua-nginx-module/compare/v0.10.15...v0.10.16",
          "https://github.com/openresty/lua-nginx-module/pull/1654",
          "https://news.ycombinator.com/item?id=26712562",
          "https://security.netapp.com/advisory/ntap-20210507-0005/",
          "https://ubuntu.com/security/notices/USN-5371-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-36309",
        "resource": "nginx",
        "score": 5.3,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "ngx_http_lua_module (aka lua-nginx-module) before 0.10.16 in OpenResty ...",
        "vulnerabilityID": "CVE-2020-36309"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P"
          },
          "redhat": {
            "V2Score": 2.6,
            "V2Vector": "AV:N/AC:H/Au:N/C:N/I:P/A:N"
          }
        },
        "description": "nginx 0.7.64 writes data to a log file without sanitizing non-printable characters, which might allow remote attackers to modify a window's title, or possibly execute arbitrary commands or overwrite files, via an HTTP request containing an escape sequence for a terminal emulator.",
        "fixedVersion": "",
        "installedVersion": "1.15.12-1~stretch",
        "links": [
          "http://www.securityfocus.com/archive/1/508830/100/0/threaded",
          "http://www.securityfocus.com/bid/37711",
          "http://www.ush.it/team/ush/hack_httpd_escape/adv.txt",
          "https://access.redhat.com/security/cve/CVE-2009-4487",
          "https://nvd.nist.gov/vuln/detail/CVE-2009-4487"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2009-4487",
        "resource": "nginx",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "nginx: Absent sanitation of escape sequences in web server log",
        "vulnerabilityID": "CVE-2009-4487"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"
          }
        },
        "description": "The default configuration of nginx, possibly 1.3.13 and earlier, uses world-readable permissions for the (1) access.log and (2) error.log files, which allows local users to obtain sensitive information by reading the files.",
        "fixedVersion": "",
        "installedVersion": "1.15.12-1~stretch",
        "links": [
          "http://secunia.com/advisories/55181",
          "http://security.gentoo.org/glsa/glsa-201310-04.xml",
          "http://www.openwall.com/lists/oss-security/2013/02/21/15",
          "http://www.openwall.com/lists/oss-security/2013/02/22/1",
          "http://www.openwall.com/lists/oss-security/2013/02/24/1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2013-0337",
        "resource": "nginx",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "The default configuration of nginx, possibly 1.3.13 and earlier, uses  ...",
        "vulnerabilityID": "CVE-2013-0337"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 4.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"
          }
        },
        "description": "In shadow before 4.5, the newusers tool could be made to manipulate internal data structures in ways unintended by the authors. Malformed input may lead to crashes (with a buffer overflow or other memory corruption) or other unspecified behaviors. This crosses a privilege boundary in, for example, certain web-hosting environments in which a Control Panel allows an unprivileged user account to create subaccounts.",
        "fixedVersion": "1:4.4-4.1+deb9u1",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2017-12424",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=756630",
          "https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1266675",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12424",
          "https://github.com/shadow-maint/shadow/commit/954e3d2e7113e9ac06632aee3c69b8d818cc8952",
          "https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html",
          "https://security.gentoo.org/glsa/201710-16",
          "https://ubuntu.com/security/notices/USN-5254-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-12424",
        "resource": "passwd",
        "score": 4.5,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "shadow-utils: Buffer overflow via newusers tool",
        "vulnerabilityID": "CVE-2017-12424"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.6,
            "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "The Debian shadow package before 1:4.5-1 for Shadow incorrectly lists pts/0 and pts/1 as physical terminals in /etc/securetty. This allows local users to login as password-less users even if they are connected by non-physical means such as SSH (hence bypassing PAM's nullok_secure configuration). This notably affects environments such as virtual machines automatically generated with a default blank root password, allowing all local users to escalate privileges.",
        "fixedVersion": "1:4.4-4.1+deb9u1",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877374",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=914957",
          "https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2017-20002",
        "resource": "passwd",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "The Debian shadow package before 1:4.5-1 for Shadow incorrectly lists  ...",
        "vulnerabilityID": "CVE-2017-20002"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.9,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:N/A:N"
          }
        },
        "description": "initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.",
        "fixedVersion": "",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "http://secunia.com/advisories/27215",
          "http://www.securityfocus.com/archive/1/482129/100/100/threaded",
          "http://www.securityfocus.com/archive/1/482857/100/0/threaded",
          "http://www.securityfocus.com/bid/26048",
          "http://www.vupen.com/english/advisories/2007/3474",
          "https://issues.rpath.com/browse/RPL-1825"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2007-5686",
        "resource": "passwd",
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "initscripts in rPath Linux 1 sets insecure permissions for the /var/lo ...",
        "vulnerabilityID": "CVE-2007-5686"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 3.3,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:P",
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N"
          },
          "redhat": {
            "V2Score": 3.7,
            "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
            "V3Score": 4.4,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N"
          }
        },
        "description": "shadow: TOCTOU (time-of-check time-of-use) race condition when copying and removing directory trees",
        "fixedVersion": "",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2013-4235",
          "https://access.redhat.com/security/cve/cve-2013-4235",
          "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4235",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4235",
          "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
          "https://security-tracker.debian.org/tracker/CVE-2013-4235"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2013-4235",
        "resource": "passwd",
        "score": 4.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "shadow-utils: TOCTOU race conditions by copying and removing directory trees",
        "vulnerabilityID": "CVE-2013-4235"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "V3Score": 5.3,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
          },
          "redhat": {
            "V3Score": 4.4,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
          }
        },
        "description": "An issue was discovered in shadow 4.5. newgidmap (in shadow-utils) is setuid and allows an unprivileged user to be placed in a user namespace where setgroups(2) is permitted. This allows an attacker to remove themselves from a supplementary group, which may allow access to certain filesystem paths if the administrator has used \"group blacklisting\" (e.g., chmod g-rwx) to restrict access to paths. This flaw effectively reverts a security feature in the kernel (in particular, the /proc/self/setgroups knob) to prevent this sort of privilege escalation.",
        "fixedVersion": "",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2018-7169",
          "https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1729357",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7169",
          "https://github.com/shadow-maint/shadow/pull/97",
          "https://security.gentoo.org/glsa/201805-09",
          "https://ubuntu.com/security/notices/USN-5254-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-7169",
        "resource": "passwd",
        "score": 4.4,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "shadow-utils: newgidmap allows unprivileged user to drop supplementary groups potentially allowing privilege escalation",
        "vulnerabilityID": "CVE-2018-7169"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          }
        },
        "description": "shadow 4.8, in certain circumstances affecting at least Gentoo, Arch Linux, and Void Linux, allows local users to obtain root access because setuid programs are misconfigured. Specifically, this affects shadow 4.8 when compiled using --with-libpam but without explicitly passing --disable-account-tools-setuid, and without a PAM configuration suitable for use with setuid account management tools. This combination leads to account management tools (groupadd, groupdel, groupmod, useradd, userdel, usermod) that can easily be used by unprivileged local users to escalate privileges to root in multiple ways. This issue became much more relevant in approximately December 2019 when an unrelated bug was fixed (i.e., the chmod calls to suidusbins were fixed in the upstream Makefile which is now included in the release version 4.8).",
        "fixedVersion": "",
        "installedVersion": "1:4.4-4.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2019-19882",
          "https://bugs.archlinux.org/task/64836",
          "https://bugs.gentoo.org/702252",
          "https://github.com/shadow-maint/shadow/commit/edf7547ad5aa650be868cf2dac58944773c12d75",
          "https://github.com/shadow-maint/shadow/pull/199",
          "https://github.com/void-linux/void-packages/pull/17580",
          "https://security.gentoo.org/glsa/202008-09"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-19882",
        "resource": "passwd",
        "score": 7.8,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "shadow-utils: local users can obtain root access because setuid programs are misconfigured",
        "vulnerabilityID": "CVE-2019-19882"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.4,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:P",
            "V3Score": 8.2,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
          },
          "redhat": {
            "V3Score": 8.2,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
          }
        },
        "description": "Perl before 5.30.3 on 32-bit platforms allows a heap-based buffer overflow because nested regular expression quantifiers have an integer overflow.",
        "fixedVersion": "5.24.1-3+deb9u7",
        "installedVersion": "5.24.1-3+deb9u5",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html",
          "https://access.redhat.com/security/cve/CVE-2020-10543",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10543",
          "https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod",
          "https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3",
          "https://github.com/perl/perl5/commit/897d1f7fd515b828e4b198d8b8bef76c6faf03ed",
          "https://linux.oracle.com/cve/CVE-2020-10543.html",
          "https://linux.oracle.com/errata/ELSA-2021-9238.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/",
          "https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod",
          "https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod",
          "https://security.gentoo.org/glsa/202006-03",
          "https://security.netapp.com/advisory/ntap-20200611-0001/",
          "https://ubuntu.com/security/notices/USN-4602-1",
          "https://ubuntu.com/security/notices/USN-4602-2",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2021.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2020.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-10543",
        "resource": "perl-base",
        "score": 8.2,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "perl: heap-based buffer overflow in regular expression compiler leads to DoS",
        "vulnerabilityID": "CVE-2020-10543"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.5,
            "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"
          },
          "redhat": {
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "Perl before 5.30.3 has an integer overflow related to mishandling of a \"PL_regkind[OP(n)] == NOTHING\" situation. A crafted regular expression could lead to malformed bytecode with a possibility of instruction injection.",
        "fixedVersion": "5.24.1-3+deb9u7",
        "installedVersion": "5.24.1-3+deb9u5",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html",
          "https://access.redhat.com/security/cve/CVE-2020-10878",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10878",
          "https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod",
          "https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3",
          "https://github.com/perl/perl5/commit/0a320d753fe7fca03df259a4dfd8e641e51edaa8",
          "https://github.com/perl/perl5/commit/3295b48defa0f8570114877b063fe546dd348b3c",
          "https://linux.oracle.com/cve/CVE-2020-10878.html",
          "https://linux.oracle.com/errata/ELSA-2021-9238.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/",
          "https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod",
          "https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod",
          "https://security.gentoo.org/glsa/202006-03",
          "https://security.netapp.com/advisory/ntap-20200611-0001/",
          "https://ubuntu.com/security/notices/USN-4602-1",
          "https://ubuntu.com/security/notices/USN-4602-2",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2021.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2020.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-10878",
        "resource": "perl-base",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "perl: corruption of intermediate language state of compiled regular expression due to integer overflow leads to DoS",
        "vulnerabilityID": "CVE-2020-10878"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          }
        },
        "description": "regcomp.c in Perl before 5.30.3 allows a buffer overflow via a crafted regular expression because of recursive S_study_chunk calls.",
        "fixedVersion": "5.24.1-3+deb9u7",
        "installedVersion": "5.24.1-3+deb9u5",
        "links": [
          "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html",
          "https://access.redhat.com/security/cve/CVE-2020-12723",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12723",
          "https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod",
          "https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3",
          "https://github.com/Perl/perl5/issues/16947",
          "https://github.com/Perl/perl5/issues/17743",
          "https://github.com/perl/perl5/commit/66bbb51b93253a3f87d11c2695cfb7bdb782184a",
          "https://linux.oracle.com/cve/CVE-2020-12723.html",
          "https://linux.oracle.com/errata/ELSA-2021-9238.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/",
          "https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod",
          "https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod",
          "https://security.gentoo.org/glsa/202006-03",
          "https://security.netapp.com/advisory/ntap-20200611-0001/",
          "https://ubuntu.com/security/notices/USN-4602-1",
          "https://ubuntu.com/security/notices/USN-4602-2",
          "https://www.oracle.com//security-alerts/cpujul2021.html",
          "https://www.oracle.com/security-alerts/cpuApr2021.html",
          "https://www.oracle.com/security-alerts/cpuapr2022.html",
          "https://www.oracle.com/security-alerts/cpujan2021.html",
          "https://www.oracle.com/security-alerts/cpujan2022.html",
          "https://www.oracle.com/security-alerts/cpuoct2020.html",
          "https://www.oracle.com/security-alerts/cpuoct2021.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-12723",
        "resource": "perl-base",
        "score": 7.5,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "perl: corruption of intermediate language state of compiled regular expression due to recursive S_study_chunk() calls leads to DoS",
        "vulnerabilityID": "CVE-2020-12723"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 6.8,
            "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "CPAN 2.28 allows Signature Verification Bypass.",
        "fixedVersion": "",
        "installedVersion": "5.24.1-3+deb9u5",
        "links": [
          "http://blogs.perl.org/users/neilb/2021/11/addressing-cpan-vulnerabilities-related-to-checksums.html",
          "https://access.redhat.com/security/cve/CVE-2020-16156",
          "https://blog.hackeriet.no/cpan-signature-verification-vulnerabilities/",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-16156",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SD6RYOJII7HRJ6WVORFNVTYNOFY5JDXN/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SZ32AJIV4RHJMLWLU5QULGKMMIHYOMDC/",
          "https://metacpan.org/pod/distribution/CPAN/scripts/cpan",
          "https://ubuntu.com/security/notices/USN-5689-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2020-16156",
        "resource": "perl-base",
        "score": 7.8,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "perl-CPAN: Bypass of verification of signatures in CHECKSUMS files",
        "vulnerabilityID": "CVE-2020-16156"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
          },
          "redhat": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:N"
          }
        },
        "description": "_is_safe in the File::Temp module for Perl does not properly handle symlinks.",
        "fixedVersion": "",
        "installedVersion": "5.24.1-3+deb9u5",
        "links": [
          "http://www.openwall.com/lists/oss-security/2011/11/04/2",
          "http://www.openwall.com/lists/oss-security/2011/11/04/4",
          "https://access.redhat.com/security/cve/CVE-2011-4116",
          "https://github.com/Perl-Toolchain-Gang/File-Temp/issues/14",
          "https://rt.cpan.org/Public/Bug/Display.html?id=69106",
          "https://seclists.org/oss-sec/2011/q4/238"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2011-4116",
        "resource": "perl-base",
        "score": 7.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "perl: File::Temp insecure temporary file handling",
        "vulnerabilityID": "CVE-2011-4116"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "GNU Tar through 1.30, when --sparse is used, mishandles file shrinkage during read access, which allows local users to cause a denial of service (infinite read loop in sparse_dump_region in sparse.c) by modifying a file that is supposed to be archived by a different user's process (e.g., a system backup running as root).",
        "fixedVersion": "1.29b-1.1+deb9u1",
        "installedVersion": "1.29b-1.1",
        "links": [
          "http://git.savannah.gnu.org/cgit/tar.git/commit/?id=c15c42ccd1e2377945fd0414eca1a49294bff454",
          "http://lists.gnu.org/archive/html/bug-tar/2018-12/msg00023.html",
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00077.html",
          "http://www.securityfocus.com/bid/106354",
          "https://access.redhat.com/security/cve/CVE-2018-20482",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20482",
          "https://lists.debian.org/debian-lts-announce/2018/12/msg00023.html",
          "https://lists.debian.org/debian-lts-announce/2021/11/msg00025.html",
          "https://news.ycombinator.com/item?id=18745431",
          "https://security.gentoo.org/glsa/201903-05",
          "https://twitter.com/thatcks/status/1076166645708668928",
          "https://ubuntu.com/security/notices/USN-4692-1",
          "https://utcc.utoronto.ca/~cks/space/blog/sysadmin/TarFindingTruncateBug"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-20482",
        "resource": "tar",
        "score": 5.5,
        "severity": "MEDIUM",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tar: Infinite read loop in sparse_dump_region function in sparse.c",
        "vulnerabilityID": "CVE-2018-20482"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 10,
            "V2Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          }
        },
        "description": "Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users or remote attackers to gain privileges.",
        "fixedVersion": "",
        "installedVersion": "1.29b-1.1",
        "links": [
          "http://marc.info/?l=bugtraq\u0026m=112327628230258\u0026w=2",
          "https://access.redhat.com/security/cve/CVE-2005-2541",
          "https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c@%3Cissues.guacamole.apache.org%3E"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2005-2541",
        "resource": "tar",
        "score": 7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tar: does not properly warn the user when extracting setuid or setgid files",
        "vulnerabilityID": "CVE-2005-2541"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "pax_decode_header in sparse.c in GNU Tar before 1.32 had a NULL pointer dereference when parsing certain archives that have malformed extended headers.",
        "fixedVersion": "",
        "installedVersion": "1.29b-1.1",
        "links": [
          "http://git.savannah.gnu.org/cgit/tar.git/commit/?id=cb07844454d8cc9fb21f53ace75975f91185a120",
          "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00077.html",
          "http://savannah.gnu.org/bugs/?55369",
          "https://access.redhat.com/security/cve/CVE-2019-9923",
          "https://bugs.launchpad.net/ubuntu/+source/tar/+bug/1810241",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9923",
          "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
          "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
          "https://ubuntu.com/security/notices/USN-4692-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2019-9923",
        "resource": "tar",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tar: null-pointer dereference in pax_decode_header in sparse.c",
        "vulnerabilityID": "CVE-2019-9923"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 4.3,
            "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 3.3,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L"
          }
        },
        "description": "A flaw was found in the src/list.c of tar 1.33 and earlier. This flaw allows an attacker who can submit a crafted input file to tar to cause uncontrolled consumption of memory. The highest threat from this vulnerability is to system availability.",
        "fixedVersion": "",
        "installedVersion": "1.29b-1.1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-20193",
          "https://bugzilla.redhat.com/show_bug.cgi?id=1917565",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20193",
          "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=d9d4435692150fa8ff68e1b1a473d187cc3fd777",
          "https://savannah.gnu.org/bugs/?59897",
          "https://security.gentoo.org/glsa/202105-29",
          "https://ubuntu.com/security/notices/USN-5329-1"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-20193",
        "resource": "tar",
        "score": 3.3,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tar: Memory leak in read_header() in list.c",
        "vulnerabilityID": "CVE-2021-20193"
      },
      {
        "fixedVersion": "2020d-0+deb9u1",
        "installedVersion": "2019a-0+deb9u1",
        "resource": "tzdata",
        "severity": "UNKNOWN",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tzdata - new upstream version",
        "vulnerabilityID": "DLA-2424-1"
      },
      {
        "fixedVersion": "2020e-0+deb9u1",
        "installedVersion": "2019a-0+deb9u1",
        "resource": "tzdata",
        "severity": "UNKNOWN",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tzdata - new upstream version",
        "vulnerabilityID": "DLA-2509-1"
      },
      {
        "fixedVersion": "2021a-0+deb9u1",
        "installedVersion": "2019a-0+deb9u1",
        "resource": "tzdata",
        "severity": "UNKNOWN",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tzdata - new upstream version",
        "vulnerabilityID": "DLA-2542-1"
      },
      {
        "fixedVersion": "2021a-0+deb9u2",
        "installedVersion": "2019a-0+deb9u1",
        "resource": "tzdata",
        "severity": "UNKNOWN",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tzdata - new upstream version",
        "vulnerabilityID": "DLA-2797-1"
      },
      {
        "fixedVersion": "2021a-0+deb9u3",
        "installedVersion": "2019a-0+deb9u1",
        "resource": "tzdata",
        "severity": "UNKNOWN",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tzdata - new timezone database",
        "vulnerabilityID": "DLA-2963-1"
      },
      {
        "fixedVersion": "2021a-0+deb9u4",
        "installedVersion": "2019a-0+deb9u1",
        "resource": "tzdata",
        "severity": "UNKNOWN",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "tzdata - new timezone database",
        "vulnerabilityID": "DLA-3051-1"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 7.2,
            "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
            "V3Score": 7.8,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V2Score": 6.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
            "V3Score": 8.6,
            "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
          }
        },
        "description": "runuser in util-linux allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "http://www.openwall.com/lists/oss-security/2016/02/27/1",
          "http://www.openwall.com/lists/oss-security/2016/02/27/2",
          "https://access.redhat.com/security/cve/CVE-2016-2779",
          "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2016-2779",
        "resource": "util-linux",
        "score": 8.6,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: runuser tty hijack via TIOCSTI ioctl",
        "vulnerabilityID": "CVE-2016-2779"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.2,
            "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 4.7,
            "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"
          }
        },
        "description": "** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2021-37600",
          "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
          "https://github.com/karelzak/util-linux/issues/1395",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
          "https://security.netapp.com/advisory/ntap-20210902-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2021-37600",
        "resource": "util-linux",
        "score": 4.7,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
        "vulnerabilityID": "CVE-2021-37600"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 1.9,
            "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          },
          "redhat": {
            "V3Score": 5.5,
            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
          }
        },
        "description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
        "fixedVersion": "",
        "installedVersion": "2.29.2-1+deb9u1",
        "links": [
          "https://access.redhat.com/security/cve/CVE-2022-0563",
          "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
          "https://security.netapp.com/advisory/ntap-20220331-0002/"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-0563",
        "resource": "util-linux",
        "score": 5.5,
        "severity": "LOW",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
        "vulnerabilityID": "CVE-2022-0563"
      },
      {
        "cvss": {
          "nvd": {
            "V3Score": 9.8,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "redhat": {
            "V3Score": 7,
            "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"
          }
        },
        "description": "zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).",
        "fixedVersion": "",
        "installedVersion": "1:1.2.8.dfsg-5",
        "links": [
          "http://www.openwall.com/lists/oss-security/2022/08/05/2",
          "http://www.openwall.com/lists/oss-security/2022/08/09/1",
          "https://access.redhat.com/security/cve/CVE-2022-37434",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37434",
          "https://github.com/curl/curl/issues/9271",
          "https://github.com/ivd38/zlib_overflow",
          "https://github.com/madler/zlib/blob/21767c654d31d2dccdde4330529775c6c5fd5389/zlib.h#L1062-L1063",
          "https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1",
          "https://github.com/nodejs/node/blob/75b68c6e4db515f76df73af476eccf382bbcb00a/deps/zlib/inflate.c#L762-L764",
          "https://lists.debian.org/debian-lts-announce/2022/09/msg00012.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JWN4VE3JQR4O2SOUS5TXNLANRPMHWV4I/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NMBOJ77A7T7PQCARMDUK75TE6LLESZ3O/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PAVPQNCG3XRLCLNSQRM3KAN5ZFMVXVTY/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/X5U7OTKZSHY2I3ZFJSR2SHFHW72RKGDK/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YRQAI7H4M4RQZ2IWZUEEXECBE5D56BH2/",
          "https://nvd.nist.gov/vuln/detail/CVE-2022-37434",
          "https://security.netapp.com/advisory/ntap-20220901-0005/",
          "https://ubuntu.com/security/notices/USN-5570-1",
          "https://ubuntu.com/security/notices/USN-5570-2",
          "https://ubuntu.com/security/notices/USN-5573-1",
          "https://www.debian.org/security/2022/dsa-5218"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2022-37434",
        "resource": "zlib1g",
        "score": 7,
        "severity": "CRITICAL",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "zlib: heap-based buffer over-read and overflow in inflate() in inflate.c via a large gzip header extra field",
        "vulnerabilityID": "CVE-2022-37434"
      },
      {
        "cvss": {
          "nvd": {
            "V2Score": 5,
            "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "V3Score": 7.5,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "redhat": {
            "V3Score": 8.2,
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
          }
        },
        "description": "zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many distant matches.",
        "fixedVersion": "1:1.2.8.dfsg-5+deb9u1",
        "installedVersion": "1:1.2.8.dfsg-5",
        "links": [
          "http://seclists.org/fulldisclosure/2022/May/33",
          "http://seclists.org/fulldisclosure/2022/May/35",
          "http://seclists.org/fulldisclosure/2022/May/38",
          "http://www.openwall.com/lists/oss-security/2022/03/25/2",
          "http://www.openwall.com/lists/oss-security/2022/03/26/1",
          "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-25032.json",
          "https://access.redhat.com/security/cve/CVE-2018-25032",
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25032",
          "https://errata.almalinux.org/8/ALSA-2022-2201.html",
          "https://github.com/madler/zlib/commit/5c44459c3b28a9bd3283aaceab7c615f8020c531",
          "https://github.com/madler/zlib/compare/v1.2.11...v1.2.12",
          "https://github.com/madler/zlib/issues/605",
          "https://github.com/sparklemotion/nokogiri/releases/tag/v1.13.4",
          "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-v6gp-9mmm-c6p5",
          "https://groups.google.com/g/ruby-security-ann/c/vX7qSjsvWis/m/TJWN4oOKBwAJ",
          "https://linux.oracle.com/cve/CVE-2018-25032.html",
          "https://linux.oracle.com/errata/ELSA-2022-9565.html",
          "https://lists.debian.org/debian-lts-announce/2022/04/msg00000.html",
          "https://lists.debian.org/debian-lts-announce/2022/05/msg00008.html",
          "https://lists.debian.org/debian-lts-announce/2022/09/msg00023.html",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DCZFIJBJTZ7CL5QXBFKTQ22Q26VINRUF/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DF62MVMH3QUGMBDCB3DY2ERQ6EBHTADB/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZZPTWRYQULAOL3AW7RZJNVZ2UONXCV4/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NS2D2GFPFGOJUL4WQ3DUAY7HF4VWQ77F/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VOKNP2L734AEL47NRYGVZIKEFOUBQY5Y/",
          "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XOKFMSNQ5D5WGMALBNBXU3GE442V74WU/",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-25032",
          "https://security.netapp.com/advisory/ntap-20220526-0009/",
          "https://security.netapp.com/advisory/ntap-20220729-0004/",
          "https://support.apple.com/kb/HT213255",
          "https://support.apple.com/kb/HT213256",
          "https://support.apple.com/kb/HT213257",
          "https://ubuntu.com/security/notices/USN-5355-1",
          "https://ubuntu.com/security/notices/USN-5355-2",
          "https://ubuntu.com/security/notices/USN-5359-1",
          "https://ubuntu.com/security/notices/USN-5359-2",
          "https://www.debian.org/security/2022/dsa-5111",
          "https://www.openwall.com/lists/oss-security/2022/03/24/1",
          "https://www.openwall.com/lists/oss-security/2022/03/28/1",
          "https://www.openwall.com/lists/oss-security/2022/03/28/3",
          "https://www.oracle.com/security-alerts/cpujul2022.html"
        ],
        "primaryLink": "https://avd.aquasec.com/nvd/cve-2018-25032",
        "resource": "zlib1g",
        "score": 8.2,
        "severity": "HIGH",
        "target": "nginx:1.15 (debian 9.9)",
        "title": "zlib: A flaw found in zlib when compressing (not decompressing) certain inputs",
        "vulnerabilityID": "CVE-2018-25032"
      }
    ]
  }
}