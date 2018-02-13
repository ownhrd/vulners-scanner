#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Igor Sidorenko"
__email__ = "neither89@gmail.com"
__status__ = "Production"

import paramiko
import json
from pyzabbix import ZabbixMetric, ZabbixSender
paramiko.util.log_to_file('paramiko.log')

# Zabbix server or proxy ip address
def zbx_send(packet):
    ZabbixSender('127.0.0.1').send(packet)

with open('/root/vulners-scanner/hosts') as host_list:
    content = host_list.readlines()
content = [x.strip() for x in content] 
for hosts in content:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # SSH user and private key
        ssh.connect(hosts, username='vulners-scanner', key_filename='/root/vulners-key/vulners_key')
    except:
        continue
    get_os = "cat /etc/os-release | sed 's/\"//g' | awk  '/'^ID='/' | sed 's/ID=//'"
    get_os_version = "cat /etc/os-release | sed 's/\"/ /g' | awk  '/'^VERSION_ID='/{print $2}'"
    get_hostname = "hostname -f"

    stdin, stdout, stderr = ssh.exec_command(get_os)
    v_stdin, v_stdout, v_stderr = ssh.exec_command(get_os_version)
    h_stdin, h_stdout, h_stderr = ssh.exec_command(get_hostname)

    detect_hostname = h_stdout.read()
    detect_os = stdout.read()
    detect_os_version = v_stdout.read()

    # Get Ubuntu 14.04 vulnerability information
    if detect_os == 'ubuntu\n' and detect_os_version == '14.04\n':
        from executor import execute
        stdin, stdout, stderr = ssh.exec_command("dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'")
        print("\nHost info: {}\nOS: {}\nVersion: {}".format(detect_hostname.rstrip(), detect_os.rstrip(), detect_os_version.rstrip()))
        with open('/root/vulners-scanner/ubuntu_1404.json') as data_file:
            data = json.load(data_file)
            vuln_package = []
            results = []
            vuln_print = []
            update_pkg = []
            pkg_list = stdout.readlines()
            for vuln in data:
                affected_packages = vuln['_source']['affectedPackage']
                for variant in affected_packages:
                    if (variant['OSVersion'] == "14.04" or variant['OSVersion'] == 'any'):
                        vp_name = variant['packageName']
                        vp_version = variant['packageVersion']
                        for package in [pkg for pkg in pkg_list if pkg.startswith(vp_name)]:
                            try:
                                p_name = package.split()[0]
                                p_version = package.split()[1]
                            except:
                                continue
                            if vp_name == p_name:
                                package_version = execute('dpkg', '--compare-versions', vp_version, 'gt', p_version, check=False)
                                if  package_version:
                                    stripped_vuln_package = package
                                    vuln_package.append(stripped_vuln_package)
                                    stripped_vuln = vuln
                                    stripped_vuln['_source']['affectedPackage'] = variant
                                    results.append(stripped_vuln)
            if not results:
                print('\nNo vulnerabilities found')
                packet = [ZabbixMetric(detect_hostname.rstrip(), 'cve.score', '0')]
                zbx_send(packet)
            else:    
                print('\nVulnerable packages:')
                for result in set(vuln_package):
                    update_pkg.append(result.split()[0])
                    print(result.strip())
                print('\nVulnerabilities information:')
                zbx_vuln = 0
                for vulnInfo in results:
                    source = vulnInfo['_source']
                    vuln_print.append("      {} - '{}', cvss.score - {} ".format(source['id'], source['title'], source['cvss']['score']))
                    if float(source['cvss']['score']) > zbx_vuln:
                        zbx_vuln = float(source['cvss']['score'])
                packet = [ZabbixMetric(detect_hostname.rstrip(), 'cve.score', zbx_vuln)]
                zbx_send(packet)
                for result in set(vuln_print):
                    print(result)
                print_pkg = ' '.join(update_pkg)
                print("\nPlease run:\napt install {}".format(print_pkg))

    # Get Ubuntu 16.04 vulnerability information
    elif detect_os == 'ubuntu\n' and detect_os_version == '16.04\n':
        from executor import execute
        stdin, stdout, stderr = ssh.exec_command("dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'")
        print("\nHost info: {}\nOS: {}\nVersion: {}".format(detect_hostname.rstrip(), detect_os.rstrip(), detect_os_version.rstrip()))
        with open('/root/vulners-scanner/ubuntu_1604.json') as data_file:
            data = json.load(data_file)
            vuln_package = []
            results = []
            vuln_print = []
            update_pkg = []
            pkg_list = stdout.readlines()
            for vuln in data:
                affected_packages = vuln['_source']['affectedPackage']
                for variant in affected_packages:
                    if (variant['OSVersion'] == "16.04" or variant['OSVersion'] == 'any'):
                        vp_name = variant['packageName']
                        vp_version = variant['packageVersion']
                        for package in [pkg for pkg in pkg_list if pkg.startswith(vp_name)]:
                            try:
                                p_name = package.split()[0]
                                p_version = package.split()[1]
                            except:
                                continue
                            if vp_name == p_name:
                                package_version = execute('dpkg', '--compare-versions', vp_version, 'gt', p_version, check=False)
                                if  package_version:
                                    stripped_vuln_package = package
                                    vuln_package.append(stripped_vuln_package)
                                    stripped_vuln = vuln
                                    stripped_vuln['_source']['affectedPackage'] = variant
                                    results.append(stripped_vuln)
            if not results:
                print('\nNo vulnerabilities found')
                packet = [ZabbixMetric(detect_hostname.rstrip(), 'cve.score', '0')]
                zbx_send(packet)
            else:
                print('\nVulnerable packages:')
                for result in set(vuln_package):
                    update_pkg.append(result.split()[0])
                    print(result.strip())
                print('\nVulnerabilities information:')
                zbx_vuln = 0
                for vulnInfo in results:
                    source = vulnInfo['_source']
                    vuln_print.append("      {} - '{}', cvss.score - {} ".format(source['id'], source['title'], source['cvss']['score']))
                    if float(source['cvss']['score']) > zbx_vuln:
                        zbx_vuln = float(source['cvss']['score'])
                packet = [ZabbixMetric(detect_hostname.rstrip(), 'cve.score', zbx_vuln)]
                zbx_send(packet)
                for result in set(vuln_print):
                    print(result)
                print_pkg = ' '.join(update_pkg)
                print("\nPlease run:\napt install {}".format(print_pkg))

    # Get Debian 8 vulnerability information
    elif detect_os == 'debian\n' and detect_os_version == '8\n':
        from executor import execute
        stdin, stdout, stderr = ssh.exec_command("dpkg -l | awk '/'^ii'/''{print $2, $3, $4}'")
        print("\nHost info: {}\nOS: {}\nVersion: {}".format(detect_hostname.rstrip(), detect_os.rstrip(), detect_os_version.rstrip()))
        with open('/root/vulners-scanner/debian_8.json') as data_file:
            data = json.load(data_file)
            vuln_package = []
            results = []
            vuln_print = []
            update_pkg = []
            pkg_list = stdout.readlines()
            for vuln in data:
                affected_packages = vuln['_source']['affectedPackage']
                for variant in affected_packages:
                    if (variant['OSVersion'] == "8" or variant['OSVersion'] == 'any'):
                        vp_name = variant['packageName']
                        vp_version = variant['packageVersion']
                        for package in [pkg for pkg in pkg_list if pkg.startswith(vp_name)]:
                            try:
                                p_name = package.split()[0]
                                p_version = package.split()[1]
                            except:
                                continue
                            if vp_name == p_name:
                                package_version = execute('dpkg', '--compare-versions', vp_version, 'gt', p_version, check=False)
                                if  package_version:
                                    stripped_vuln_package = package
                                    vuln_package.append(stripped_vuln_package)
                                    stripped_vuln = vuln
                                    stripped_vuln['_source']['affectedPackage'] = variant
                                    results.append(stripped_vuln)
            if not results:
                print('\nNo vulnerabilities found')
                packet = [ZabbixMetric(detect_hostname.rstrip(), 'cve.score', '0')]
                zbx_send(packet)
            else:
                print('\nVulnerable packages:')
                for result in set(vuln_package):
                    update_pkg.append(result.split()[0])
                    print(result.strip())
                print('\nVulnerabilities information:')
                zbx_vuln = 0
                for vulnInfo in results:
                    source = vulnInfo['_source']
                    vuln_print.append("      {} - '{}', cvss.score - {} ".format(source['id'], source['title'], source['cvss']['score']))
                    if float(source['cvss']['score']) > zbx_vuln:
                        zbx_vuln = float(source['cvss']['score'])
                packet = [ZabbixMetric(detect_hostname.rstrip(), 'cve.score', zbx_vuln)]
                zbx_send(packet)
                for result in set(vuln_print):
                    print(result)
                print_pkg = ' '.join(update_pkg)
                print("\nPlease run:\napt install {}".format(print_pkg))

    # Get Centos 7 vulnerability information
    elif detect_os == 'centos\n' and detect_os_version == '7\n':
        from rpmUtils.miscutils import splitFilename
        from rpmUtils.miscutils import compareEVR
        uname_stdin, uname_stdout, uname_stderr = ssh.exec_command("uname -r | sed 's/-/ /g'")
        uname = uname_stdout.read()
        stdin, stdout, stderr = ssh.exec_command("rpm -qa --qf '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n' | grep -v 'kernel'")
        f_stdin, f_stdout, f_stderr = ssh.exec_command("rpm -qa --qf '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n' | grep -e '^kernel.*|*" + uname.rstrip() + "'")
        pkg_list = stdout.readlines() + f_stdout.readlines()
        print("\nHost info: {}\nOS: {}\nVersion: {}".format(detect_hostname.rstrip(), detect_os.rstrip(), detect_os_version.rstrip()))
        with open('/root/vulners-scanner/centos_7.json') as data_file:
            data = json.load(data_file)
            vuln_package = []
            results = []
            vuln_print = []
            update_pkg = []
            for vuln in data:
                affected_packages = vuln['_source']['affectedPackage']
                for variant in affected_packages:
                    if (variant['OSVersion'] == "7" or variant['OSVersion'] == 'any'):
                        [vp_name, vp_version, vp_release, vp_epoch, vp_arch] = splitFilename(variant['packageFilename'])
                        for package in [pkg for pkg in pkg_list if pkg.startswith(vp_name)]:
                            try:
                                [p_name, p_version, p_release, p_arch] = package.split()
                            except:
                                continue
                            if vp_name == p_name:
                                check_version = compareEVR(("1", vp_version, vp_release ), ("1", p_version, p_release))
                                arch_match = vp_arch == p_arch
                                package_version = check_version > 0
                                if  arch_match and package_version:
                                    stripped_vuln_package = package
                                    vuln_package.append(stripped_vuln_package)
                                    stripped_vuln = vuln
                                    stripped_vuln['_source']['affectedPackage'] = variant
                                    results.append(stripped_vuln)
            if not results:
                print('\nNo vulnerabilities found')
                packet = [ZabbixMetric(detect_hostname.rstrip(), 'cve.score', '0')]
                zbx_send(packet)
            else:
                print('\nVulnerable packages:')
                for result in set(vuln_package):
                    update_pkg.append(result.split()[0])
                    print(result.strip())
                print('\nVulnerabilities information:')
                zbx_vuln = 0
                for vulnInfo in results:
                    source = vulnInfo['_source']
                    vuln_print.append("      {} - '{}', cvss.score - {} ".format(source['id'], source['title'], source['cvss']['score']))
                    if float(source['cvss']['score']) > zbx_vuln:
                        zbx_vuln = float(source['cvss']['score'])
                packet = [ZabbixMetric(detect_hostname.rstrip(), 'cve.score', zbx_vuln)]
                zbx_send(packet)
                for result in set(vuln_print):
                    print(result)
                print_pkg = ' '.join(update_pkg)
                print("\nPlease run:\nyum install {}".format(print_pkg))

    else:
        print("\nHost info: {}\nOS: {}\nVersion: {}\n\nSystem not supported".format(detect_hostname.rstrip(), detect_os.rstrip(), detect_os_version.rstrip()))
    ssh.close()
