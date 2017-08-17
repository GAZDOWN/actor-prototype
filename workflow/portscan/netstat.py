#!/usr/bin/env python
import psutil
import socket
import nmap


class PortList(dict):
    PROTO_TCP = "tcp"
    PROTO_UDP = "udp"

    def __init__(self):
        super(PortList, self).__init__()

        self[self.PROTO_TCP] = {} 
        self[self.PROTO_UDP] = {}

    def _raise_for_protocol(self, protocol):
        if not protocol in self.get_protocols():
            raise ValueError("Invalid protocol: {}".format(str(protocol)))

    def set_port(self, protocol, source, data = None):
        self._raise_for_protocol(protocol)

        self[protocol][int(source)] = data

    def set_tcp_port(self, source, target = None):
        self.set_port(self.PROTO_TCP, source, target)

    def unset_port(self, protocol, source):
        self._raise_for_protocol(protocol)

        if not self.has_port(protocol, source):
            raise ValueError("Invalid port: {}".format(str(source)))

        del self[protocol][source]

    def unset_tcp_port(self, source):
        self.unset_port(self.PROTO_TCP, source)

    def list_ports(self, protocol):
        self._raise_for_protocol(protocol)

        return self[protocol].keys()

    def list_tcp_ports(self):
        return self.list_ports(self.PROTO_TCP)

    def has_port(self, protocol, source):
        self._raise_for_protocol(protocol)

        if not source in self.list_ports(protocol):
            return False

        return True

    def has_tcp_port(self, source):
        return self.has_port(self.PROTO_TCP, source)

    def get_port(self, protocol, source):
        if not self.has_port(protocol, source):
            raise ValueError("Port {} is not mapped".format(str(source)))

        return self[protocol][source]

    def get_tcp_port(self, source):
        return self.get_port(self.PROTO_TCP, source)

    def get_protocols(self):
        return self.keys()


def port_scan(ip_or_fqdn, port_range=None, shallow=False, force_nmap=False):
    def _nmap(port_list, ip, port_range=None, shallow=False):
        if shallow and port_range is None:
            port_range = '{}-{}'.format(_MIN_PORT, _MAX_PORT)
        scan_args = '-sS' if shallow else '-sV'

        port_scanner = nmap.PortScanner()
        port_scanner.scan(ip, port_range, scan_args)
        scan_info = port_scanner.scaninfo()

        if scan_info.get('error', False):
            raise PortScanException(
                scan_info['error'][0] if isinstance(scan_info['error'], list) else scan_info['error']
            )

        for proto in port_scanner[ip].all_protocols():
            for port in sorted(port_scanner[ip][proto]):
                if port_scanner[ip][proto][port]['state'] in ('open', 'filtered'):
                    port_list.set_port(proto, port, port_scanner[ip][proto][port])
        return port_list

    def _net_util(port_list):
        sconns = psutil.net_connections(kind=port_list.PROTO_TCP)
        for sconn in sconns:
            addr, port = sconn.laddr
            if not port_list.has_port(port_list.PROTO_TCP, port):
                if sconn.pid:
                    name = psutil.Process(sconn.pid).name()
                else:
                    name = "Unknown"

            port_list.set_port(port_list.PROTO_TCP, port, {"name": name})
        return port_list

    port_list = PortList()

    if ip_or_fqdn in ('localhost', '127.0.0.1') and not force_nmap:
        return _net_util(port_list)

    ip = socket.gethostbyname(ip_or_fqdn)
    return _nmap(port_list, ip, port_range, shallow)


if __name__ == '__main__':
    port_list = PortList()
    
    try: 
        result = port_scan("127.0.0.1")
        import pprint
        pprint.pprint(result)

    except Exception as e:
        pass
    #    module.fail_json(msg=str(e))
