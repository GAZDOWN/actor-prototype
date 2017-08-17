#!/usr/bin/env python
from sets import Set
from json import dumps


class PortCollisionException(Exception):
    pass


class PortList(dict):
    PROTO_TCP = "tcp"
    PROTO_UDP = "udp"

    MIN_PORT = 1
    MAX_PORT = 65535

    def __init__(self):
        super(PortList, self).__init__()

        self[self.PROTO_TCP] = {}
        self[self.PROTO_UDP] = {}

    def _raise_for_protocol(self, protocol):
        if protocol not in self.get_protocols():
            raise ValueError("Invalid protocol: {}".format(str(protocol)))

    def set_port(self, protocol, source, data=None):
        self._raise_for_protocol(protocol)

        if int(source) >= self.MIN_PORT and int(source) <= self.MAX_PORT:
            self[protocol][int(source)] = data
        else:
            raise ValueError("Port must be in interval <{}; {}>".format(self.MIN_PORT, self.MAX_PORT))

    def set_tcp_port(self, source, target=None):
        self.set_port(self.PROTO_TCP, source, target)

    def unset_port(self, protocol, source):
        self._raise_for_protocol(protocol)

        if not self.has_port(protocol, source):
            raise ValueError("Invalid port: {}".format(str(source)))

        del self[protocol][int(source)]

    def unset_tcp_port(self, source):
        self.unset_port(self.PROTO_TCP, source)

    def list_ports(self, protocol):
        self._raise_for_protocol(protocol)

        return self[protocol].keys()

    def list_tcp_ports(self):
        return self.list_ports(self.PROTO_TCP)

    def has_port(self, protocol, source):
        self._raise_for_protocol(protocol)

        if int(source) not in self.list_ports(protocol):
            return False

        return True

    def has_tcp_port(self, source):
        return self.has_port(self.PROTO_TCP, source)

    def get_port(self, protocol, source):
        if not self.has_port(protocol, source):
            raise ValueError("Port {} is not mapped".format(str(source)))

        return self[protocol][int(source)]

    def get_tcp_port(self, source):
        return self.get_port(self.PROTO_TCP, source)

    def get_protocols(self):
        return self.keys()


class PortMap(PortList):
    def set_port(self, protocol, source, target=None):
        self._raise_for_protocol(protocol)

        if not target:
            target = source

        # Check if there isn't map colision on right side
        for used_source, used_tport_set in self[protocol].items():
            if used_source != source and target in used_tport_set:
                raise PortCollisionException("Target port {} has been already mapped".format(target))

        if not self.has_port(protocol, source):
            # data = Set() ## not possible to serialize
            data = []
        else:
            data = self.get_port(protocol, source)

        # data.add(int(target))
        data.append(int(target))

        super(PortMap, self).set_port(protocol, source, data)


def map_ports(source_ports, target_ports, user_mapped_ports=None, user_excluded_ports=None):
    """
    :param source_ports:        ports found by the tool on source machine
    :param source_ports:        PortList
    :param target_ports:        ports found by the tool on target machine
    :param target_ports:        PortList
    :param user_mapped_ports:   port mapping defined by user
                                if empty, only the default mapping will aaplied

                                DEFAULT RE-MAP:
                                    22/tcp -> 9022/tcp
    :type user_mapped_ports:    PortMap
    :param user_excluded_ports: excluded port mapping defined by user
    :type user_excluded_ports:  PortList
    """

    user_mapped_ports = user_mapped_ports or PortMap()
    user_excluded_ports = user_excluded_ports or PortList()

    # TODO: change this to PortMap only
    """
        remapped_ports structure:
        {
            tcp: [
                [ exposed port on target, source_port ],
                .
                .
                .
            ]
            udp: [ ... ]
        }
    """
    # remapped_ports = {
    #     PortMap.PROTO_TCP: [],
    #     PortMap.PROTO_UDP: []
    # }
    remapped_ports = PortMap()

    # add user ports which was not discovered
    for protocol in user_mapped_ports.get_protocols():
        for port in user_mapped_ports.list_ports(protocol):
            for user_target_port in user_mapped_ports.get_port(protocol, port):
                if target_ports.has_port(protocol, user_target_port):
                    raise PortCollisionException("Specified mapping is in conflict with target "
                                                 "{} -> {}".format(port, user_target_port))

            # Add dummy port to sources
            if not source_ports.has_port(protocol, port):
                source_ports.set_port(protocol, port)

    # Static (default) mapping applied only when the source service is available
    if not user_mapped_ports.has_tcp_port(22):
        user_mapped_ports.set_tcp_port(22, 9022)

    print(str(user_excluded_ports))

    # remove unwanted ports
    for protocol in user_excluded_ports.get_protocols():
        for port in user_excluded_ports.list_ports(protocol):
            if source_ports.has_port(protocol, port):
                # remove port from sources
                source_ports.unset_port(protocol, port)

    # remap ports
    for protocol in source_ports.get_protocols():
        for port in source_ports.list_ports(protocol):
            source_port = port

            # remap port if user defined it
            if user_mapped_ports.has_port(protocol, port):
                user_mapped_target_ports = user_mapped_ports.get_port(protocol, port)
            else:
                user_mapped_target_ports = Set([port])

            for target_port in user_mapped_target_ports:
                while target_port <= PortList.MAX_PORT:
                    if target_ports.has_port(protocol, target_port):
                        if target_port == PortList.MAX_PORT:
                            raise PortCollisionException("Automatic port collision resolve failed, please use "
                                                         "--tcp-port SELECTED_TARGET_PORT:{} to solve the "
                                                         "issue".format(source_port))

                        target_port = target_port + 1
                    else:
                        break

                # add newly mapped port to target ports so we can track collisions
                target_ports.set_port(protocol, target_port)

                # create mapping array
                # remapped_ports[protocol].append((target_port, source_port))
                remapped_ports.set_port(protocol, source_port, target_port)

    return remapped_ports


if __name__ == '__main__':
    src = PortList()
    src.set_tcp_port("22", {"name": "ssh"})
    src.set_tcp_port("80", {"name": "httpd"})

    tgt = PortList()
    tgt.set_tcp_port("22", {"name": "ssh"})

    usr = PortMap()
    usr.set_tcp_port("80", "8080")
    usr.set_tcp_port("80", "80")

    print("usr")
    print(str(usr))

    print("mapping")
    result = map_ports(src, tgt, usr)

    print(dumps(result))
