from six import string_types
import sys
import socket
import struct
import json
import datetime
import socket

class XiaomiConnector:
    """Connector for the Xiaomi Mi Hub and devices on multicast."""

    MULTICAST_PORT = 9898
    SERVER_PORT = 4321

    MULTICAST_ADDRESS = '224.0.0.50'
    SOCKET_BUFSIZE = 1024

    def __init__(self, data_callback=None, auto_discover=True, debug_mode=0, log_callback=None):
        """Initialize the connector."""
        self.debug_mode = debug_mode
        self.log_callback = log_callback
        self.data_callback = data_callback
        self.last_tokens = dict()
        self.socket = self._prepare_socket()
        self.nodes = dict()
        self.gnodes = dict()
        self.gateways = set()
        self.send_whois()

    def log(self, *args):
        if self.log_callback is not None:
            self.log_callback(*args)
        else:
            d = datetime.datetime.now()
            print(d.strftime("%Y-%m-%d %H:%M:%S"), *args)
        return

    def _prepare_socket(self):
        sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP

        sock.bind(("0.0.0.0", self.MULTICAST_PORT))

        mreq = struct.pack("=4sl", socket.inet_aton(self.MULTICAST_ADDRESS),
                           socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                        self.SOCKET_BUFSIZE)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        return sock
    def check_incoming(self):
        """Check incoming data."""
        data, addr = self.socket.recvfrom(self.SOCKET_BUFSIZE)
        try:
            payload = json.loads(data.decode("utf-8"))
            if self.debug_mode > 1:
                self.log(addr, ":", payload)
            self.gateway_address = addr[0]
            self.handle_incoming_data(payload)

        except Exception as e:
            raise
            self.log("Can't handle message %r (%r)" % (data, e))

    def handle_incoming_data(self, payload):
        """Handle an incoming payload, save related data if needed,
        and use the callback if there is one.
        """
        if isinstance(payload.get('data', None), string_types):
            cmd = payload["cmd"]

            if cmd in ["heartbeat", "report", "read_ack"]:
                if self.data_callback is not None:
                    try:
                        self.data_callback(payload["model"],
                                           payload["sid"],
                                           payload["cmd"],
                                           json.loads(payload["data"]))
                    except KeyError as e:
                        self.log("KeyError", e)



            if cmd == "heartbeat" and payload["sid"] not in self.nodes:
                #self.request_sids(payload["sid"])
                self.nodes[payload["sid"]] = json.loads(payload["data"])
                self.nodes[payload["sid"]]["model"] = payload["model"]
                self.nodes[payload["sid"]]["sensors"] = []
                self.nodes[payload["sid"]]["gateway_address"] = self.gateway_address

        if "token" in payload:
            self.last_tokens[payload["sid"]] = payload['token']

    def request_sids(self, sid, ip):
        """Request System Ids from the hub."""
        self.send_command({"cmd": "get_id_list", sid: sid}, ip)

    def request_current_status(self, device_sid, ip):
        """Request (read) the current status of the given device sid."""
        self.send_command({"cmd": "read", "sid": device_sid}, ip)

    def send_command(self, data, addr = MULTICAST_ADDRESS, port=MULTICAST_PORT):
        """Send a command to the UDP subject (all related will answer)."""
        #self.socket.sendto(json.dumps(data).encode("utf-8"), (addr, self.MULTICAST_PORT))
        if type(data) is dict:
            self.socket.sendto(json.dumps(data).encode("utf-8"), (addr, port))
            if self.debug_mode > 1:
                self.log("SEND dATA:", json.dumps(data).encode("utf-8"))
        else:
            self.socket.sendto(data.encode("utf-8"), (addr, port))
            if self.debug_mode > 1:
                self.log("SEND dATA:", data.encode("utf-8"))
    def get_nodes(self):
        """Return the current discovered node configuration."""
        return self.nodes
    def get_token(self):
        return self.last_tokens

    def send_whois(self):
        self.socket.sendto(json.dumps({"cmd":"whois"}).encode("utf-8"),
                           (self.MULTICAST_ADDRESS, self.SERVER_PORT))

        endTime = datetime.datetime.now() + datetime.timedelta(seconds=5)
        self.log("Waiting for Whois replies (5s) ...")
        while datetime.datetime.now() <= endTime:

            data, addr = self.socket.recvfrom(self.SOCKET_BUFSIZE)
            try:
                payload = json.loads(data.decode("utf-8"))
                #self.gateways.add(addr[0])

                #self.gateway_address = addr[0]

            except Exception as e:
                raise
                self.log("Can't handle message %r (%r)" % (data, e))

            if payload["cmd"] == 'iam':
                cmd = payload["cmd"]

                if cmd == 'iam' and payload["sid"] not in self.nodes:
                    if self.debug_mode > 0:
                        self.log(addr, ":", payload)
                    #self.gateways.add(payload["ip"])
                    self.gnodes[payload["sid"]] = dict(model="gateway")
                    self.gnodes[payload["sid"]]['ip'] = payload["ip"]
                    #self.request_sids(payload["sid"])


        for sid in self.gnodes:
            gateway_ip = self.gnodes[sid]['ip']
            self.request_sids(payload["sid"], gateway_ip)

            endTime = datetime.datetime.now() + datetime.timedelta(seconds=2)
            self.log("Waiting for login replies (2s) ...")
            while datetime.datetime.now() <= endTime:
                data, addr = self.socket.recvfrom(self.SOCKET_BUFSIZE)
                try:
                    payload = json.loads(data.decode("utf-8"))
                    if self.debug_mode > 1:
                        self.log(addr, ":", payload)
                except Exception as e:
                    raise
                    self.log("Can't handle message %r (%r)" % (data, e))

                cmd = payload["cmd"]
                if cmd == "get_id_list_ack" and payload["sid"] == sid:

                    device_sids = json.loads(payload["data"])

                    if payload["sid"] not in self.gnodes:
                        pass
                        #self.nodes[payload["sid"]] = dict(model=u'gateway')
                    else:
                        self.gnodes[payload["sid"]]["nodes"] = device_sids

                    if "token" in payload:
                        self.last_tokens[payload["sid"]] = payload['token']

                    if self.debug_mode > 0:
                        self.log(addr, ":", payload)
                    if self.debug_mode > 1:
                        self.log("NODES:", self.gnodes)
                    break

        for sid in self.gnodes:
            if self.gnodes[sid]['model'] == 'gateway':
                for sub_node in self.gnodes[sid]['nodes']:
                    if self.debug_mode > 1:
                        self.log(sid, self.nodes[sid]['ip'])
                    self.request_current_status(sub_node, self.gnodes[sid]['ip'])

                    endTime = datetime.datetime.now() + datetime.timedelta(seconds=2)
                    if self.debug_mode > 1:
                        self.log("Waiting for reply from ", sub_node)
                    while datetime.datetime.now() <= endTime:
                        data, addr = self.socket.recvfrom(self.SOCKET_BUFSIZE)
                        try:
                            payload = json.loads(data.decode("utf-8"))
                            if self.debug_mode > 1:
                                self.log(addr, ":", payload)
                        except Exception as e:
                            raise
                            self.log("Can't handle message %r (%r)" % (data, e))

                        cmd = payload["cmd"]

                        if cmd == "read_ack" and payload["sid"] not in self.nodes and sub_node == payload["sid"]:
                            try:
                                self.nodes[payload["sid"]] = dict(model=payload["model"])
                                self.nodes[payload["sid"]]["gateway_address"] = self.gnodes[sid]['ip']
                                self.nodes[payload["sid"]]["gateway_sid"] = sid
                            except KeyError as e:
                                self.log("KeyError", e)
                            self.log("Connected:", addr)
                            if self.debug_mode > 0:
                                self.log(addr, ":", payload)
                            if self.debug_mode > 1:
                                self.log("NODES:", len(self.nodes), self.nodes)
                            break
        self.nodes.update(self.gnodes)
        #print("Final:", len(self.nodes))
        #for i in self.nodes:
        #	print(i, self.nodes[i])