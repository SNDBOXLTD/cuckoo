import logging
import re
import os
from scapy.all import *

log = logging.getLogger(__name__)

from cuckoo.common.abstracts import Processing

HOST_IGNORE_LIST =  [
    '52.179.17.38', # microsoft ntp server
    '192.88.99.1'
]

DNS_IGNORE_LIST = [
    'jack-pc',
    'isatap',
    'wpad',
    'time.windows.com',
    'teredo.ipv6.microsoft.com',
    'dns.msftncsi.com' ,
    '6to4.ipv6.microsoft.com',
    'oracle.com',
    'sun.com',
    'status.geotrust.com',
    'gvt1.com',
    'googleapis.com',
    'adobe.com',
    'symcb.com', # DigiCert, Inc.
    'symcd.com' # DigiCert, Inc.
]

NETBIOS_IGNORE_LIST = ['jack-pc', 'workgroup', 'msbrowse', 'isatap', 'wpad']

SSDP_PAYLOAD = "M-SEARCH * HTTP/1.1\r\n" \
"HOST:239.255.255.250:1900\r\n" \
"ST:upnp:rootdevice\r\n" \
"MAN: \"ssdp:discover\"\r\n" \
"MX:2\r\n\r\n"

SSDP_PAYLOAD_TYPE2 = "M-SEARCH * HTTP/1.1\r\n" \
"Host:239.255.255.250:1900\r\n" \
"ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" \
"Man:\"ssdp:discover\"\r\n" \
"MX:3\r\n\r\n"

def _strip_name(name):
    """strip non characters and return as lowercase
    """
    return " ".join(re.findall("[a-zA-Z-]+", name)).strip().lower()

def _domain(host):
    return ".".join(host.split(".")[1:])

class PcapFilter(Processing):
    """Filter pcap file against blacklisted vm communication.
    """
    key = "pcap_filter"

    def run(self):
        if not os.path.exists(self.pcap_path):
            log.warning("The PCAP file does not exist at path \"%s\".",
                        self.pcap_path)

        if not os.path.getsize(self.pcap_path):
            log.error("The PCAP file at path \"%s\" is empty." % self.pcap_path)

        try:
            pkts = rdpcap(self.pcap_path)
            filtered = [pkt for pkt in pkts if not self._should_filter(pkt)]
            wrpcap(self.pcap_path, filtered) # write the filtered packets to file
        except Exception as e:
            print "error %s" % e
            log.info('failed to filter pcap file. Error: %s', e)

    def _should_filter(self, p):
        """Filter vm network (dns, netbios, ssdp) traffic
        """
        try:
            if p.haslayer(DNS) or p.haslayer(LLMNRQuery):
                name = ''
                if p.qdcount > 0 and isinstance(p.qd, DNSQR):
                    name = p.qd.qname[:-1] # remove dot

                # save response host/domain
                if p.ancount > 0 and isinstance(p.an, DNSRR):
                    for i in range(p.ancount):
                        an = p.an[i]
                        rdata = an.rdata
                        if rdata[-1] == ".":
                            name = rdata[:-1]
                            DNS_IGNORE_LIST.append(name)
                        else:
                            HOST_IGNORE_LIST.append(rdata)

                return name.lower() in DNS_IGNORE_LIST or \
                    _domain(name.lower()) in DNS_IGNORE_LIST

            if p.haslayer(NBNSQueryRequest) or p.haslayer(NBNSRequest):
                name = _strip_name(p.QUESTION_NAME)
                return name in NETBIOS_IGNORE_LIST

            if p.haslayer(NBTDatagram):
                name = _strip_name(p.DestinationName)
                return name in NETBIOS_IGNORE_LIST

            if p.haslayer(IP):
                if p[IP].dst in HOST_IGNORE_LIST or p[IP].src in HOST_IGNORE_LIST:
                    return True

            if p.haslayer(Raw) and len(p[Raw].load) > 0:
                if p[Raw].load == SSDP_PAYLOAD or p[Raw].load == SSDP_PAYLOAD_TYPE2:
                    return True

        except Exception as e:
            log.error("Failed to parse packet: %s, with error %s", repr(p), e)

        return False

