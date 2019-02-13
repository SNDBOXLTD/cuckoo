import logging
import re
import os
from scapy.all import *
conf.verbose = 0  # ask Scapy to be quiet

log = logging.getLogger(__name__)

try:
    from cuckoo.common.abstracts import Processing
except ImportError:
    # init standalone processing
    class Processing(object):
        def __init__(self, pcap_path):
            self.pcap_path = pcap_path

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

    def __init__(self, *args, **kwargs):
        super(PcapFilter, self).__init__(*args, **kwargs)

        # The above sets represent unique blacklisted values
        # For performance, and duplication handling we use set() data type
        self.host_ignore_list = set([
            '52.179.17.38',  # microsoft ntp server
            '23.217.129.17',  # microsoft ncsi server
            '192.88.99.1'
        ])

        self.dns_ignore_list = set([
            'petra-pc',
            'isatap',
            'wpad',
            'time.windows.com',
            'teredo.ipv6.microsoft.com',
            'msftncsi.com',
            '6to4.ipv6.microsoft.com',
            'windowsupdate.com',
            'oracle.com',
            'sun.com',
            'status.geotrust.com',
            'googleapis.com',
            'adobe.com',
            'digicert.com',
            'symcb.com',  # DigiCert, Inc.
            'symcd.com'  # DigiCert, Inc.
        ])

        self.netbios_ignore_list = set(
            ['petra-pc', 'workgroup', 'msbrowse', 'isatap', 'wpad'])

    def run(self):
        if not os.path.exists(self.pcap_path):
            log.warning("The PCAP file does not exist at path \"%s\".",
                        self.pcap_path)

        if not os.path.getsize(self.pcap_path):
            log.error("The PCAP file at path \"%s\" is empty." %
                      self.pcap_path)

        start_time = time.time()
        try:
            pkts = rdpcap(self.pcap_path)
            filtered = filter(lambda pkt: not self._should_filter(pkt), pkts)
            # write the filtered packets to file
            wrpcap(self.pcap_path, filtered)
            log.info("Filtered %d packets, ignored: (%d,%d), elapsed time:%s",
                     len(pkts) - len(filtered),
                     len(self.host_ignore_list),
                     len(self.dns_ignore_list),
                     time.time() - start_time)
        except Exception as e:
            print "error %s" % e
            log.info('failed to filter pcap file. Error: %s', e)

    def _ignore_req_name(self, req_name):
        return req_name and (req_name.lower() in self.dns_ignore_list or
                             _domain(req_name.lower()) in self.dns_ignore_list)

    def _extract_res(self, p):
        res_names = set()
        res_hosts = set()
        if p.ancount > 0 and isinstance(p.an, DNSRR):
            for i in range(p.ancount):
                an = p.an[i]
                rdata = an.rdata
                if rdata[-1] == ".":
                    res_names.add(rdata[:-1])
                else:
                    res_hosts.add(rdata)
        return res_names, res_hosts

    def _should_filter(self, p):
        """Filter vm network (dns, netbios, ssdp) traffic
        """
        try:
            if p.haslayer(DNS) or p.haslayer(LLMNRQuery):
                req_name = res_name = res_host = None
                if p.qdcount > 0 and isinstance(p.qd, DNSQR):
                    req_name = p.qd.qname[:-1]  # remove dot

                # extract response
                res_names, res_hosts = self._extract_res(p)

                if self._ignore_req_name(req_name):
                    if res_names:
                        self.dns_ignore_list |= res_names
                    if res_hosts:
                        self.host_ignore_list |= res_hosts
                    return True

            if p.haslayer(NBNSQueryRequest) or p.haslayer(NBNSRequest):
                name = _strip_name(p.QUESTION_NAME)
                return name in self.netbios_ignore_list

            if p.haslayer(NBTDatagram):
                name = _strip_name(p.DestinationName)
                return name in self.netbios_ignore_list

            if p.haslayer(IP):
                if p[IP].dst in self.host_ignore_list or p[IP].src in self.host_ignore_list:
                    return True

            if p.haslayer(Raw) and len(p[Raw].load) > 0:
                if p[Raw].load == SSDP_PAYLOAD or p[Raw].load == SSDP_PAYLOAD_TYPE2:
                    return True

        except Exception as e:
            log.error("Failed to parse packet: %s, with error %s", repr(p), e)

        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    pcap_path = '/Users/tomerf/Downloads/e79e313dbd77727af748bae42926b065.pcap'
    pf = PcapFilter(pcap_path)
    pf.run()
