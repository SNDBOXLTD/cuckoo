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
            self.debug = True
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

CONNECTIVITY_HEALTHCHECK_DOMAIN = 'sndbox.com'  # network check


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
            '23.194.117.4',  # adobe
            '72.21.91.29',  # don't know ...
            '192.88.99.1',
            '224.0.0.251',  # mDNS
            '104.70.70.251', '40.69.219.197', '40.79.65.237'  # win10 leftovers
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
            'symcd.com',  # DigiCert, Inc.
            # win10 below (https://docs.microsoft.com/en-gb/windows/privacy/windows-endpoints-1803-non-enterprise-editions)
            'msftconnecttest.com',
            'petra-pc.local',
            'cdn.onenote.net',
            'client.wns.windows.com',
            'update.microsoft.com',
            'www.microsoft.com',
            'sls.microsoft.com',
            'licensing.mp.microsoft.com',
            'delivery.mp.microsoft.com',
            'trafficshaping.dsp.mp.microsoft.com',
            'do.dsp.mp.microsoft.com',
            'settings-win.data.microsoft.com',
            'login.live.com',
            'tlu.dl.delivery.mp.microsoft.com',
            'arc.msn.com',
            'arc.msn.com.nsatc.net',
            'au.download.windowsupdate.com',
            'b.akamaiedge.net',
            'cdn.onenote.net',
            'client-office365-tas.msedge.net',
            'evoke-windowsservices-tas.msedge.net',
            'cloudtile.photos.microsoft.com.akadns.net',
            'config.edge.skype.com',
            'ctldl.windowsupdate.com',
            'cy2.displaycatalog.md.mp.microsoft.com.akadns.net',
            'cy2.licensing.md.mp.microsoft.com.akadns.net',
            'cy2.settings.data.microsoft.com.akadns.net',
            'displaycatalog.mp.microsoft.com',
            'dm3p.wns.notify.windows.com.akadns.net',
            'download.windowsupdate.com',
            'e-msedge.net',
            'emdl.ws.microsoft.com',
            'fe2.update.microsoft.com',
            'fe3.delivery.dsp.mp.microsoft.com.nsatc.net',
            'fe3.delivery.mp.microsoft.com',
            'flightingservicewus.cloudapp.net',
            'g.akamaiedge.net',
            'g.live.com',
            'g.msn.com.nsatc.net',
            'geo-prod.do.dsp.mp.microsoft.com',
            'geo-prod.dodsp.mp.microsoft.com.nsatc.net',
            'ip5.afdorigin-prod-am02.afdogw.com',
            'ipv4.login.msa.akadns6.net',
            'licensing.mp.microsoft.com',
            'location-inference-westus.cloudapp.net',
            'maps.windows.com',
            'modern.watson.data.microsoft.com.akadns.net',
            'ocos-office365-s2s.msedge.net',
            'ocsp.digicert.com',
            'oneclient.sfx.ms',
            'onecollector.cloudapp.aria.akadns.net',
            'prod.nexusrules.live.com.akadns.net',
            'query.prod.cms.rt.microsoft.com',
            'ris.api.iris.microsoft.com',
            'ris.api.iris.microsoft.com.akadns.net',
            's-msedge.net',
            'msedge.net',
            'm1-msedge.net',
            'settings-win.data.microsoft.com',
            'settings.data.microsoft.com',
            'share.microsoft.com',
            'sls.update.microsoft.com',
            'storecatalogrevocation.storequality.microsoft.com',
            'storeedgefd.dsx.mp.microsoft.com',
            'telecommand.telemetry.microsoft.com.akadns.net',
            'tile-service.weather.microsoft.com',
            'tlu.dl.delivery.mp.microsoft.com',
            'tsfe.trafficshaping.dsp.mp.microsoft.com',
            'us.configsvc1.live.com.akadns.net',
            'vip5.afdorigin-prod-am02.afdogw.com',
            'vip5.afdorigin-prod-ch02.afdogw.com',
            'watson.telemetry.microsoft.com',
            'wd-prod-cp-us-east-2-fe.eastus.cloudapp.azure.com',
            'wd-prod-cp-us-west-3-fe.westus.cloudapp.azure.com',
            'windowsupdate.com',
            'www.bing.com',
            'www.office.com',  # office
            'office14client.microsoft.com',
            'office.microsoft.com',
            'eusofficehome.msocdn.com',
            'self.events.data.microsoft.com',
            'browser.pipe.aria.microsoft.com',
            'watson.microsoft.com',
            'go.microsoft.com',
            'dmd.metaservices.microsoft.com'
        ])

        self.netbios_ignore_list = set(
            ['petra-pc', 'workgroup', 'msbrowse', 'isatap', 'wpad', 'petra-pc.local'])

        self.network_check_to_see = 2  # count request and response

    def run(self):
        if not os.path.exists(self.pcap_path):
            log.warning("The PCAP file does not exist at path \"%s\".", self.pcap_path)

        if not os.path.getsize(self.pcap_path):
            log.error("The PCAP file at path \"%s\" is empty." % self.pcap_path)

        start_time = time.time()
        try:
            pkts = rdpcap(self.pcap_path)
            filtered = filter(lambda pkt: not self._should_filter(pkt), pkts)
            self._write_pcap(filtered)
            log.info("Filtered %d packets, ignored: (%d,%d), elapsed time:%s",
                     len(pkts) - len(filtered),
                     len(self.host_ignore_list),
                     len(self.dns_ignore_list),
                     time.time() - start_time)
        except:
            log.exception('failed to filter pcap file')

    def _should_ignore_network_check(self, req_name):
        """Check if dns request to verify network should be ignored. """
        return self.network_check_to_see and (req_name and (req_name.lower() == CONNECTIVITY_HEALTHCHECK_DOMAIN or _domain(req_name.lower()) == CONNECTIVITY_HEALTHCHECK_DOMAIN))

    def _should_ignore_req_name(self, req_name):
        """Check if dns request (host) should be ignored 
        Also check the domain of the host

        Arguments:
            req_name {string} -- dns request name

        Returns:
            bool -- true if ignorable
        """

        return req_name and (req_name.lower() in self.dns_ignore_list or
                             _domain(req_name.lower()) in self.dns_ignore_list)

    def _extract_dns_response(self, dns_response_count, dns_response_list):
        """Extract dns response name/hosts

        Arguments:
            dns_response_count {integer} -- DNS answer count (default is 0)
            dns_response_list {list} -- DNS answer list (default is null)

        Returns:
            set() -- dns names, e.g. [host.xyz, host.com]
            set() -- dns hosts, e.g. [1.1.1.1, 2.2.2.2]
        """

        res_names = set()
        res_hosts = set()
        for i in range(dns_response_count):
            an = dns_response_list[i]
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
                req_name = None
                if p.qdcount > 0 and isinstance(p.qd, DNSQR):
                    req_name = p.qd.qname[:-1]  # remove dot

                # extract dns response
                res_names, res_hosts = self._extract_dns_response(p.ancount, p.an)

                if self._should_ignore_req_name(req_name):
                    self.dns_ignore_list.update(res_names)
                    self.host_ignore_list.update(res_hosts)
                    return True

                if self._should_ignore_network_check(req_name):
                    self.network_check_to_see -= 1
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

        except:
            log.exception("Failed to parse packet: %s", repr(p))

        return False

    def _write_pcap(self, filtered):
        # write the filtered packets to file
        file_path = self.pcap_path if not hasattr(self, 'debug') else self.pcap_path + '_filtered'
        wrpcap(file_path, filtered)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    pcap_path = '/Users/tomerf/Downloads/d8adf71838bcd6989901e50f5809378b_ping.pcap'
    pf = PcapFilter(pcap_path)
    pf.run()
