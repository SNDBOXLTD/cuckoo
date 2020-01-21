"""
Module Name:    gcs.py
Purpose:        Saves the PCAP and the report to gcs
Author:         Itay Huri
Date:           18/09/2017
"""

from cuckoo.common.abstracts import Report
import os
import json
import gzip
import logging
from google.cloud import storage

log = logging.getLogger(__name__)

gcs = storage.Client()


class GCS(Report):
    """
    Responsible to export the results to GCS
    """

    order = 2

    def gzip_report(self, name):
        """
        GZIPs the report, saves it into a temp location
        :param name: desired GZIP file name
        :return: the location of the GZIP file
        """
        report_path = os.path.join(self.reports_path, "report.json")
        if not os.path.isfile(report_path):
            log.critical("Report file %s is missing" % report_path)

        gzipped_report_path = os.path.join(self.reports_path, name + ".gz")
        with open(report_path, "r") as report:
            with gzip.open(gzipped_report_path, "wb") as gz:
                gz.write(report.read())
        return gzipped_report_path

    def upload_report(self, report_path, name):
        """
        uploads the gzipped report to gcs, into a temp directory,
        this is the report expected to be read by the ML processor.
        this is NOT the final report.
        :param report_path: local location of the gzipped report
        :param name: name of the gzip file
        :return: gcs path the file was saved in
        """
        if not os.path.isfile(report_path):
            log.critical("Report GZIP File %s is missing" % report_path)
            return

        gcs_report_path = os.path.join("dynamic_tmp/", name + ".json.gz")
        blob = self._bucket.blob(gcs_report_path)
        blob.upload_from_filename(report_path)

        return gcs_report_path

    def upload_pcap(self, pcap_path, gcs_path, name):
        """
        uploads PCAP file to gcs
        :param pcap_path: the location of the PCAP file locally
        :param gcs_path: the gcs path the PCAP needs to
                be saved in, changes frequently due to Ran's needs
        :param name: the PCAP filename
        :return: gcs path the file was saved in
        """
        if not os.path.isfile(pcap_path):
            log.critical("PCAP File %s is missing" % pcap_path)

        save_in = gcs_path + "/pcaps/" + name + ".pcap"
        blob = self._bucket.blob(save_in)
        blob.upload_from_filename(pcap_path)
        return save_in

    def upload_dropped(self, dropped_files, gcs_path, gcs_key):
        for dropped in dropped_files:
            path = dropped["path"]
            if not os.path.isfile(path):
                log.warning("dropped file at {} was not found".format(path))
                continue

            save_in = "{base}/dropped_files/{key}/{sha256}".format(base=gcs_path, key=gcs_key, sha256=dropped["sha256"])
            blob = self._bucket.blob(save_in)
            blob.metadata = {"original_name": dropped["name"]}
            blob.upload_from_filename(path)

    def run(self, results):
        """
        Exports the PCAP and the gzipped version of the report file to gcs
        along with its original filename
        :param results: the full report
        """
        self._bucket = gcs.get_bucket(self.options.bucket)

        sample = json.loads(results["info"]["custom"])["sample"]

        pcap_path = os.path.join(self.analysis_path, "dump.pcap")

        self.upload_pcap(pcap_path, sample["gcp_path"], sample["gcp_key"])

        if results.get("dropped"):
            self.upload_dropped(results["dropped"], sample["gcp_path"], sample["gcp_key"])

        gzipped_report_path = self.gzip_report(sample["gcp_key"])
        if gzipped_report_path:
            gcs_report_path = self.upload_report(gzipped_report_path, sample["gcp_key"])
            results["gcs"] = {
                "gcs_bucket": self.options.bucket,
                "gcs_key": gcs_report_path
            }
