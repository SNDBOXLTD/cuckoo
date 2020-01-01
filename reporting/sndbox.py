"""
Module Name:    sandbox.py
Purpose:        Removes the sample from the SQS queue and reports back to SNS
Author:         Itay Huri
Date:           12/09/2017
"""

from cuckoo.common.abstracts import Report
import json
import calendar
import datetime
import boto3
import logging
import requests
import re
import pika

logger = logging.getLogger(__name__)


def default(obj):
    """
    JSON serializer for objects not serializable by default json loads.
    Replaces datetime attributes with a serializable timestamp
    Args:
        obj: dict
            the BSON report object

    Returns:
        The timestamp
    """
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)


class Sndbox(Report):
    """
    Responsible for reporting about analysis completion or failure back to
    Sndbox's services
    """
    order = 3

    @classmethod
    def init_once(self):
        logging.info("init_once")
        self.init = False

    def _setup(self):
        if not self.init:
            connection = pika.BlockingConnection(pika.URLParameters(self.options.get('amqp_endpoint')))
            self._channel = connection.channel()

            self.init = True

    def _send_reporting_status_notification(self, analysis_id, to, success):
        """
        Notifies about the status of the reporting process to the consumer component.

        :param analysis_id: string, uuid
        :param to: string, consumer's RPC queue
        :param success: boolean, whether the reporting process is successful
        :return: None
        """
        message = {"success": success, "analysis_id": analysis_id}
        self._channel.basic_publish(exchange='',
                                    routing_key=to,
                                    body=json.dumps(message))

    def _send_success_notification(self, s3, sample):
        """
        sends an SNS notification, along with the
        Args:
            s3: the location of the uploaded gzipped report on s3
            sample: the sample JSON properties, was sent original from the web backend
            trace: trace context of the Cuckoo span

        Returns:
            None
        """
        data = {
            "sample": sample,
            "payload": s3
        }

        requests.post(self.options.get('sndbox_api', None) + '/onprem/complete', json=data)

    @staticmethod
    def _has_process_error(debug):
        """
        Checks if there were any CreateProcess errors that's worth showing
        to the end user, for example, if the sample is not a valid PE x32

        :param debug: the debug object
        :return: the error, if found
        """
        logs = debug['log']
        error_pattern = re.compile(r"error: \(\d+, 'CreateProcessW', '(.*)'")

        for log in logs:
            match = error_pattern.search(log)
            if match:
                return match.group(1)  # returns the first group

    def run(self, results):
        """
        Notifies about a successful/unsuccessful analysis.
        If the analysis completed successfully, remove it from the SQS queue
        and send a completion notification.

        If there was a process error, remove it from the queue as it's not worth
        retrying (the sample is the issue) and send a failure notification

        :param results: cuckoo results
        :return:
        """
        self._setup()

        if "s3" not in results:
            logger.critical("S3 upload was not successful, aborting")
            return

        debug = results['debug']
        custom_payload = json.loads(results['info']['custom'])
        sample = custom_payload["sample"]

        has_no_behavior = not results.get("behavior", False)
        process_error = self._has_process_error(debug)

        if process_error:
            logger.warning("First process related error was found")
            return self._send_reporting_status_notification(sample["id"], custom_payload["reply_to"], success=False)

        if debug['errors'] or has_no_behavior:
            # don't remove from the queue, retries might be
            # helpful here since this might be an issue with this host only.
            logger.warning("No behavior was found")
            return self._send_reporting_status_notification(sample["id"], custom_payload["reply_to"], success=False)

        self._send_success_notification(results["s3"], sample)
        self._send_reporting_status_notification(sample["id"], custom_payload["reply_to"], success=True)
