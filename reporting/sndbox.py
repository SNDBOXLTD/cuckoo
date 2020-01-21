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
import re

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
    def init_once(cls):
        cls._sns = boto3.client("sns")
        cls._sqs = boto3.client('sqs')

    def send_success_notification(self, gcs, sample, trace):
        """
        sends an SNS notification, along with the
        Args:
            gcs: the location of the uploaded gzipped report on gcs
            sample: the sample JSON properties, was sent original from the web backend
            trace: trace context of the Cuckoo span

        Returns:
            None
        """
        sample["trace"] = trace

        message = {
            "sample": sample,
            "payload": gcs
        }

        self._sns.publish(
            TopicArn=self.options.completed_sns_arn,
            Message=json.dumps(message)
        )

    def send_failure_notification(self, sample, logs, message=None):
        """
        Sends an analysis failure notification to indicate that something
        is wrong with an analysis

        :param sample: sample dict
        :param logs: logs to be saved internally
        :param message: user-friendly message to be displayed in the user interface
        :return:
        """
        self._sns.publish(
            TopicArn=self.options.failed_sns_arn,
            Message=json.dumps({
                "where": "dynamic",
                "sample": sample,
                "message": message,
                "logs": logs
            })

        )

    @staticmethod
    def has_process_error(debug):
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

        if "gcs" not in results:
            logger.critical("gcs upload was not successful, aborting")
            return

        debug = results['debug']
        custom = json.loads(results['info']['custom'])
        sample = custom["sample"]
        has_no_behavior = not results.get("behavior", False)
        process_error = self.has_process_error(debug)

        if process_error:
            logger.warning("First process related error was found")
            results["reporting_status"] = "processerror"

            # this will occur on all VMs, no point in retrying
            self._sqs.delete_message(QueueUrl=custom['source_queue'], ReceiptHandle=custom['receipt_handle'])

            self.send_failure_notification(
                sample,
                debug,
                process_error  # pass the error to the user
            )
            return

        if debug['errors'] or has_no_behavior:
            # don't remove from the queue, retries might be
            # helpful here since this might be an issue with this host only.
            logger.error("No behavior was found")
            results["reporting_status"] = "nobehavior"
            # change message visibility to 0 in order for another consumer to immediately pull it
            self._sqs.change_message_visibility(QueueUrl=custom['source_queue'], ReceiptHandle=custom['receipt_handle'], VisibilityTimeout=0)
            return

        self.send_success_notification(results["gcs"], sample, custom.get('trace'))
        self._sqs.delete_message(QueueUrl=custom['source_queue'], ReceiptHandle=custom['receipt_handle'])
        results["reporting_status"] = "completed"
