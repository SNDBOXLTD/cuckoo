"""
Module Name:    sns.py
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

    def remove_from_queue(self, receipt_handle):
        """
        Removes a message from the SQS queue given a receipt handle
        Args:
            receipt_handle: str
                The receipt_handle of the sample

        Returns:
            None
        """
        self._sqs.delete_message(
            QueueUrl=self.options.sqs_uri,
            ReceiptHandle=receipt_handle
        )

    def send_success_notification(self, s3, sample):
        """
        sends an SNS notification, along with the
        Args:
            s3: the location of the uploaded gzipped report on s3
            sample: the sample JSON properties, was sent original from the web backend

        Returns:
            None
        """
        message = {
            "sample": sample,
            "payload": s3
        }

        self._sns.publish(
            TopicArn=self.options.completed_sns_arn,
            Message=json.dumps(message)
        )

    def send_failure_notification(self, sample, logs, message=""):
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
        logs = debug.log
        error_pattern = re.compile(r"^error: \(\d+, 'CreateProcess', '(.*)'")

        for log in logs:
            match = error_pattern.match(log)
            if match:
                return match


    @staticmethod
    def has_cuckoo_errors(debug):
        """
        Checks if there were any cuckoo host/vm specific errors

        :param debug: the debug object
        :return: whether or not errors were found
        """
        return not debug.errors

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

        if "s3" not in results:
            logger.critical("S3 upload was not successful, aborting")
            return

        debug = results.debug
        sample = json.loads(results['info']['custom'])

        process_error = self.has_process_errors(debug)
        cuckoo_error = self.has_cuckoo_error(debug)

        if process_error:
            self.remove_from_queue(sample['receipt_handle'])

            self.send_failure_notification(
                sample,
                results.debug,
                process_error  # pass the error to the user
            )

        elif cuckoo_error or not results.behavior:
            # don't remove from the queue, retries might be
            # helpful here since this might be an issue with this host only.
            self.send_failure_notification(
                sample,
                debug
            )

        else:
            self.send_success_notification(results["s3"], sample)
            self.remove_from_queue(sample['receipt_handle'])
