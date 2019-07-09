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

    @staticmethod
    def has_crash_process(processes):
        """
        Check if a process that is related to a crash is found in a list of processes
        :param processes: list of processes
        :return: boolean indicating whether a crash process was found
        """
        process_paths = (
            '\\Device\\HarddiskVolume2\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\dw20.exe',
            '\\Device\\HarddiskVolume2\\Program Files\\Common Files\\microsoft shared\\DW\\DW20.EXE',
            '\\Device\\HarddiskVolume2\\Windows\\x86_netfx-dw-b03f5f711d50a3a_6.1.7600.16385_none_a223bd3dd785391a\\dw20.exe',
            '\\Device\\HarddiskVolume2\\Windows\\System32\\WerFault.exe',
            '\\Device\\HarddiskVolume2\\Windows\\System32\\wermgr.exe'
        )
        found_processes = filter(lambda p: p["process_path"] in process_paths, processes)
        return len(found_processes) > 0

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

        debug = results['debug']
        custom = json.loads(results['info']['custom'])
        sample = custom["sample"]
        is_office_package = self.task.get("package") in ['xls', 'doc', 'ppt']

        process_error = self.has_process_error(debug)
        has_no_behavior = debug['errors'] or not results.get("behavior", False)
        has_crash_process = self.has_crash_process(results["behavior"]["processes"]) and not custom["soon_to_retire"]

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


        if has_no_behavior and not is_office_package:
            # don't remove from the queue, retries might be
            # helpful here since this might be an issue with this host only.
            logger.warning("No behavior was found")
            results["reporting_status"] = "nobehavior"
            return

        if has_crash_process and not is_office_package:
            # in case we have a crash process and this sample is scheduled to have more retries, we should
            # run it again, this handles case where VMs sometimes perform poorly under heavy load
            logger.warning("Detected crash process")
            results["reporting_status"] = "crash"
            return

        if (has_no_behavior or has_crash_process) and is_office_package:
            logger.warning("ignored a detected crash, package is office")

        self.send_success_notification(results["s3"], sample)
        self._sqs.delete_message(QueueUrl=custom['source_queue'], ReceiptHandle=custom['receipt_handle'])
        results["reporting_status"] = "completed"
