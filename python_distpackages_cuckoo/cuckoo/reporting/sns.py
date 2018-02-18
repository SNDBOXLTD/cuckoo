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


class SNS(Report):
    """
    Responsible for sending the final report back to the SNS consumers
    """
    order = 3

    def ack(self, receipt_handle):
        """
        Removes a message from the SQS queue given a receipt handle
        Args:
            receipt_handle: str
                The receipt_handle of the sample

        Returns:
            None
        """
        sqs = boto3.client('sqs')
        sqs.delete_message(QueueUrl=self.options.sqs_uri, ReceiptHandle=receipt_handle)

    def publish(self, s3, sample):
        """
        sends an SNS notification, along with the
        Args:
            s3: the location of the uploaded gzipped report on s3
            sample: the sample JSON properties, was sent original from the web backend

        Returns:
            None
        """
        client = boto3.client("sns")
        message = {
            "db_id": sample["id"],
            "sample": sample,
            "s3_bucket": s3["s3_bucket"],
            "s3_key": s3["s3_key"]
        }

        client.publish(
            TopicArn=self.options.sns_arn,
            Message=json.dumps(message)
        )

    def run(self, results):
        """
        If sample analysis was completed successfully, send an SNS notification, notifying that
        that cuckoo analysis was complete, and marks the sample as complete
        Args:
            results: dict
                the full report dict
        Returns:

        """

        custom = json.loads(results['info']['custom'])

        if "s3" in results:
            self.publish(results["s3"], custom)
            self.ack(custom['receipt_handle'])
