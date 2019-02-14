"""
Module Name:    cleanup.py
Purpose:        Wipes the output folder after an analysis is finished
Author:         Itay Huri
Date:           18/11/2017
"""

from cuckoo.common.abstracts import Report
import os


class Cleanup(Report):
    order = 4

    @staticmethod
    def list_files(directory):
        """
        Gets all files in a given directory
        Args:
            directory:
                The directory

        Returns:
            List of all files found
        """
        for root, dirs, files in os.walk(directory):
            for name in files:
                yield os.path.join(root, name)

    def run(self, results):
        """
        Deletes the entire analysis folder including the binary
        Args:
            results: dict
                the full report

        Returns:
            None
        """
        if self.analysis_path:
            files_to_keep = ["cuckoo.log", "task_summary.json"]

            for f in self.list_files(self.analysis_path):
                if f.rsplit("/", 1)[1] not in files_to_keep:
                    os.remove(f)

        if results["target"]["file"]["path"]:
            os.remove(results["target"]["file"]["path"])
