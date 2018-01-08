# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
from cuckoo.common.abstracts import Signature
from itertools import groupby

log = logging.getLogger(__name__)


class ProcessHollowing(Signature):
    id = 2
    name = "process_hollowing"
    description = "Identifies process hollowing injection"
    severity = 5
    categories = ["Injection"]
    authors = ["Itay Huri"]
    minimum = "2.0"
    enabled = True
    process_relationship = True

    matches = [
        ["ZwCreateUserProcess", "ZwUnmapViewOfSection"],
        ["ZwCreateUserProcess", "ZwCreateRemoteThread|ZwSetContextThread"]
    ]

    def init(self):
        self.handle_uses = {}

    def on_process(self, process):
        pid = process["pid"]
        self.handle_uses[pid] = self.get_handles_by_pid(pid)

    @staticmethod
    def has_api_keys(calls, apis):
        """
        Checks for apis in a list of handle calls
        :param calls: handle calls
        :param apis: the names of the api calls we look for
        :return: matched api calls or False
        """
        seen = []

        for call in calls:
            for api_name in apis:
                if (call["api"] == api_name or call["api"] in api_name.split("|")) and call["api"] not in seen:
                    seen.append(call["api"])
                if len(seen) == len(apis):
                    return seen
        return False

    @staticmethod
    def extract_created_process(calls):
        for call in calls:
            if call["api"] == "ZwCreateUserProcess":
                return int(call["arguments"]["ChildPID"], 16)

    @staticmethod
    def remove_duplicates_order(list_to_order):
        """
        Removes duplicates from a list of API calls and orders it by time
        :param list_to_order: list of API calls
        :return: the ordered list
        """
        list_to_order.sort(key=lambda arg: arg['time'])
        return [k for k, v in groupby(list_to_order)]

    def on_complete(self):
        for pid, handle_groups in self.handle_uses.items():
            seen = []
            tracks = []
            for match in self.matches:
                for calls in handle_groups:
                    if match not in seen and self.has_api_keys(calls, match):
                        tracks.extend(calls)
                        seen.append(match)
                if len(seen) == len(self.matches):
                    self.mark(calls_in_handle=self.remove_duplicates_order(tracks),
                              child=self.extract_created_process(tracks),
                              pid=pid)
        return self.has_marks()
