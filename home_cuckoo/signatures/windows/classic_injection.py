# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import json
from cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)


class Injection(Signature):
    name = "Injection"
    description = "Looks for suspicious APIs within the same handle"
    severity = 3
    categories = ["Injection"]
    authors = ["Itay Huri"]
    minimum = "2.0"
    enabled = True
    apinames = ["ZwOpenProcess",
                "ZwAllocateVirtualMemory",
                "ZwWriteVirtualMemory",
                "ZwCreateThreadEx|ZwCreateThread"]

    def init(self):
        self.handle_uses = {}
        self.found_in_process = []

    def on_process(self, process):
        pid = process["pid"]
        self.handle_uses[pid] = self.get_handles_by_pid(pid)
        self.found_in_process = []

    def is_unique_indicator(self, api):
        for api_indicator in filter(lambda x: x not in self.found_in_process, self.apinames):
            if api == api_indicator or api in api_indicator.split("|"):
                return api_indicator
        return False

    def on_complete(self):
        for pid, handle_groups in self.handle_uses.items():
            for calls in handle_groups:
                for call in calls:
                    indicator = self.is_unique_indicator(call["api"])
                    if indicator:
                        self.found_in_process.append(indicator)
                if len(self.found_in_process) == len(self.apinames):
                    self.mark(calls_in_handle=calls, pid=pid)
                    break
        return self.has_marks()
