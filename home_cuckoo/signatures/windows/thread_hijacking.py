# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
from cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)


class ThreadHijacking(Signature):
    id = 3
    name = "thread_hijacking"
    description = "Identifies thread hijacking"
    severity = 5
    categories = ["Injection"]
    authors = ["Itay Huri"]
    minimum = "2.0"
    enabled = True
    process_relationship = True
    apinames = [
        "ZwOpenThread",
        "ZwGetContextThread",
        "ZwSetContextThread"
    ]
    references = [
        "http://www.rohitab.com/discuss/topic/40579-dll-injection-via-thread-hijacking/",
        "https://reverse2learn.wordpress.com/2012/05/01/malware-reversing-part-1/"
    ]

    def init(self):
        self.handle_uses = {}
        self.found_in_handle = []

    def on_process(self, process):
        pid = process["pid"]
        self.handle_uses[pid] = self.get_handles_by_pid(pid)

    def is_unique_indicator(self, api):
        for api_indicator in filter(lambda x: x not in self.found_in_handle, self.apinames):
            if api == api_indicator or api in api_indicator.split("|"):
                return api_indicator
        return False

    def is_suspicious_handle(self, calls):
        self.found_in_handle = []

        for call in calls:
            indicator = self.is_unique_indicator(call["api"])
            if indicator:
                self.found_in_handle.append(indicator)
        return len(self.found_in_handle) != 0

    def on_complete(self):
        for pid, handle_groups in self.handle_uses.items():
            for calls in handle_groups:
                if self.is_suspicious_handle(calls) and len(self.found_in_handle) == len(self.apinames):
                    self.mark(calls_in_handle=calls, pid=pid)
        return self.has_marks()