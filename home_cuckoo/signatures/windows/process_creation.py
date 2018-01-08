# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.abstracts import Signature


class ProcessCreation(Signature):
    id = 0
    name = "Process creation"
    description = "Identifies process creation"
    severity = 0
    authors = ["Itay Huri"]
    minimum = "2.0"
    enabled = True
    process_relationship = True
    indicator = False
    apinames = ["ZwCreateProcessEx",
                "ZwCreateProcess",
                "ZwCreateUserProcess"]

    def init(self):
        self.handle_uses = {}
        self.found_in_handle = []

    def on_process(self, process):
        pid = process["pid"]
        self.handle_uses[pid] = self.get_handles_by_pid(pid)

    def is_created_child(self, calls):
        """
        Searches in calls for created processes, returns the PID of the child if found
        :param calls: API calls so search in
        :return: Child PID
        """
        for call in calls:
            if call["api"] in self.apinames:
                return int(call["arguments"]["ChildPID"], 16)
        return False

    def on_complete(self):
        """
        Marks handles which include creation APIs
        :return: marks found
        """
        children_seen = []

        for pid, handle_groups in self.handle_uses.items():
            for calls in handle_groups:
                created_child = self.is_created_child(calls)
                if created_child and created_child not in children_seen:
                    self.mark(calls_in_handle=calls, pid=pid, child=created_child)
                    children_seen.append(created_child)
        return self.has_marks()
