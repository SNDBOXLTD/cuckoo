# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import os
from datetime import datetime

from cuckoo.common.abstracts import Report


class TaskSummary(Report):
    order = 5

    def run(self, results):
        task_info = os.path.join(self.analysis_path, "task.json")
        if not os.path.isfile(task_info):
            return

        task = json.load(open(task_info))

        format = "%Y-%m-%dT%H:%M:%S.%f"
        reported_on = datetime.now().strftime(format)
        reporting_time = datetime.now() - datetime.strptime(task["completed_on"]["$dt"], format)

        task["reporting_status"] = results["reporting_status"]
        task["reported_on"] = reported_on
        task["reporting_duration"] = reporting_time.total_seconds()

        task_summary_path = os.path.join(self.reports_path, "task_summary.json")
        with open(task_summary_path, "wb") as report: \
                # newline important for Filebeat to work
                report.write(json.dumps(task) + "\r\n")
