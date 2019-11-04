# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from ddtrace.propagation.http import HTTPPropagator
from cuckoo.common.abstracts import Report
from datetime import datetime
from ddtrace import tracer
import dateutil.parser
import logging
import json
import math
import os


logger = logging.getLogger(__name__)


class DataDog(Report):
    order = 6

    @staticmethod
    def _to_timestamp(date):
        epoch = datetime(1970, 1, 1)
        return int(math.ceil((date - epoch).total_seconds()))

    def run(self, results):
        tracer.configure(hostname=self.options.agent_host, port=self.options.agent_port)
        tracer.set_tags({'env': self.options.environment})

        task_info = os.path.join(self.analysis_path, "task.json")
        if not os.path.isfile(task_info):
            return

        task = json.load(open(task_info))
        custom = json.loads(results['info']['custom'])

        propagator = HTTPPropagator()
        context = propagator.extract(custom.get("trace"))
        tracer.context_provider.activate(context)

        # VM trace
        vm_span = tracer.start_span('cuckoo.analysis.vm', service=self.options.service_name, child_of=context)

        start_time = dateutil.parser.parse(task["added_on"]["$dt"])
        vm_span.start = self._to_timestamp(start_time)

        finish = dateutil.parser.parse(task["completed_on"]["$dt"])
        finish_timestamp = self._to_timestamp(finish)
        vm_span.finish(finish_timestamp)

        # Reporting trace
        context = propagator.extract(custom.get("trace"))
        reporting_span = tracer.start_span('cuckoo.analysis.reporting', service=self.options.service_name, child_of=context)
        reporting_span.start = finish_timestamp
        reporting_span.finish()

