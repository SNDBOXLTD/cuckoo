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
    """
    Ships execution metrics and logs to Datadog.
    Those traces will be associated with the trace of the upload.
    """
    order = 6

    @staticmethod
    def _to_timestamp(date):
        """
        Converts a date to a timestamp
        :param date: string, for example 2019-11-04T11:57:07.368053
        :return: int, epoch timestamp in seconds
        """
        epoch = datetime(1970, 1, 1)
        parsed_date = dateutil.parser.parse(date)
        return int(math.ceil((parsed_date - epoch).total_seconds()))

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

        # VM trace, starting from the time the task created and ending in the time the VM was shut down
        vm_span = tracer.start_span('cuckoo.analysis.vm', service=self.options.service_name, child_of=context)
        vm_span.start = self._to_timestamp(task["added_on"]["$dt"])
        finish_timestamp = self._to_timestamp(task["completed_on"]["$dt"])
        vm_span.finish(finish_timestamp)

        # Reporting trace, VM shutdown - now
        context = propagator.extract(custom.get("trace"))
        reporting_span = tracer.start_span('cuckoo.analysis.reporting', service=self.options.service_name,
                                           child_of=context)
        reporting_span.start = finish_timestamp
        reporting_span.finish()
