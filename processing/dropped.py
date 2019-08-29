# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import os
import re
import logging

from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import File

logger = logging.getLogger(__name__)


class Dropped(Processing):
    """Dropped files analysis."""

    def _is_whitelisted_path(self, file_path):
        """Exclude common whitelist files.
        """
        whitelist_paths = [
            '\Users\Petra\AppData\Roaming\Microsoft\UProof\ExcludeDictionary',
            '\Users\Petra\AppData\Local\Temp\~$',
            '\Users\Petra\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Word\~',
            '\Users\Petra\AppData\Roaming\Microsoft\Publisher Building Blocks\ContentStore.xml',
            '\Users\Petra\AppData\Local\Microsoft\Office\ONetConfig',
            '\Users\Petra\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content',
            '\Users\Petra\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData',
            '\Windows\System32\winevt\Logs',
        ]
        whitelist_regex_patterns = [
            r'\\Users\\Petra\\AppData\\Local\\Temp\\[0-9]+.*\.cvr',
            r'\\Users\\Petra\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\[0-9a-fA-F]+.(emf|wmf|dat)',
            r'\\Users\\Petra\\AppData\\Local\\Temp\\\w+.tmp.WERInternalMetadata.xml',
            r'\\Users\\Petra\\AppData\\Local\\Temp\\(Word8.0|Excel8.0|VBE)\\.*.exd',
            r'\\Users\\Petra\\AppData\\Roaming\\Microsoft\\Forms\\.*.exd',
            r'\\Users\\Petra\\AppData\\Roaming\\Microsoft\\Office\\.*\.xml',
        ]

        paths_test = all(path not in file_path for path in whitelist_paths)
        regex_test = any(re.match(query, file_path) for query in whitelist_regex_patterns)
        return paths_test and not regex_test

    def run(self):
        """Run analysis.
        @return: list of dropped files with related information.
        """
        self.key = "dropped"
        dropped_files, meta = [], {}

        if os.path.exists(self.dropped_meta_path):
            for line in open(self.dropped_meta_path, "rb"):
                entry = json.loads(line)
                filepath = os.path.join(self.analysis_path, entry["path"])
                meta[filepath] = {
                    "pids": entry["pids"],
                    "filepath": entry["filepath"],
                }

        for dir_name, dir_names, file_names in os.walk(self.dropped_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                file_info = File(file_path=file_path).get_all()
                file_info.update(meta.get(file_info["path"], {}))
                dropped_files.append(file_info)

        for dir_name, dir_names, file_names in os.walk(self.package_files):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                file_info = File(file_path=file_path).get_all()
                dropped_files.append(file_info)

        whitelisted_dropped_files = [f for f in dropped_files if self._is_whitelisted_path(f['filepath'])]

        return whitelisted_dropped_files
