#
# Copyright (C) 2025 Isima, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
""""Error classes"""

from typing import Any, List, Tuple


class RemoteExecutionsError(RuntimeError):
    """Error raised when method execute_on_hosts fails.
    This is a RuntimeError with an additional property results that contains the results of the
    execution. In a parallel execution, size of the results is always the same with number of
    remote hosts. But in a sequential execution, size of the results is number of executions
    which breaks on an error.
    """

    def __init__(self, message: str, results: List[Tuple[int, dict, Any, Exception]]):
        super().__init__(message)
        self.results = results

    def __str__(self):
        elements = [super().__str__()]
        for _, host, _, error in self.results:
            if error is None:
                elements.append(f"\n    host {host['name']}: successful")
            else:
                elements.append(f"\n    host {host['name']}: ERROR - {error}")
        return "".join(elements)
