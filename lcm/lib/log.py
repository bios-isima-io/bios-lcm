#!/usr/bin/env python3
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

import datetime
import os
import sys

from rich.console import Console as RichConsole

from .constants import ISIMA_BASE_PATH, LCM_LOGS_PATH

# from rich.traceback import install as rich_traceback_install
# rich_traceback_install(show_locals=False, max_frames=8)
CONSOLE = RichConsole()


def _get_log_file(log_host, bucket):
    if bucket == "trace":
        level_name = "trace_full"
    else:
        level_name = bucket

    if log_host is None:
        machine_name = "localhost"
    else:
        machine_name = log_host["name"]

    filename = f"{level_name}__{machine_name}.log"
    if filename not in Log.host_log_files:
        Log.host_log_files[filename] = open(  # pylint: disable=consider-using-with
            f"{LCM_LOGS_PATH}/{filename}", "a", encoding="UTF-8"
        )
    return Log.host_log_files[filename]


def _get_host_prefix(log_host):
    if log_host is None:
        name = "localhost"
    else:
        name = log_host["name"]
    if len(name) <= 18:
        truncated_name = name
    else:
        truncated_name = ".." + name[len(name) - 16 :]
    return f"{truncated_name:<18}| "


def _log(log_host, dash_prefix: str, log_level_name: str, log_level: int, message):
    caller = sys._getframe(2).f_code.co_name
    callers_caller = None
    try:
        if sys._getframe(3).f_code.co_name != "<module>":
            callers_caller = sys._getframe(3).f_code.co_name
    except Exception:
        pass
    callers = [element for element in [callers_caller, caller] if element]
    stack = f"\\[{'/'.join(callers)}]"

    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_line = log_level_name + " " + stack + " " + str(message)
    time_log_line = time + " " + log_line
    host_prefix = _get_host_prefix(log_host)

    # In trace files add a blank line before higher log levels for better readability.
    if log_level < 3:
        readable = ""
    else:
        readable = "\n"

    # All messages go to trace files.
    print(readable + host_prefix + dash_prefix + time_log_line, flush=True, file=Log.all_traces)
    print(
        readable + dash_prefix + time_log_line, flush=True, file=_get_log_file(log_host, "trace")
    )

    # Info and higher levels to level-specific files.
    if log_level >= 3:
        print(time_log_line, flush=True, file=_get_log_file(log_host, "info"))
        if log_level in range(4, 7):
            print(time_log_line, flush=True, file=_get_log_file(log_host, "warn"))

    # Print to stdout based on whether or not user selected verbose output.
    if Log.verbose_output:
        CONSOLE.log(
            readable + host_prefix + dash_prefix + log_line, _stack_offset=3, highlight=True
        )
    else:
        if log_level >= 3:
            CONSOLE.log(log_line, _stack_offset=3, highlight=True)

    return time_log_line


class Log:
    os.system(f"sudo mkdir -p {LCM_LOGS_PATH}")
    os.system(f"sudo chown -R $USER:$USER {ISIMA_BASE_PATH}")
    error_messages = []
    host_log_files = {}
    all_traces = open(  # pylint: disable=consider-using-with
        f"{LCM_LOGS_PATH}/trace_compact__all_hosts.log", "a", encoding="UTF-8"
    )
    verbose_output = False
    time_of_last_marker = datetime.datetime.now().replace(microsecond=0)

    @staticmethod
    def set_verbose_output(verbose_output_in):
        Log.verbose_output = verbose_output_in

    @staticmethod
    def get_trace_file(log_host):
        return _get_log_file(log_host, "trace")

    @staticmethod
    def trace2(log_host, message):
        _log(log_host, "    -- ", "TRACE", 1, message)

    @staticmethod
    def trace(message):
        # Call _log directly instead of chaining calls to trace2() to get uniform call stacks.
        _log(None, "    -- ", "TRACE", 1, message)

    @staticmethod
    def debug2(log_host, message):
        _log(log_host, "  ---- ", "DEBUG", 2, message)

    @staticmethod
    def debug(message):
        _log(None, "  ---- ", "DEBUG", 2, message)

    @staticmethod
    def info(message):
        _log(None, "------ ", "INFO ", 3, message)

    @staticmethod
    def warn(message):
        _log(None, "!----- ", "WARN ", 4, message)

    @staticmethod
    def error(message):
        log_line = _log(None, "!!!--- ", "ERROR", 5, message)
        Log.error_messages.append(log_line)

    @staticmethod
    def fatal(message):
        log_line = _log(None, "!!!!!! ", "FATAL", 6, message)
        Log.print_accumulated_errors()
        Log.error_messages.append(log_line)

    @staticmethod
    def marker(message):
        current_time = datetime.datetime.now().replace(microsecond=0)
        time_taken = current_time - Log.time_of_last_marker
        Log.time_of_last_marker = current_time
        _log(
            None,
            "------ ",
            "MARK ",
            7,
            f"""


+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|                                                                                                 |
|               {message}
|                                                                                                 |
|               Time taken: {time_taken}
|                                                                                                 |
|                                                                                                 |
+-------------------------------------------------------------------------------------------------+


""",
        )

    @staticmethod
    def print_accumulated_errors():
        if Log.error_messages:
            print(f"\nEncountered {len(Log.error_messages)} errors earlier:", flush=True)
            print(
                f"\nEncountered {len(Log.error_messages)} errors earlier:",
                flush=True,
                file=_get_log_file(None, "trace"),
            )
            print(
                f"\nEncountered {len(Log.error_messages)} errors earlier:",
                flush=True,
                file=_get_log_file(None, "info"),
            )
            for message in Log.error_messages:
                print(message, flush=True)
                print(message, flush=True, file=_get_log_file(None, "trace"))
                print(message, flush=True, file=_get_log_file(None, "info"))
            print("", flush=True)
