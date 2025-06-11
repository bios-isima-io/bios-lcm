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
import json
import logging
import math
import os
import random
import re
from datetime import datetime

import bios
import pytz
import requests


def first_or_second(first, second):
    if first:
        return first
    return second


def get_log_message_digest(orig_severity, hostname, log_location, message):
    message_digest = message.strip()

    # Just for these two, remove till the end of the line.
    message_digest = re.sub(r"(eventText: ).*", r"\1?", message_digest)
    message_digest = re.sub(r"(event: ).*", r"\1?", message_digest)

    message_digest = re.sub(r"(event[=: ]+)[\w\-\.,@\(\)\[\]/= {}]+", r"\1?", message_digest)
    message_digest = re.sub(r"(Failed Queries are)[\w :]*", r"\1?", message_digest)
    message_digest = re.sub(r"(File[=: ]+)['\"][\w:,\-\./ ]*['\"]", r"\1?", message_digest)
    for keyword in [
        "appName",
        "appType",
        "attribute",
        "auditSignal",
        "context",
        "foreignKey",
        "from",
        "groupBy",
        "host",
        "http",
        "https",
        "orderBy",
        "POST",
        "primaryKey",
        "request",
        "select",
        "signal",
        "stream",
        "target",
        "tenant",
        "upstream",
        "user",
        "where",
    ]:
        message_digest = re.sub(
            f"({keyword}[=: ]+)" + r"[\w\-\.,@\(\)\[\]/:']+", r"\1?", message_digest
        )

    # Decimal/hex numbers containing at least one digit, with optional separators :,-./
    message_digest = re.sub(
        r"([0-9a-fA-F:,\-\./])*[0-9]([0-9a-fA-F:,\-\./])*", "#", message_digest
    )

    # Remove various thread markers.
    message_digest = re.sub(r"cluster#nio-worker#", r"", message_digest)
    message_digest = re.sub(r"default task#", r"", message_digest)
    message_digest = re.sub(r"ForkJoinPool#worker#", r"", message_digest)
    message_digest = re.sub(r"MSC service thread #", r"", message_digest)
    message_digest = re.sub(r"pool#thr#", r"", message_digest)
    message_digest = re.sub(r"ServerService Thread Pool -- #", r"", message_digest)
    message_digest = re.sub(r"Thr#", r"", message_digest)

    # Collapse repeated blocks.
    message_digest = re.sub(
        r"(## :Ingest failed Insert Record )+", r"## :Ingest failed Insert Record ", message_digest
    )
    message_digest = re.sub(r"(.merge.fetchConfig)+", r".merge.fetchConfig", message_digest)

    short_log_location = os.path.basename(log_location)
    if "bioslb" in log_location:
        short_log_location = "bioslb/" + short_log_location
    message_digest = f"{short_log_location} {orig_severity} {hostname}: {message_digest}"
    return message_digest


def window_start_time_to_millis(src):
    return int(datetime.strptime(src, "%Y-%m-%dT%H:%M:%SZ").timestamp() * 1000)


def json_to_string(src):
    return json.dumps(src)


def get_time_str(time_epoch_ms, time_zone=None):
    time2 = datetime.fromtimestamp(int(time_epoch_ms) / 1000)
    if not time_zone:
        time_zone = "TIME_ZONE_FOR_START_TIME_1" or "UTC"
    out = time2.astimezone(pytz.timezone(time_zone)).strftime("%Y-%m-%d %-I:%M %p  %Z")
    return out


# Truncate log message to fit within about max_lines_per_log lines.
# Take into account both newlines as well as length of the text that fits in a line.
def truncate_if_needed(log):
    max_lines_per_log = int("MAX_LINES_PER_LOG")
    max_chars_per_line = 90

    # Track the total display lines used up by checking line-by-line.
    in_lines = log.split("\n")
    out_lines = []
    total_display_lines = 0
    for line in in_lines:
        current_display_lines = math.floor(len(line) / max_chars_per_line) + 1
        if (total_display_lines + current_display_lines) > max_lines_per_log:
            display_lines_allowed = max_lines_per_log - total_display_lines
            line = line[: display_lines_allowed * max_chars_per_line]
        out_lines.append(line)
        total_display_lines += current_display_lines
        if total_display_lines >= max_lines_per_log:
            break
    out = "\n".join(out_lines)
    if len(out) != len(log):
        out += "..."
    return out


def get_random_color():
    color = "#" + "".join([random.choice("0123456789ABCDEF") for _ in range(6)])
    return color


def process_alert(
    domain_name, signal_name, alert_name, condition, window_start_time, window_length, event_str
):
    cluster_dns_name = "CLUSTER_DNS_NAME"
    lb_https_port = "LB_HTTPS_PORT"
    user = "OBSERVE_READ_WRITE_USER"
    password = "OBSERVE_READ_WRITE_PASSWORD"
    slack_url_low = "SLACK_URL_LOW"
    slack_url_high = "SLACK_URL_HIGH"
    time_zone_for_start_time_1 = "TIME_ZONE_FOR_START_TIME_1" or "UTC"
    time_zone_for_start_time_2 = "TIME_ZONE_FOR_START_TIME_2"
    time_zone_for_start_time_3 = "TIME_ZONE_FOR_START_TIME_3"
    reports = {}  # REPORTS_PLACEHOLDER
    default_periods = {}  # DEFAULT_PERIODS_PLACEHOLDER
    alert_periods = {}  # ALERT_PERIODS_PLACEHOLDER

    window_start_time_str = get_time_str(window_start_time, time_zone_for_start_time_1)
    current_time = bios.time.now()
    logger = logging.getLogger("ObserveUtils")
    # Sanity check.
    if cluster_dns_name != domain_name:
        logger.error(
            f"Domain name configured in processor ({cluster_dns_name}) does not match "
            + f"domain name received in alert ({domain_name}) configured in server.options"
        )

    alert_key = alert_name + "  "
    host_friendly_name = ""
    event = json.loads(event_str)
    if "hostFriendlyName" in event:
        host_friendly_name = event["hostFriendlyName"]
        alert_key += "    " + host_friendly_name
    if "tenant" in event:  # For appStatus and containers signals
        if (signal_name == "containers") or (
            (signal_name == "appStatus") and (event["appName"] == "webhook")
        ):
            alert_key += "    " + event["tenant"]
    if "name" in event:  # Container name for "containers" signal.
        alert_key += "    " + event["name"]
    if "mountpoint" in event:  # For diskStats and ioStats
        alert_key += "    " + event["mountpoint"]
    if "status" in event:  # For lbRequest
        alert_key += "    <status " + event["status"] + ">"
    if "serviceName" in event:  # For exception
        alert_key += "    " + event["serviceName"]

    suffix = alert_name[-1]
    if suffix in ["1", "2"]:
        base_alert_level = int(suffix)
    else:
        logger.info(
            f"None: non-notifying alertKey <{alert_key}> activated; "
            + f"window: {window_start_time_str} + {window_length}"
        )
        return {"alertKey": alert_key, "sentToSlack": "None", "details": ""}

    # If this alert is for a very old window, do not notify. This can happen due to
    # retroactive rollups.
    if (current_time - window_start_time) > bios.time.days(2):
        logger.info(
            f"VeryOldAlert: skipping notification for alertKey <{alert_key}>; "
            + f"window: {window_start_time_str} + {window_length}"
        )
        return {"alertKey": alert_key, "sentToSlack": "VeryOldAlert", "details": ""}

    # Prepare a header including the alert_key and an important number specific to the alert type.
    alert_name_core = alert_name[0:-1]
    alert_specific_info = None
    if alert_name_core == "highCpuUsage":
        usage = event["sum(cpuUsage)"] / event["count()"]
        alert_specific_info = f"{usage:.1f}%"
    elif alert_name_core == "highMemoryUsage":
        usage = event["sum(memUsage)"] / event["count()"]
        alert_specific_info = f"{usage:.1f}%"
    elif alert_name_core == "biosHeartbeat15Min":
        alert_specific_info = f"got {event['count()']} / 30 expected"
    elif alert_name_core == "biosHeartbeat30Min":
        alert_specific_info = f"got {event['count()']} / 60 expected"
    elif alert_name_core == "highDiskSpaceUsage":
        usage = event["sum(bytesUsed)"] * 100.0 / event["sum(bytesTotal)"]
        total_space = event["sum(bytesTotal)"] / event["count()"]
        total_space_gb = total_space / 1024 / 1024 / 1024
        alert_specific_info = f"{usage:.0f}% of {total_space_gb:,.0f} GiB"
    elif alert_name_core == "highDiskIoReadLatency":
        latency = event["sum(readLatencySum)"] / event["sum(numReads)"] / 1000.0
        alert_specific_info = f"{latency:.0f} ms"
    elif alert_name_core == "highDiskIoWriteLatency":
        latency = event["sum(writeLatencySum)"] / event["sum(numWrites)"] / 1000.0
        alert_specific_info = f"{latency:.0f} ms"
    elif alert_name_core == "highNetworkErrors1":
        errors = event["sum(numReceiveErrors)"] + event["sum(numTransmitErrors)"]
        alert_specific_info = f"{errors} errors in {window_length}"
    elif alert_name_core == "highLbErrors":
        errors = event["count()"]
        alert_specific_info = f"{errors} times in {window_length}"
    elif alert_name_core == "biosStorageIsDown":
        uptime = event["sum(isUpInteger)"] * 100.0 / event["count()"]
        alert_specific_info = f"uptime {uptime:.0f}% in {window_length}"
    elif alert_name_core.startswith("log"):
        logs = event["count()"]
        if "severity" in event:
            log_severity_name = event["severity"].lower()
        else:
            log_severity_name = "log"
        alert_specific_info = f"{logs} {log_severity_name}s in {window_length}"
    header = alert_key
    if alert_specific_info:
        header += "    " + alert_specific_info

    start_time_string = "*Start Time:*    " + window_start_time_str
    if time_zone_for_start_time_2:
        start_time_string += "      " + get_time_str(window_start_time, time_zone_for_start_time_2)
    if time_zone_for_start_time_3:
        start_time_string += "      " + get_time_str(window_start_time, time_zone_for_start_time_3)
    # If this alert is for a time window that did not just finish, add a message to note it.
    if (current_time - window_start_time) > bios.time.minutes(36):
        start_time_string = "*Old Alert!*    " + start_time_string

    description = f"*Cluster:* {cluster_dns_name}"
    if alert_name in reports:
        description += f"\n*Reports:*  "
        prefix = ""
        reports_for_alert = reports[alert_name]
        for report in reports_for_alert:
            description += (
                prefix
                + f"<https://{cluster_dns_name}:{lb_https_port}/report/{report['reportId']}"
                + f"/{report['durationMinutes'] * 60 * 1000}|{report['reportId']}>"
            )
            prefix = "\n                 "
    description += f"\n*Duration:* {window_length}\n" + start_time_string
    description += (
        f"\n*Signal:* <https://{cluster_dns_name}:{lb_https_port}/signal"
        f"/{signal_name}|{signal_name}>"
        f"\n*Condition:* {condition}\n"
        + json.dumps(event, ensure_ascii=False, indent=4)
        + f"\n*Processed on node:* {os.uname().nodename}"
    )

    message = {}
    message["blocks"] = [
        {"type": "header", "text": {"type": "plain_text", "text": header}},
    ]
    message["attachments"] = []
    message["attachments"].append({"color": get_random_color()})
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": description,
            },
        },
    ]
    message["attachments"][0]["blocks"] = blocks

    logs_alert_level = 2
    session = bios.login(f"https://{cluster_dns_name}", user, password)
    if alert_name.startswith("log"):
        logs_alert_level = add_logs(event, session, blocks, current_time)

    given_alert_level = min(base_alert_level, logs_alert_level)
    if not given_alert_level:
        logger.info(
            f"KnownLogs alertKey <{alert_key}>; "
            + f"window: {window_start_time_str} + {window_length}"
        )
        return {"alertKey": alert_key, "sentToSlack": "KnownLogs", "details": str(message)}

    # Track fired alerts to avoid sending too many Slack messages in quick succession.
    (slack_alert_level, context_block, fired_alert_info) = check_fired_alerts(
        given_alert_level,
        session,
        alert_key,
        alert_name,
        current_time,
        default_periods,
        alert_periods,
    )
    if not slack_alert_level:
        logger.info(
            f"Silenced alertKey <{alert_key}> for now; "
            + f"window: {window_start_time_str} + {window_length}"
        )
        return {"alertKey": alert_key, "sentToSlack": "Silenced", "details": str(message)}
    # If a context_block was returned, add it to the top of the message just below the header.
    if context_block:
        message["blocks"].append(context_block)

    if slack_alert_level == 1:
        slack_alert_level_string = "Low"
        slack_url = slack_url_low
    else:
        slack_alert_level_string = "High"
        slack_url = slack_url_high

    # Message is ready to be sent; now send it to Slack if configured.
    out = {"alertKey": alert_key, "details": str(message)}

    if slack_url == "NotConfigured":
        logger.info(
            f"NotConfigured Slack alertKey <{alert_key}>; "
            + f"window: {window_start_time_str} + {window_length}"
        )
        out["sentToSlack"] = "NotConfigured"
    else:
        response = requests.post(
            slack_url, json=message, headers={"Content-Type": "application/json"}, timeout=120
        )
        if response.status_code != 200:
            logger.error(
                f"UnableToSend: Sending message to Slack failed. Error: {response.status_code}, "
                + f"response: {response.text}, message: {str(message)}; "
                + f"window: {window_start_time_str} + {window_length}"
            )
            out["sentToSlack"] = "UnableToSend" + slack_alert_level_string
        else:
            logger.info(
                f"Sent to Slack alertKey <{alert_key}>; "
                + f"window: {window_start_time_str} + {window_length}"
            )
            out["sentToSlack"] = "Sent" + slack_alert_level_string
            record_notified_alert(
                fired_alert_info,
                slack_alert_level,
                given_alert_level,
                session,
                alert_key,
                alert_name,
                current_time,
            )

    return out


# Returns an integer - the alert level (0, 1, or 2) determined by the logs found.
# Unless configured lower by knownLogMessages, the alert level is assumed to be 2.
def add_logs(event, session, blocks, current_time):
    max_logs_to_show = int("MAX_LOGS_TO_SHOW")
    max_log_digests_to_show = int("MAX_LOG_DIGESTS_TO_SHOW")
    logs_period_seconds = int("LOGS_PERIOD_SECONDS")
    log_digests_period_minutes = int("LOG_DIGESTS_PERIOD_MINUTES")

    # Get individual log events filtered by the host, severity, and service (if specified).
    # If they are all specified, calculate the alert level by going through all logs returned and
    # checking with knownLogMessages to determine alert level.
    calculate_alert_level = True
    where_clause = []
    if "hostFriendlyName" in event:
        where_clause.append(f"(hostFriendlyName = '{event['hostFriendlyName']}')")
    else:
        calculate_alert_level = False
    if "severity" in event:
        where_clause.append(f"(severity = '{event['severity']}')")
    else:
        calculate_alert_level = False
    if "serviceName" in event:
        where_clause.append(f"(serviceName = '{event['serviceName']}')")
    else:
        calculate_alert_level = False

    delta = bios.time.seconds(logs_period_seconds)
    query_part = bios.isql().select().from_signal("exception")
    if where_clause:
        query_part = query_part.where(" and ".join(where_clause))
    query_part = query_part.order_by(":timestamp", reverse=True)
    # If we are not calculating the alert level, add a limit clause to reduce load.
    if not calculate_alert_level:
        query_part = query_part.limit(max_logs_to_show)
    query = query_part.time_range(current_time, -delta).build()
    result = session.execute(query)

    known_log_messages = None
    if calculate_alert_level:
        known_log_messages = get_known_log_messages(session)

    blocks.append({"type": "divider"})
    logs_title_section = {"type": "section", "text": {"type": "mrkdwn"}}
    blocks.append(logs_title_section)
    blocks.append({"type": "divider"})
    logs_subtitle_element = {"type": "mrkdwn"}
    blocks.append(
        {
            "type": "context",
            "elements": [logs_subtitle_element],
        }
    )
    overall_alert_level = 0
    num_logs_added = 0
    earliest_shown_log_time = current_time
    if result.get_data_windows():
        window = result.get_data_windows()[0]
        for record in window.get_records():
            log_text = record.get("message")
            service_name = record.get("serviceName")
            current_log_alert_level = get_alert_level(known_log_messages, log_text, service_name)
            if current_log_alert_level == 0:
                continue
            overall_alert_level = max(overall_alert_level, current_log_alert_level)
            if num_logs_added < max_logs_to_show:
                earliest_shown_log_time = record.get_timestamp()
                log_summary = (
                    f"Service: *{service_name}*"
                    + f", host: {record.get('hostFriendlyName')}"
                    + f", log file: {record.get('logLocation')}"
                    + f", time: {record.get('origEventTimestamp')}"
                    + f", severity: *{record.get('origSeverity')}*"
                )
                if record.get("tenant"):
                    log_summary += f", tenant: *{record.get('tenant')}*"
                log_text = truncate_if_needed(log_text)
                blocks.append({"type": "divider"})
                blocks.append(
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": log_summary,
                            },
                            {"type": "plain_text", "text": log_text},
                        ],
                    }
                )
                num_logs_added += 1

    # Get log digests and counts.
    # Get a clean number of 5-minute windows to include in query.
    num_sketch_windows = math.floor(log_digests_period_minutes / 5)
    num_sketch_windows = max(num_sketch_windows, 1)
    delta = bios.time.minutes(5)
    query = (
        bios.isql()
        .select("samplecounts(messageDigest)")
        .from_signal("exception")
        .tumbling_window(num_sketch_windows * delta)
        .time_range(current_time, -num_sketch_windows * delta, delta)
        .build()
    )
    result = session.execute(query)
    blocks.append({"type": "divider"})
    num_digests_added = 0
    if result.get_data_windows():
        window = result.get_data_windows()[0]
        all_records = window.get_records()
        total_records = len(all_records)
        num_log_digests_to_show = min(max_log_digests_to_show, total_records)
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Log Digests* in last {num_sketch_windows * 5} minutes "
                    + f"(aligned to 5 minute boundary), "
                    + f"top {num_log_digests_to_show} out of {total_records} items:",
                },
            }
        )
        for record in all_records:
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "Count: *" + str(record.get("_sampleCount")) + "*",
                        },
                        {"type": "plain_text", "text": truncate_if_needed(record.get("_sample"))},
                    ],
                }
            )
            num_digests_added += 1
            if num_digests_added >= num_log_digests_to_show:
                break
    else:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*0 Log Digests* found in last {num_sketch_windows * 5} minutes "
                    + "(aligned to 5 minute boundary).",
                },
            }
        )

    shown_logs_period_seconds = (current_time - earliest_shown_log_time) / 1000.0
    logs_subtitle = f"Logs in last {shown_logs_period_seconds:.3g} seconds (latest first)"
    if where_clause:
        logs_subtitle += f"\n    where {' and '.join(where_clause)}"
    logs_subtitle_element["text"] = logs_subtitle
    logs_title = (
        f"*{num_logs_added} logs* (in last {shown_logs_period_seconds:.3g} seconds) "
        + f"and *{num_digests_added} log digests* (in last {num_sketch_windows * 5} minutes)."
    )
    logs_title_section["text"]["text"] = logs_title

    return overall_alert_level


def get_known_log_messages(session):
    # Get all the keys in the context.
    keys = []
    query = bios.isql().select("logMessagePart").from_context("knownLogMessages").build()
    result = session.execute(query)
    records = result.get_records()
    for record in records:
        keys.append(record.get_primary_key())

    # Get all the records in the context.
    known_log_messages = []
    query = bios.isql().select().from_context("knownLogMessages").where(keys=keys).build()
    result = session.execute(query)
    records = result.get_records()
    for record in records:
        known_log_messages.append(
            [
                record.get("logMessagePart"),
                record.get("serviceName"),
                record.get("targetAlertLevel"),
            ]
        )

    return known_log_messages


def get_alert_level(known_log_messages, log_text, service_name):
    alert_level = 2
    if known_log_messages:
        for known_log_message in known_log_messages:
            if known_log_message[1] == service_name and known_log_message[0] in log_text:
                return known_log_message[2]
    return alert_level


def get_effective_period(given_alert_level, item, default_periods, alert_name, alert_periods):
    if given_alert_level == 1:
        given_alert_level_string = "low"
    else:
        given_alert_level_string = "high"
    default_item_name = given_alert_level_string + "_alert_" + item

    out = get_effective_value(item, default_item_name, default_periods, alert_name, alert_periods)
    return out


def get_effective_value(item, default_item_name, default_periods, alert_name, alert_periods):
    out = default_periods[default_item_name]
    if alert_name in alert_periods:
        if item in alert_periods[alert_name]:
            out = alert_periods[alert_name][item]
    return out


# Returns a tuple: (slack_alert_level, context_block, fired_alert_info)
def check_fired_alerts(
    given_alert_level, session, alert_key, alert_name, current_time, default_periods, alert_periods
):
    silence_days = get_effective_period(
        given_alert_level, "silence_days", default_periods, alert_name, alert_periods
    )
    caution_days = get_effective_period(
        given_alert_level, "caution_days", default_periods, alert_name, alert_periods
    )
    high_alert_low_reminders = get_effective_value(
        "low_reminders", "high_alert_low_reminders", default_periods, alert_name, alert_periods
    )
    silence_period = silence_days * bios.time.days(1)
    caution_period = caution_days * bios.time.days(1)
    reminder_period = (silence_days / (high_alert_low_reminders + 1)) * bios.time.days(1)

    query = bios.isql().select().from_context("firedAlert").where(keys=[[alert_key]]).build()
    result = session.execute(query)
    records = result.get_records()

    # In the explanation of the code below we use examples in the form:
    # [firstActivationTime, lastNotificationTime, lastReminderTime, lastActivationTime]
    # These examples assume that:
    #   - silence_period is 300
    #   - caution_period is 1,000
    #   - reminders is 2
    # For an alert at high level, reminders of 2 means that since silence_period is 300,
    #       reminder_period is 100 and 2 low level reminders are sent at times 100 and 200 after
    #       a notification at high level.
    # E.g. [10, 320, 425, 475] means that this alert_key was:
    #       FA: first activated (process_alert called) at time 10,
    #       LN: last notified at the given alert level at time 320,
    #       LR: last reminded at the low alert level at time 425 (if given alert level is high),
    #       LA: last activated at time 475 (notification may or may not have been sent).
    #   CT represents current time.
    # Note that lastReminderTime is not used (and is set to 0) for alerts with low alert level.

    # We only insert/upsert into the firedAlert context after at least one successful notification.
    # So if a Slack notification fails, the alert is treated as if it was fresh next time.

    # If this is the first time, or first time after a long time (a long time has passed),
    # send a plain notification without a context block.
    if not records or current_time > records[0].get("lastActivationTime") + silence_period:
        # Examples: <not present>, or:
        # [10, 320, 425, 475] and current_time is > 475 + 300
        # ...FA...................LN.........LR...LA...................................CT
        return (given_alert_level, None, None)

    # This alert_key has been active recently and has been notified. Figure out whether to
    # notify now, the target notification level, and the context message.
    first_activation = records[0].get("firstActivationTime")
    last_notification = records[0].get("lastNotificationTime")
    last_reminder = records[0].get("lastReminderTime")
    activations = records[0].get("activationCount")
    notifications = records[0].get("notificationCount")
    fired_alert_info = {}
    fired_alert_info["first_activation"] = first_activation
    fired_alert_info["last_notification"] = last_notification
    fired_alert_info["last_reminder"] = last_reminder
    fired_alert_info["activations"] = activations
    fired_alert_info["notifications"] = notifications

    context_block = {
        "type": "context",
        "elements": [{"type": "mrkdwn"}],
    }
    context_element = context_block["elements"][0]

    # If this alert has been active for a long time, longer than caution_period, add a caution
    # statement to the context block.
    # Example: [10, 1320, 1425, 1475] and current_time is > 10 + 1,000
    # ...FA....................................................LN.........LR...LA................CT
    if current_time > first_activation + caution_period:
        context_element["text"] = (
            f":exclamation: *This alert has been active since {get_time_str(first_activation)}*!\n"
        )
        context_element = {"type": "mrkdwn"}
        context_block["elements"].append(context_element)
    # After adding a caution statement, continue below.

    # If last notification was more than silence_period ago, notify at the given alert level.
    # Example: [10, 320, 425, 475] and current_time is > 320 + 300
    # ...FA...................LN.........LR...LA............CT
    if current_time > last_notification + silence_period:
        context_element["text"] = (
            f"Activated {activations + 1} times and notified {notifications + 1} times since "
            f"{get_time_str(first_activation)} \n"
            f"Last notified: {get_time_str(last_notification)}"
        )
        return (given_alert_level, context_block, fired_alert_info)

    # If given alert level is high and last reminder/notification was more than
    # reminder_period ago, notify at low alert level.
    # Example 1: [10, 320, 425, 475] and current_time is > 425 + 100
    # ...FA...................LN.........LR...LA.....CT
    # Example 2: [10, 320, 320, 475] and current_time is 425
    # ...FA...................LN.........CT
    # ........................LR...........
    if given_alert_level == 2 and current_time > last_reminder + reminder_period:
        context_element["text"] = (
            f":warning: Reminder for an alert posted in high severity Slack channel! \n"
            f"Activated {activations + 1} times and notified {notifications + 1} times since "
            f"{get_time_str(first_activation)} \n"
            f"Last notified: {get_time_str(last_notification)}"
        )
        return (1, context_block, fired_alert_info)

    # Looks like we have either notified or reminded recently; don't send a notification now
    # but record this activation in the DB.
    request = (
        bios.isql()
        .upsert()
        .into("firedAlert")
        .csv(
            f"{alert_key},{alert_name},{first_activation},{last_notification},{last_reminder},"
            + f"{current_time},{activations + 1},{notifications}"
        )
        .build()
    )
    session.execute(request)

    return (0, None, fired_alert_info)


def record_notified_alert(
    fired_alert_info,
    slack_alert_level,
    given_alert_level,
    session,
    alert_key,
    alert_name,
    current_time,
):
    # Create info to upsert into DB.
    last_activation = current_time
    last_reminder = current_time
    if fired_alert_info:
        first_activation = fired_alert_info["first_activation"]
        activations = fired_alert_info["activations"] + 1
        notifications = fired_alert_info["notifications"] + 1
        if slack_alert_level == given_alert_level:
            last_notification = current_time
        else:
            last_notification = fired_alert_info["last_notification"]
    else:
        first_activation = current_time
        last_notification = current_time
        activations = 1
        notifications = 1

    request = (
        bios.isql()
        .upsert()
        .into("firedAlert")
        .csv(
            f"{alert_key},{alert_name},{first_activation},{last_notification},{last_reminder},"
            + f"{last_activation},{activations},{notifications}"
        )
        .build()
    )
    session.execute(request)
