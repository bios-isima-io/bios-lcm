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
import copy
import uuid
from collections import OrderedDict

import bios
import yaml
from bios import Client, ErrorCode, ServiceError
from lib.common_with_bios import create_bios_session_system
from lib.constants import BIOS_CONFIGS_PATH, DATA_DIR, LOCAL_RES_PATH_BASE

from .common import get_cluster_dns_name_port, replace_line_re, run_local
from .log import Log


def upgrade_system_schema(config):
    Log.info("Upgrading system schema for observability.")
    session = create_bios_session_system(config)
    create_system_users_if_absent(config, session)
    schema = get_system_schema_from_files(config)

    # Create/update contexts first as signals depend on them.
    for context in schema["contexts"]:
        context_name = context["contextName"]
        try:
            Log.debug(f"Updating context {context_name}")
            result = session.get_context(context_name)
            Log.trace(f"------ Current config: \n{result}\n-------- New config: \n{context}")
            session.update_context(context_name, context)
            Log.info(f"Updated context {context_name}")
        except ServiceError as error:
            # Create the context if it does not already exist, raise exception in other cases.
            if error.error_code != ErrorCode.NO_SUCH_STREAM:
                Log.debug(f"Creating context {context_name}")
                session.create_context(context)
                Log.info(f"Created context {context_name}")
            elif "config for change is identical to existing" in str(error):
                Log.debug(f"        skipping {context_name} because the config is identical")
            else:
                raise
    populate_contexts(session)

    for signal in schema["signals"]:
        signal_name = signal["signalName"]
        try:
            Log.debug(f"Updating signal {signal_name}")
            result = session.get_signal(signal_name)
            Log.trace(f"------ Current config: \n{result}\n-------- New config: \n{signal}")
            session.update_signal(signal_name, signal)
            Log.info(f"Updated signal {signal_name}")
        except ServiceError as error:
            # Create the signal if it does not already exist, raise exception in other cases.
            if error.error_code == ErrorCode.NO_SUCH_STREAM:
                Log.debug(f"Creating signal {signal_name}")
                session.create_signal(signal)
                Log.info(f"Created signal {signal_name}")
            elif "config for change is identical to existing" in str(error):
                Log.debug(f"        skipping {signal_name} because the config is identical")
            else:
                raise

    for import_destination in schema["importDestinations"]:
        Log.debug(
            f"Confirming import destination existence: "
            f"{import_destination['importDestinationName']}"
        )
        try:
            result = session.get_import_destination(import_destination["importDestinationId"])
            if result != import_destination:
                Log.debug(
                    f"Updating import destination: {import_destination['importDestinationName']}"
                )
                session.update_import_destination(
                    import_destination["importDestinationId"], import_destination
                )
                Log.info(
                    f"Updated import destination: {import_destination['importDestinationName']}"
                )
        except ServiceError as error:
            # Create the import destination if it does not already exist, raise exception in other
            # cases.
            if error.error_code != ErrorCode.NOT_FOUND:
                raise
            Log.debug(
                f"Creating import destination: {import_destination['importDestinationName']}"
            )
            session.create_import_destination(import_destination)
            Log.info(f"Created import destination: {import_destination['importDestinationName']}")

    for import_source in schema["importSources"]:
        Log.debug(f"Confirming import source existence: {import_source['importSourceName']}")
        try:
            result = session.get_import_source(import_source["importSourceId"])
            if result != import_source:
                Log.debug(f"Updating import source: {import_source['importSourceName']}")
                session.update_import_source(import_source["importSourceId"], import_source)
                Log.info(f"Updated import source: {import_source['importSourceName']}")
        except ServiceError as error:
            # Create the import source if it does not already exist, raise exception in other cases
            if error.error_code != ErrorCode.NOT_FOUND:
                raise
            Log.debug(f"Creating import source: {import_source['importSourceName']}")
            session.create_import_source(import_source)
            Log.info(f"Created import source: {import_source['importSourceName']}")

    any_processor_changed = False
    for processor in schema["importDataProcessors"]:
        processor_name = processor["processorName"]
        code = processor["code"]
        Log.debug(f"Confirming import data processor existence: {processor_name}")
        try:
            result = session.get_import_data_processor(processor_name)
            if result != processor:
                Log.debug(f"Updating import data processor: {processor_name}")
                session.update_import_data_processor(processor_name, code)
                any_processor_changed = True
                Log.info(f"Updated import data processor: {processor_name}")
        except ServiceError as error:
            # Create the processor if it does not already exist, raise exception in other cases
            if error.error_code != ErrorCode.NOT_FOUND:
                raise
            Log.debug(f"Creating import data processor: {processor_name}")
            session.create_import_data_processor(processor_name, code)
            Log.info(f"Created import data processor: {processor_name}")

    for flow in schema["importFlowSpecs"]:
        Log.debug(f"Confirming existence of import flow spec: {flow['importFlowName']}")
        try:
            result = session.get_import_flow_spec(flow["importFlowName"])
            # If a processor was changed, update all flows in order to ensure webhook reloads
            # configuration.
            if (result != flow) or any_processor_changed:
                Log.debug(f"Updating import flow spec: {flow['importFlowName']}")
                session.update_import_flow_spec(flow["importFlowName"], flow)
                Log.info(f"Updated import flow spec: {flow['importFlowName']}")
        except ServiceError as error:
            # Create the flow if it does not already exist, raise exception in other cases.
            if error.error_code != ErrorCode.NOT_FOUND:
                raise
            Log.debug(f"Creating import flow spec: {flow['importFlowName']}")
            session.create_import_flow_spec(flow)
            Log.info(f"Created import flow spec: {flow['importFlowName']}")

    Log.info("Completed upgrading system schema.")


def create_system_users_if_absent(config, session):
    create_user_if_absent(
        session,
        "observe_read_write@isima.io",
        config["observe_read_write_password"],
        ["Extract", "Ingest"],
    )
    create_user_if_absent(
        session, "observe_writer@isima.io", config["observe_writer_password"], ["Ingest"]
    )


def create_user_if_absent(session, email, password, roles):
    Log.debug(f"Creating user {email}")
    try:
        Log.debug(f"Creating user {email}")
        user = bios.User(email, email, "_system", password, roles)
        session.create_user(user)
    except Exception as exception:
        # Raise the exception further in any case except if the user already exists.
        if "User already exists" not in str(exception):
            raise


def get_system_schema_from_files(config):
    with open(f"{DATA_DIR}/alerts.yaml", "r", encoding="UTF-8") as alerts_schema:
        alerts = yaml.safe_load(alerts_schema)

    run_local(f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/observe_utils.py {LOCAL_RES_PATH_BASE}/")
    file = f"{LOCAL_RES_PATH_BASE}/observe_utils.py"
    replace_line_re("CLUSTER_DNS_NAME", config["cluster_dns_name"], file)
    replace_line_re('"LB_HTTPS_PORT"', config["lb_https_port"], file)
    replace_line_re("SLACK_URL_LOW", config["slack_url_low"], file)
    replace_line_re("SLACK_URL_HIGH", config["slack_url_high"], file)
    replace_line_re("OBSERVE_READ_WRITE_USER", "observe_read_write@isima.io", file)
    replace_line_re("OBSERVE_READ_WRITE_PASSWORD", config["observe_read_write_password"], file)
    replace_line_re("MAX_LOGS_TO_SHOW", str(alerts["max_logs_to_show"]), file)
    replace_line_re("MAX_LOG_DIGESTS_TO_SHOW", str(alerts["max_log_digests_to_show"]), file)
    replace_line_re("MAX_LINES_PER_LOG", str(alerts["max_lines_per_log"]), file)
    replace_line_re("LOGS_PERIOD_SECONDS", str(alerts["logs_period_seconds"]), file)
    replace_line_re("LOG_DIGESTS_PERIOD_MINUTES", str(alerts["log_digests_period_minutes"]), file)
    replace_line_re("TIME_ZONE_FOR_START_TIME_1", str(alerts["time_zone_for_start_time_1"]), file)
    replace_line_re("TIME_ZONE_FOR_START_TIME_2", str(alerts["time_zone_for_start_time_2"]), file)
    replace_line_re("TIME_ZONE_FOR_START_TIME_3", str(alerts["time_zone_for_start_time_3"]), file)

    # Add configuration about which reports to use for which alerts.
    reports = {}
    alert_periods = {}
    for features in alerts["signals"].values():
        for feature in features:
            for alert in feature["alerts"]:
                if "reports" in alert:
                    reports[alert["alertName"]] = alert["reports"]
                    del alert["reports"]
                if "alert_periods" in alert:
                    alert_periods[alert["alertName"]] = alert["alert_periods"]
                    del alert["alert_periods"]
    replace_line_re("{}  # REPORTS_PLACEHOLDER", str(reports), file)
    replace_line_re("{}  # ALERT_PERIODS_PLACEHOLDER", str(alert_periods), file)
    replace_line_re("{}  # DEFAULT_PERIODS_PLACEHOLDER", str(alerts["default_periods"]), file)

    with open(
        f"{LOCAL_RES_PATH_BASE}/observe_utils.py", "r", encoding="UTF-8"
    ) as observe_utils_file:
        observe_utils_code = observe_utils_file.read()

    run_local(
        f"cp --no-preserve=mode {BIOS_CONFIGS_PATH}/system_schema.yaml {LOCAL_RES_PATH_BASE}/"
    )
    file = f"{LOCAL_RES_PATH_BASE}/system_schema.yaml"
    replace_line_re("CLUSTER_DNS_NAME", get_cluster_dns_name_port(config), file)

    with open(file, "r", encoding="UTF-8") as system_schema:
        schema = yaml.safe_load(system_schema)
    for processor in schema["importDataProcessors"]:
        if processor["processorName"] == "ObserveUtils":
            processor["code"] = observe_utils_code
    for signal_name, features in alerts["signals"].items():
        for signal_1 in schema["signals"]:
            if signal_1["signalName"] == signal_name:
                signal = signal_1
                break
        for feature in features:
            for alert in feature["alerts"]:
                host = config["cluster_dns_name"]
                port = config["lb_https_port"]
                alert["webhookUrl"] = f"https://{host}:{port}/integration/_system/alerts/alert"
                alert["userName"] = "observe_writer@isima.io"
                alert["password"] = config["observe_writer_password"]
            signal["postStorageStage"]["features"].append(feature)

    return schema


def populate_contexts(session):
    Log.debug("Populating context booleanToNumber")
    context_entries = ["false,0", "true,1"]
    request = bios.isql().upsert().into("booleanToNumber").csv_bulk(context_entries).build()
    session.execute(request)

    Log.debug("Context knownLogMessages: first get all the keys in the context")
    keys = []
    # TODO(BIOS-5144): re-enable after the bug is fixed.
    # query = bios.isql().select("logMessagePart").from_context("knownLogMessages").build()
    # result = session.execute(query)
    # records = result.get_records()
    # for record in records:
    #     keys.append(record.get_primary_key())

    Log.debug("Context knownLogMessages: next delete entries not present in configuration")
    with open(f"{DATA_DIR}/alerts.yaml", "r", encoding="UTF-8") as system_schema:
        known_log_messages = yaml.safe_load(system_schema)["knownLogMessages"]
    for entry in known_log_messages:
        if entry["logMessagePart"] in keys:
            keys.remove(entry["logMessagePart"])
    delete_request = bios.isql().delete().from_context("knownLogMessages").where(keys=keys).build()
    session.execute(delete_request)

    Log.debug("Context knownLogMessages: then upsert entries present in configuration")
    attribute_mapping = {
        "commonKeys": ["knownLogMessages", "*"],
        "data": OrderedDict(
            [
                ("logMessagePart", "logMessagePart"),
                ("serviceName", "serviceName"),
                ("targetAlertLevel", "targetAlertLevel"),
            ]
        ),
    }
    request = (
        bios.isql()
        .upsert()
        .into("knownLogMessages")
        .json({"knownLogMessages": known_log_messages}, attribute_mapping)
        .build()
    )
    session.execute(request)


def initialize_system_schema(config):
    Log.info("Initializing bi(OS) system schema for observability.")
    session = create_bios_session_system(config)
    create_system_users_if_absent(config, session)
    schema = get_system_schema_from_files(config)
    create_schema(session, schema, populate_contexts)
    Log.debug("Completed setting up system schema.")


def update_tenant(session: Client, tenant_config: dict):
    """Iterates members of tenant configuration, compare them with the existing config,
    and create or update them on the server."""
    original_tenant_config = session.get_tenant(detail=True)
    update_contexts(session, tenant_config, original_tenant_config)
    # fetch tenant config again to obtain audit signals
    original_tenant_config = session.get_tenant(detail=True)
    update_signals(session, tenant_config, original_tenant_config)
    update_import_destinations(session, tenant_config, original_tenant_config)
    update_import_sources(session, tenant_config, original_tenant_config)
    update_import_data_processors(session, tenant_config, original_tenant_config)
    update_flows(session, tenant_config, original_tenant_config)
    update_reports(session, tenant_config)
    Log.info("Done configuring schema")


def update_contexts(session: Client, new_tenant: dict, original_tenant: dict):
    """Creates or updates contexts"""
    # resolve dependencies
    contexts = new_tenant.get("contexts") or []
    name2context = {}
    dependencies = []
    for context in contexts:
        name = context.get("contextName")
        if name == "_ip2geo":
            continue
        name2context[name] = context
        depends_on = set()
        enrichments = context.get("enrichments") or []
        for enrichment in enrichments:
            for attr in enrichment.get("enrichedAttributes"):
                depends_on.add(attr.get("value").split(".")[0])
        dependencies.append((name, depends_on))

    new_tenant_clone = copy.deepcopy(new_tenant)
    new_tenant_clone["contexts"] = [name2context[name] for name in topological_sort(dependencies)]

    update_entity(
        "context",
        "contextName",
        new_tenant_clone,
        original_tenant,
        session.create_context,
        session.update_context,
    )


def update_signals(session, new_tenant: dict, original_tenant: dict):
    """Creates or updates signals"""
    update_entity(
        "signal",
        "signalName",
        new_tenant,
        original_tenant,
        session.create_signal,
        session.update_signal,
    )


def update_import_sources(session, new_tenant: dict, original_tenant: dict):
    """Creates or updates importSources"""
    update_entity(
        "importSource",
        "importSourceId",
        new_tenant,
        original_tenant,
        session.create_import_source,
        session.update_import_source,
        True,
    )


def update_import_destinations(session, new_tenant: dict, original_tenant: dict):
    """Creates or updates importDestinations"""
    update_entity(
        "importDestination",
        "importDestinationId",
        new_tenant,
        original_tenant,
        session.create_import_destination,
        session.update_import_destination,
        True,
    )


def update_flows(session: Client, new_tenant: dict, original_tenant: dict):
    """Creates or updates importFlowSpecs"""
    update_entity(
        "importFlowSpec",
        "importFlowId",
        new_tenant,
        original_tenant,
        session.create_import_flow_spec,
        session.update_import_flow_spec,
        True,
    )


def update_import_data_processors(session: Client, new_tenant: dict, original_tenant: dict):
    """Creates or updates importDataProcessors"""
    new_tenant_clone = copy.deepcopy(new_tenant)
    for processor in new_tenant_clone.get("importDataProcessors") or []:
        if processor.get("encoding") == "source_file" and processor.get("code"):
            with open(processor["code"], "r", encoding="UTF-8") as code_file:
                processor["code"] = code_file.read()
                processor["encoding"] = "plain"
    update_entity(
        "importDataProcessor",
        "processorName",
        new_tenant_clone,
        original_tenant,
        lambda conf: session.create_import_data_processor(
            conf.get("processorName"), conf.get("code")
        ),
        lambda name, conf: session.update_import_data_processor(
            conf.get("processorName"), conf.get("code")
        ),
        True,
    )


def update_reports(session: Client, new_tenant: dict):
    """Upserts reports"""
    section_1hr = {"sectionId": str(uuid.uuid4()), "timeRange": 3600000, "insightConfigs": []}
    section_1day = {"sectionId": str(uuid.uuid4()), "timeRange": 86400000, "insightConfigs": []}
    for report in new_tenant.get("reportConfigs") or []:
        fav = report.pop("fav", False)
        report_source = report.pop("source", None)
        session.put_report_config(report)
        if report_source == "signal":
            insight = {
                "insightId": str(uuid.uuid4()),
                "reportId": report.get("reportId"),
                "fav": fav,
            }
            section_1hr["insightConfigs"].append(insight)
            section_1day["insightConfigs"].append(insight)
    insight_configs = {"sections": [section_1hr, section_1day]}
    session.put_insight_configs("signal", insight_configs)


def update_entity(
    entity_type: str,
    entity_id_name: str,
    new_tenant: dict,
    original_tenant: dict,
    create_method,
    update_method,
    compare_on_client=False,
):
    """Generic method to update admin entities"""
    entities = new_tenant.get(f"{entity_type}s")
    if not entities:
        return
    Log.debug("-----")
    original_entities = {}
    for entity in original_tenant.get(f"{entity_type}s"):
        original_entities[entity.get(entity_id_name)] = entity

    new_entities = {}
    for entity in entities:
        entity_name = entity.get(entity_id_name)
        if entity_name:
            if entity_name in new_entities:
                raise ServiceError(
                    ErrorCode.GENERIC_CLIENT_ERROR,
                    f"The same {entity_id_name} appeared twice in {entity_type}s."
                    f" Check the schema JSON; name/id={entity_name}",
                )
            new_entities[entity_name] = entity
        if entity_name in original_entities:
            log_message = f"Updating {entity_type} : {entity_name} ... "
            if compare_on_client:
                orig_entity = original_entities.get(entity_name)
                if entity == orig_entity:
                    log_message += "identical"
                    continue
            try:
                update_method(entity_name, entity)
            except ServiceError as error:
                if error.error_code != ErrorCode.BAD_INPUT or not error.message.startswith(
                    "Requested config for change is identical"
                ):
                    raise
                log_message += "identical"
            else:
                log_message += "ok"
            Log.debug(log_message)
        else:
            log_message = f"Creating {entity_type} : {entity_name} ... "
            create_method(entity)
            log_message += "ok"
            Log.debug(log_message)


def topological_sort(source):
    """perform topological sort on elements.

    :arg source: list of ``(name, [list of dependencies])`` pairs
    :returns: list of names, with dependencies listed first
    """
    pending = [
        (name, set(deps)) for name, deps in source
    ]  # copy deps so we can modify set in-place
    emitted = []
    while pending:
        next_pending = []
        next_emitted = []
        for entry in pending:
            name, deps = entry
            deps.difference_update(emitted)  # remove deps we emitted last pass
            if deps:  # still has deps? recheck during next pass
                next_pending.append(entry)
            else:  # no more deps? time to emit
                yield name
                emitted.append(name)  # <-- not required, but helps preserve original ordering
                next_emitted.append(
                    name
                )  # remember what we emitted for difference_update() in next pass
        if not next_emitted:  # all entries have unmet deps, one of two things is wrong...
            raise ValueError(f"cyclic or missing dependency detected: {(next_pending,)}")
        pending = next_pending
        emitted = next_emitted


def create_schema(session, schema, populate_contexts_fn):
    # First delete old signals since they have dependencies on contexts.
    if "signals" in schema:
        for signal in schema["signals"]:
            signal_name = signal["signalName"]
            try:
                session.delete_signal(signal_name)
            except Exception:
                pass
    # Then delete old contexts and remaining items.
    if "contexts" in schema:
        for context in schema["contexts"]:
            context_name = context["contextName"]
            try:
                session.delete_context(context_name)
            except Exception:
                pass

        # Create schema items, starting with contexts.
        for context in schema["contexts"]:
            context_name = context["contextName"]
            Log.debug(f"Creating context {context_name}")
            session.create_context(context)

        # Now that contexts are created, populate them if a population function has been specified.
        if populate_contexts_fn:
            populate_contexts_fn(session)

    if "signals" in schema:
        for signal in schema["signals"]:
            signal_name = signal["signalName"]
            Log.debug(f"Creating signal {signal_name}")
            session.create_signal(signal)

    if "importDataProcessors" in schema:
        for processor in schema["importDataProcessors"]:
            processor_name = processor["processorName"]
            Log.debug(f"Creating import data processor {processor_name}")
            try:
                session.delete_import_data_processor(processor_name)
            except Exception:
                pass
            session.create_import_data_processor(processor_name, processor["code"])

    if "importDestinations" in schema:
        for import_destination in schema["importDestinations"]:
            Log.debug(f"Creating import destination {import_destination['importDestinationName']}")
            try:
                session.delete_import_destination(import_destination["importDestinationId"])
            except Exception:
                pass
            session.create_import_destination(import_destination)

    if "importSources" in schema:
        for import_source in schema["importSources"]:
            Log.debug(f"Creating import source {import_source['importSourceName']}")
            try:
                session.delete_import_source(import_source["importSourceId"])
            except Exception:
                pass
            session.create_import_source(import_source)

    if "importFlowSpecs" in schema:
        for flow in schema["importFlowSpecs"]:
            Log.debug(f"Creating import flow spec {flow['importFlowName']}")
            try:
                session.delete_import_flow_spec(flow["importFlowId"])
            except Exception:
                pass
            session.create_import_flow_spec(flow)
