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

import cmd
import copy
import functools
import os
import pprint
import sys
from typing import Any, Dict, List

import bios
import yaml
from bios import Client, ErrorCode, ServiceError


class AppSchemaManager(cmd.Cmd):
    """App schema manager"""

    prompt = "app-master> "

    IMPORT_SCHEMA_KEYS = [
        ("importSources", "importSourceId"),
        ("importDestinations", "importDestinationId"),
        ("importFlowSpecs", "importFlowId"),
        ("importDataProcessors", "processorName"),
    ]

    def __init__(
        self,
        endpoint: str,
        app_master_email: str,
        app_master_password: str,
        admin_email: str,
        admin_password: str,
    ):
        super().__init__()
        self.prompt = f"{app_master_email} > "
        self._endpoint = endpoint
        self._email = app_master_email
        self._password = app_master_password
        self._admin_email = admin_email
        self._admin_password = admin_password
        self._session = None
        self._admin_session = None
        self._master_tenant_name = None

    def start_session(self) -> "AppSchemaManager":
        """Get an established session"""
        if not self._session:
            self._session = bios.login(self._endpoint, self._email, self._password)
            self._admin_session = bios.login(
                self._endpoint, self._admin_email, self._admin_password
            )
            self.prompt = f"{self._email} ({self._get_master_tenant_name()}) > "
        return self

    def _get_master_tenant_name(self):
        return self._session.session.get_tenant_name()

    def do_list_app_tenants(self, _):
        """Lists app tenants that the app master looks after"""
        pprint.pprint(self._session.list_app_tenants())

    def do_check_streams(self, line):
        """Usage: check_streams [--include-all-missing]"""
        tokens = line.split()
        ignore_all_missing = True
        while len(tokens) > 0 and tokens[0].startswith("-"):
            option = tokens[0]
            tokens = tokens[1:]
            if option == "--include-all-missing":
                ignore_all_missing = False
            else:
                self.do_help("check_streams")
                return

        # TODO(Naoki): Add option to "ignore-all-missing"
        app_tenants = self._session.list_app_tenants()
        num_app_tenants = len(app_tenants)

        result_app_signals, result_extra_signals = self._check_signals(app_tenants)
        result_app_contexts, result_extra_contexts = self._check_contexts(app_tenants)
        self._print_results(
            "app signals", "signalName", result_app_signals, ignore_all_missing, num_app_tenants
        )
        self._print_results(
            "app contexts", "contextName", result_app_contexts, ignore_all_missing, num_app_tenants
        )
        self._print_results(
            "extra signals",
            "signalName",
            result_extra_signals,
            ignore_all_missing,
            num_app_tenants,
        )
        self._print_results(
            "extra contexts",
            "contextName",
            result_extra_contexts,
            ignore_all_missing,
            num_app_tenants,
        )

        print("")

    def do_get(self, line):
        """Usage get [options] <signals|contexts|imports> <tenant|master> [stream [..]]
        options:
          --append <file> : Append signals/contexts to file
        """
        tokens = line.split()
        out_file = None
        while len(tokens) > 0 and tokens[0].startswith("-"):
            option = tokens[0]
            tokens = tokens[1:]
            if option == "--append":
                if len(tokens) < 1:
                    self.do_help("get")
                    return
                out_file = tokens[0]
                tokens = tokens[1:]
            else:
                print(f"Unknown option: {option}")
                self.do_help("get")
                return
        if len(tokens) < 2:
            self.do_help("get")
            return
        stream_type = tokens[0]
        tenant_name = tokens[1]
        if tenant_name == "master":
            tenant_name = self._get_master_tenant_name()
        if stream_type != "imports":
            # if len(tokens) < 3:
            #     self.do_help("get")
            #     return
            stream_names = tokens[2:]
        schema = {}
        if out_file:
            try:
                with open(out_file, "r", encoding="utf-8") as file:
                    schema = yaml.safe_load(file)
            except FileNotFoundError:
                print(f"File {out_file} not found, would create one")
        try:
            if stream_type in {"signals", "contexts"}:
                self._get_streams(stream_type, tenant_name, stream_names, schema)
            elif stream_type == "imports":
                self._get_imports(tenant_name, schema)
            if out_file:
                with open(out_file, "w", encoding="utf-8") as file:
                    yaml.dump(schema, file, sort_keys=False)
                print(f"result appended to {out_file}")
            else:
                print(yaml.dump(schema, sort_keys=False))
        except ServiceError as err:
            print(err)

    def _get_streams(
        self, stream_type: str, tenant_name: str, stream_names: List[str], schema: dict
    ):
        prop = f"{stream_type[:-1]}Name"
        stream_map = {stream.get(prop): stream for stream in schema.setdefault(stream_type, [])}

        session = (
            self._session
            if tenant_name == self._get_master_tenant_name()
            else self._session.for_tenant(tenant_name)
        )

        if stream_type == "signals":
            result = session.get_signals(names=stream_names, include_internal=True, detail=True)
        elif stream_type == "contexts":
            result = session.get_contexts(names=stream_names, include_internal=True, detail=True)
        for stream in result:
            name = stream.get("signalName") or stream.get("contextName")
            if name and (name.startswith("_") or name.startswith("audit")):
                continue
            stream.pop("version", None)
            stream.pop("biosVersion", None)
            stream.pop("isInternal", None)
            stream_map[stream.get(prop)] = stream
        schema[stream_type] = list(stream_map.values())

    def _get_imports(self, tenant_name: str, schema: dict):
        if tenant_name != self._get_master_tenant_name():
            print("Import config can be retrieved only from master tenant")
            return

        schema_map = {}
        for collection_name, key in self.IMPORT_SCHEMA_KEYS:
            schema_map[collection_name] = {
                stream.get(key): stream for stream in schema.setdefault(collection_name, [])
            }

        tenant = self._session.get_tenant(detail=True)
        for collection_name, key in self.IMPORT_SCHEMA_KEYS:
            collection = tenant.get(collection_name)
            for entry in collection:
                schema_map[collection_name][entry.get(key)] = entry
            schema[collection_name] = list(schema_map[collection_name].values())

    def do_delete(self, line):
        """Usage delete <signal|context> <tenant> <stream>"""
        tokens = line.split()
        if len(tokens) < 3:
            self.do_help("delete")
            return
        stream_type = tokens[0]
        tenant_name = tokens[1]
        stream_name = tokens[2]
        try:
            if stream_type == "signal":
                self._session.for_tenant(tenant_name).delete_signal(stream_name)
            elif stream_type == "context":
                self._session.for_tenant(tenant_name).delete_context(stream_name)
            else:
                print(f"Unknown stream type: {stream_type}")
                self.do_help("delete")
                return
        except ServiceError as err:
            print(err)

    def do_apply(self, line):
        """Usage: apply [options] <schema_yaml>
        options:
          --sf      : Sets features for app master tenant (unnecessary but for reference?)
          --dry-run : Dry run
        set property 'toDelete' to delete a stream in the schema file.
        """
        tokens = line.split()
        set_features_for_master = False
        dry_run = False
        while len(tokens) > 0 and tokens[0].startswith("-"):
            option = tokens[0]
            tokens = tokens[1:]
            if option == "--sf":
                set_features_for_master = True
            elif option == "--dry-run":
                dry_run = True
            else:
                print(f"Unknown option: {option}")
                self.do_help("apply")
                return

        if len(tokens) < 1 or tokens[0] == "":
            self.do_help("apply")
            return
        schema_file_name = tokens[0]

        try:
            with open(schema_file_name, "r", encoding="utf-8") as file:
                source_schema = yaml.safe_load(file)
        except IOError as err:
            print(err)
            return

        master_schema = self._make_master_schema(source_schema, set_features_for_master)
        app_tenant_schema = self._make_app_tenant_schema(source_schema)

        if dry_run:
            print("\n## Master schema:\n")
            print(yaml.dump(master_schema, sort_keys=False))
            print("\n## App tenant schema:\n")
            print(yaml.dump(app_tenant_schema, sort_keys=False))
            return

        self._apply_app_tenant_schema(app_tenant_schema)
        self._apply_master_schema(master_schema)

    def _apply_app_tenant_schema(self, schema: dict):
        app_tenants = self._session.list_app_tenants()
        for tenant in app_tenants:
            session = self._session.for_tenant(tenant)
            self._apply_schema(session, schema)
            print("")

    def _apply_master_schema(self, schema: dict):
        self._apply_schema(self._admin_session, schema)
        print("")

    def _apply_schema(self, session: Client, schema):
        materialized_context_names = set()
        materialized_contexts = []
        audit_signals = []
        regular_contexts = []
        regular_signals = []
        for signal in schema.get("signals"):
            for feature in (signal.get("postStorageStage") or {}).get("features") or []:
                fac = feature.get("featureAsContextName")
                if fac:
                    materialized_context_names.add(fac.lower())
            if signal.get("signalName").startswith("audit"):
                audit_signals.append(signal)
            else:
                regular_signals.append(signal)
        for context in schema.get("contexts"):
            if context.get("contextName").lower() in materialized_context_names:
                materialized_contexts.append(context)
            else:
                regular_contexts.append(context)
        # cleanup the schema first
        if schema.get("importFlowSpecs"):
            self._cleanup(
                schema.get("importFlowSpecs"),
                "importFlowId",
                session,
                session.delete_import_flow_spec,
            )
        if schema.get("importDataProcessors"):
            self._cleanup(
                schema.get("importDataProcessors"),
                "processorName",
                session,
                session.delete_import_data_processor,
            )
        if schema.get("importSources"):
            self._cleanup(
                schema.get("importSources"),
                "importSourceId",
                session,
                session.delete_import_source,
            )
        if schema.get("importDestinations"):
            self._cleanup(
                schema.get("importDestinations"),
                "importDestinationId",
                session,
                session.delete_import_destination,
            )
        self._cleanup(regular_signals, "signalName", session, session.delete_signal)
        self._cleanup(regular_contexts, "contextName", session, session.delete_context)
        self._cleanup(audit_signals, "signalName", session, session.delete_signal)
        self._cleanup(materialized_contexts, "contextName", session, session.delete_context)

        # then set up
        self._setup(materialized_contexts, "contextName", session, session.create_context)
        self._setup(audit_signals, "signalName", session, session.create_signal)
        self._setup(regular_contexts, "contextName", session, session.create_context)
        self._setup(regular_signals, "signalName", session, session.create_signal)
        if schema.get("importSources"):
            self._setup(
                schema.get("importSources"),
                "importSourceId",
                session,
                session.create_import_source,
            )
        if schema.get("importDestinations"):
            self._setup(
                schema.get("importDestinations"),
                "importDestinationId",
                session,
                session.create_import_destination,
            )
        if schema.get("importDataProcessors"):
            self._setup_import_processor(
                schema.get("importDataProcessors"), "processorName", session
            )
        if schema.get("importFlowSpecs"):
            self._setup(
                schema.get("importFlowSpecs"),
                "importFlowId",
                session,
                session.create_import_flow_spec,
            )

    def _setup(self, entities: List[dict], key_for_id: str, session, method):
        if not entities:
            return
        tenant = session.get_tenant_name()
        for entity in entities:
            if entity.get("toDelete"):
                continue
            try:
                identifier = entity.get(key_for_id)
                print(f"  ({tenant}) : creating {key_for_id} = {identifier} ..", end="")
                method(entity)
                print("done")
            except ServiceError as err:
                print(f" ERROR: {err}")

    def _setup_import_processor(self, entities: List[dict], key_for_id: str, session):
        if not entities:
            return
        tenant = session.get_tenant_name()
        for entity in entities:
            if entity.get("toDelete"):
                continue
            try:
                identifier = entity.get(key_for_id)
                print(f"  ({tenant}) : creating {key_for_id} = {identifier} ..", end="")
                session.create_import_data_processor(identifier, raw_config=entity)
                print("done")
            except ServiceError as err:
                print(f" ERROR: {err}")

    def _cleanup(self, entities: List[dict], key_for_id: str, session, method):
        if not entities:
            return
        tenant = session.get_tenant_name()
        for entity in entities:
            identifier = entity.get(key_for_id)
            try:
                print(f"  ({tenant}) : deleting {key_for_id} = {identifier} ..", end="")
                method(identifier)
                print("done")
            except ServiceError as err:
                if err.error_code not in {ErrorCode.NOT_FOUND, ErrorCode.NO_SUCH_STREAM}:
                    print(f" ERROR: {err}")
                else:
                    print("deleted already")

    def _make_master_schema(self, source_schema: dict, set_features: bool) -> dict:
        schema = copy.deepcopy(source_schema)
        fac_names = set()
        for signal in schema.get("signals") or []:
            for feature in (signal.get("postStorageStage") or {}).get("features") or []:
                if feature.get("materializedAs") and not set_features:
                    fac_names.add(feature.get("featureAsContextName"))
            if not set_features:
                signal.pop("postStorageStage", None)

        for context in schema.get("contexts") or []:
            if context.get("contextName") in fac_names:
                context["toDelete"] = True

        return schema

    def _make_app_tenant_schema(self, source_schema: dict) -> dict:
        schema = copy.deepcopy(source_schema)
        for collection_name, _ in self.IMPORT_SCHEMA_KEYS:
            schema[collection_name] = []
        return schema

    def do_update_signal(self, line):
        """Usage: update_signal [options] <schema_yaml>
        options:
          --tenants : comma separated target tenants (default: all app tenants)
        """
        tokens = line.split()
        app_tenants = None
        while len(tokens) > 0 and tokens[0].startswith("-"):
            option = tokens[0]
            tokens = tokens[1:]
            if option == "--tenants":
                if len(tokens) == 0:
                    self.do_help("update_signal")
                    return
                app_tenants = tokens[0].split(",")
                tokens = tokens[1:]
            else:
                print(f"Unknown option: {option}")
                self.do_help("update_signal")
                return

        if len(tokens) < 1 or tokens[0] == "":
            self.do_help("update_signal")
            return
        schema_file_name = tokens[0]

        try:
            with open(schema_file_name, "r", encoding="utf-8") as file:
                source_schema = yaml.safe_load(file)
        except IOError as err:
            print(err)
            return

        if app_tenants is None:
            app_tenants = self._session.list_app_tenants()
        max_tenant_name_length = 0
        for tenant in app_tenants:
            max_tenant_name_length = max(max_tenant_name_length, len(tenant))
        signal_name = source_schema.get("signalName")
        for tenant in app_tenants:
            to_create = False
            padding = " " * (max_tenant_name_length - len(tenant))
            try:
                session = self._session.for_tenant(tenant)
                session.update_signal(signal_name, source_schema)
                print(f"({tenant}){padding} : Updating signalName = {signal_name} ..done")
            except ServiceError as error:
                if error.error_code == ErrorCode.BAD_INPUT and error.message.startswith(
                    "Requested config for change is identical"
                ):
                    print(f"({tenant}){padding} : Updating signalName = {signal_name} ..identical")
                elif error.error_code == ErrorCode.NO_SUCH_STREAM:
                    to_create = True
                else:
                    print(f"Update {signal_name} for tenant {tenant} -- ERROR: {error}")
            if not to_create:
                continue
            # stream does not exist, create one
            try:
                print(f"({tenant}){padding} : Creating signalName = {signal_name}", end="")
                session.create_signal(source_schema)
                print(" ..done")
            except ServiceError as error:
                print(f" ..ERROR: {error}")

    def do_show(self, line):
        """Usage: show <app_tenant_or_domain>"""
        tokens = line.split()
        if len(tokens) < 1 or tokens[0] == "":
            self.do_help("show")
            return
        tenant_or_domain = tokens[0]
        domain = tenant_or_domain
        try:
            tenant = self._session.get_tenant(tenant_name=tenant_or_domain, detail=True)
            domain = tenant.get("domain")
        except ServiceError as err:
            if err.error_code not in {ErrorCode.NO_SUCH_TENANT, ErrorCode.FORBIDDEN}:
                print("ERROR: {err}")
        statement = bios.isql().select().from_context("merchants").where(keys=[[domain]]).build()
        response = self._session.execute(statement).to_dict()
        if len(response) == 0:
            print(f"No such tenant or domain: {tenant_or_domain}")
            return
        print("")
        key_length = functools.reduce(
            lambda length, key: max(length, len(key)), response[0].keys(), 0
        )
        for key, value in response[0].items():
            this_key = key
            for _ in range(key_length - len(key)):
                this_key += " "
            print(f"    {this_key} : {value}")
        print("")

    def do_redact_tenant(self, line):
        """Usage: redact_tenant [app_tenant_or_domain] -- Deletes all resources for a tenant
        Following resources would be deleted:
          - entry in context "tenants"
          - entry in context "merchants"
          (not yet covered, to be supported in the future)
          - tenant
        """
        tokens = line.split()
        interactive_mode = len(tokens) < 1 or tokens[0] == ""
        try:
            # determine target tenant
            if interactive_mode:
                tenant_names = self._session.list_app_tenants()
                print("Domains:")
                domains = {}
                for tenant_name in tenant_names:
                    tenant = self._session.get_tenant(tenant_name=tenant_name, detail=True)
                    domain = tenant.get("domain")
                    print(f"  {domain}")
                    domains[domain] = tenant
                print("")
                while True:
                    try:
                        domain = input("Choose domain: ")
                    except EOFError:
                        print("\nCanceled")
                        return
                    if domain not in domains:
                        print("No such domain")
                        continue
                    tenant_name = domains.get(domain).get("tenantName")
                    break
            else:
                tenant_or_domain = tokens[0]
                domain = tenant_or_domain
                try:
                    tenant = self._session.get_tenant(tenant_name=tenant_or_domain, detail=True)
                    tenant_name = tenant.get("tenantName")
                    domain = tenant.get("domain")
                except ServiceError as err:
                    if err.error_code not in {ErrorCode.NO_SUCH_TENANT, ErrorCode.FORBIDDEN}:
                        raise
                    statement = (
                        bios.isql()
                        .select()
                        .from_context("merchants")
                        .where(keys=[[domain]])
                        .build()
                    )
                    response = self._session.execute(statement).to_dict()
                    if len(response) == 0:
                        print(f"No such tenant or domain: {tenant_or_domain}")
                        return
                    tenant_name = response[0].get("tenantName")
            print(f"tenant: {tenant_name}")
            print(f"domain: {domain}")
            print("\nDeleting tenant is not supported yet. Do it manually.")
            self._session.execute(
                bios.isql().delete().from_context("merchants").where([[domain]]).build()
            )
            self._session.execute(
                bios.isql().delete().from_context("tenants").where([[domain]]).build()
            )
            print("Deleting tenant is not supported yet. Delete it manually")
        except ServiceError as err:
            print(f"Error: {err}")
            return

    def do_quit(self, _):
        """Terminates the session"""
        return True

    def do_exit(self, _):
        """Terminates the session"""
        return True

    def do_EOF(self, _):  # pylint: disable=(invalid-name)
        """Terminates the session"""
        print("")
        return True

    def _check_signals(self, app_tenants: List[str]):
        app_signals = {}
        master_signals = [
            signal
            for signal in self._session.get_signals(include_internal=True, detail=True)
            if not signal["signalName"].startswith("_")
            and not signal["signalName"].startswith("audit")
        ]
        for tenant in app_tenants:
            signals = self._session.for_tenant(tenant).get_signals(
                include_internal=True, detail=True
            )
            for signal in signals:
                signal_name = signal.get("signalName")
                if signal_name.startswith("_") or signal_name.startswith("audit"):
                    continue
                signal_info = app_signals.setdefault(signal_name, {})
                signal_info[tenant] = signal

        return self._check_stream_consistency(
            master_signals, app_tenants, app_signals, "signalName"
        )

    def _check_contexts(self, app_tenants: List[str]):
        app_contexts = {}
        master_contexts = [
            context
            for context in self._session.get_contexts(include_internal=True, detail=True)
            if not context["contextName"].startswith("_")
        ]
        for tenant in app_tenants:
            contexts = self._session.for_tenant(tenant).get_contexts(
                include_internal=True, detail=True
            )
            for context in contexts:
                context_name = context.get("contextName")
                if context_name.startswith("_") or context_name.startswith("audit"):
                    continue
                context_info = app_contexts.setdefault(context_name, {})
                context_info[tenant] = context

        return self._check_stream_consistency(
            master_contexts, app_tenants, app_contexts, "contextName"
        )

    def _check_stream_consistency(
        self,
        master_streams: List[dict],
        app_tenants: List[str],
        app_streams: Dict[str, Dict[str, dict]],
        stream_name_property: str,
    ):
        in_master_result = []
        for master_signal in master_streams:
            stream_name = master_signal.get(stream_name_property)
            found_signals = app_streams.pop(stream_name, {})
            issues = {
                stream_name_property: stream_name,
                "missing": ([], []),
                "inconsistent with master": [],
            }
            prev = None
            for tenant_name in app_tenants:
                stream = found_signals.get(tenant_name)
                if not stream:
                    issues["missing"][0].append(tenant_name)
                    continue
                issues["missing"][1].append(tenant_name)
                stream.pop("version", None)
                stream.pop("biosVersion", None)
                if prev:
                    if prev != stream:
                        issues["inconsistent among app tenants"] = True
                else:
                    prev = stream
                master_copy = copy.deepcopy(master_signal)
                master_copy.pop("version", None)
                master_copy.pop("biosVersion", None)
                master_copy.pop("postStorageStage", None)
                app_copy = copy.deepcopy(stream)
                app_copy.pop("postStorageStage", None)
                if master_copy != app_copy:
                    issues["inconsistent with master"].append(tenant_name)
            in_master_result.append(issues)

        extra_signals = []
        for stream_name, signals in app_streams.items():
            if stream_name.startswith("_") or stream_name.startswith("audit"):
                continue
            prev = None
            issues = {stream_name_property: stream_name, "missing": ([], [])}
            for tenant_name in app_tenants:
                stream = signals.get(tenant_name)
                if not stream:
                    issues["missing"][0].append(tenant_name)
                    continue
                issues["missing"][1].append(tenant_name)
                stream.pop("version", None)
                stream.pop("biosVersion", None)
                if prev:
                    if prev != stream:
                        issues["inconsistent among app tenants"] = True
                else:
                    prev = stream
            extra_signals.append(issues)
        return in_master_result, extra_signals

    def _print_results(
        self,
        type_name: str,
        stream_name_property: str,
        result_entries: List[Dict[str, Any]] | None,
        ignore_all_missing: bool,
        num_app_tenants: int,
    ):
        if result_entries:
            print(f"\n{type_name}:")
            for result_entry in result_entries:
                signal_name = result_entry.get(stream_name_property)
                missing, existing = result_entry.get("missing")
                inconsistent_with_master = result_entry.get("inconsistent with master")
                inconsistent_among_apps = result_entry.get("inconsistent among app tenants")
                is_ok = (
                    not missing and not inconsistent_with_master and not inconsistent_among_apps
                )
                if not is_ok and ignore_all_missing:
                    all_missing = missing and len(missing) == num_app_tenants
                    if (
                        all_missing
                        and not inconsistent_with_master
                        and not inconsistent_among_apps
                    ):
                        continue
                mark = "v" if is_ok else "x"
                print(f"  {mark} {signal_name}")
                if missing:
                    print(f"        missing: {missing} (existing: {existing})")
                if inconsistent_with_master:
                    print(f"        inconsistent with master: {inconsistent_with_master}")
                if inconsistent_among_apps:
                    print("        inconsistent among app tenants: true")


def usage(argv: List[str]):
    print(
        f"Usage: {os.path.basename(argv[0])} <endpoint> <app-master-email> <app-master-password>"
        " <tenant-admin-email> <tenant-admin-pass>"
    )
    sys.exit(1)


def main(argv: List[str]):
    if len(argv) < 6:
        usage(argv)
    endpoint = argv[1]
    app_master_email = argv[2]
    app_master_password = argv[3]
    admin_email = argv[4]
    admin_password = argv[5]
    AppSchemaManager(
        endpoint, app_master_email, app_master_password, admin_email, admin_password
    ).start_session().cmdloop()


if __name__ == "__main__":
    main(sys.argv)
