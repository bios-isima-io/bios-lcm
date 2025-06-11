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

from io import StringIO

from interactive import select_hosts
from lib.common import initialize_lcm, run_remote
from prompt_toolkit.application import Application
from prompt_toolkit.document import Document
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import HSplit, VSplit, Window, WindowAlign
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import LayoutDimension as D
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import HorizontalLine, SearchToolbar, TextArea, VerticalLine


def main():
    config = initialize_lcm()
    # Get the list of hosts to run commands on.
    (group_str, hosts) = select_hosts(config)
    if hosts is None:
        return

    hosts_string = group_str + " ("
    for host in hosts:
        hosts_string += host["name"] + ", "
    hosts_string = hosts_string[:-2]  # Remove the last comma and space.
    hosts_string += ")"

    def get_statusbar_text():
        return [
            (
                "class:status",
                f"Cluster: {config['cluster_name']}           Ctrl-C to exit.         "
                + f"Hosts: {hosts_string}",
            )
        ]

    # The layout.
    search_field = SearchToolbar()  # For reverse search.
    input_field = TextArea(
        height=1,
        prompt="bash> ",
        style="class:input-field",
        multiline=False,
        wrap_lines=False,
        search_field=search_field,
    )

    all_output_fields = {}
    all_output_texts = {}

    def create_output_fields(hosts, output_fields_list):
        for host in hosts:
            host_friendly_name = host["name"]
            host_title = Window(
                content=FormattedTextControl(host_friendly_name),
                align=WindowAlign.CENTER,
                height=D.exact(1),
                style="bg:#9999ff ansiblack",
            )
            output_field = TextArea(scrollbar=True)
            all_output_texts[host_friendly_name] = "Welcome! Enter command to execute.\n\n"
            output_field.buffer.document = Document(text=all_output_texts[host_friendly_name])
            all_output_fields[host_friendly_name] = output_field
            output_fields_list.append(host_title)
            output_fields_list.append(output_field)

    left_outputs = []
    right_outputs = []
    left_hosts = int(len(hosts) / 2)
    create_output_fields(hosts[:left_hosts], left_outputs)
    create_output_fields(hosts[left_hosts:], right_outputs)

    all_containers = []
    if left_hosts == 0:
        all_containers.extend(right_outputs)
    else:
        all_containers.append(
            VSplit(
                [
                    HSplit(left_outputs),
                    VerticalLine(),
                    HSplit(right_outputs),
                ]
            )
        )

    remaining_containers = [
        HorizontalLine(),
        input_field,
        search_field,
        # The bottom status bar.
        Window(
            content=FormattedTextControl(get_statusbar_text),
            height=D.exact(1),
            style="class:status",
        ),
    ]
    all_containers.extend(remaining_containers)
    root_container = HSplit(all_containers)

    # Input field accept handler.
    def accept(buff):
        del buff
        command = input_field.text
        for host in hosts:
            result_buffer = StringIO()
            new_text = "---------------- " + command + "\n"
            try:
                run_remote(host, command, out_stream=result_buffer)
            except Exception:
                pass
            # Add output text to output buffer.
            new_text = new_text + result_buffer.getvalue() + "\n"
            host_friendly_name = host["name"]
            all_output_texts[host_friendly_name] = all_output_texts[host_friendly_name] + new_text
            output_field = all_output_fields[host_friendly_name]
            output_field.buffer.document = Document(text=all_output_texts[host_friendly_name])

    input_field.accept_handler = accept

    bindings = KeyBindings()

    @bindings.add("c-c")
    def _(event):
        "Pressing Ctrl-C will exit the text user interface."
        event.app.exit()

    style = Style(
        [
            ("input-field", "bg:#000000 #ffffff"),
            ("status", "reverse"),
        ]
    )

    # Run application for text user interface.
    application = Application(
        layout=Layout(root_container, focused_element=input_field),
        key_bindings=bindings,
        style=style,
        enable_page_navigation_bindings=True,
        mouse_support=True,
        full_screen=True,
    )
    application.run()


if __name__ == "__main__":
    main()
