from burp import IBurpExtender, IContextMenuFactory, ITab
from java.util import ArrayList
from javax.swing import (
    JMenuItem, JFileChooser, JOptionPane, JPanel, JScrollPane, JTable,
    JButton, JComboBox, BoxLayout, Box, JLabel, ListSelectionModel, JCheckBox
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension
import csv


class ReorderableTableModel(DefaultTableModel):
    def moveRow(self, start, end, to):
        if start == to or start < 0 or to < 0 or start >= self.getRowCount() or to >= self.getRowCount():
            return
        row = self.getDataVector().remove(start)
        self.getDataVector().insert(to, row)
        self.fireTableDataChanged()

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("API & Workflow Manager")
        self._invocation = None

        # Data structures for tab
        self.api_rows = []  # Each: [method, url, params]
        self.filtered_rows = []
        self.methods = set()
        self.selected_method = "ALL"
        
        # Duplicate control settings
        self.allow_duplicates = True  # Default to allowing duplicates

        self._init_tab()
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.addSuiteTab(self)

    # --- Context Menu ---
    def createMenuItems(self, invocation):
        self._invocation = invocation
        menu = ArrayList()
        menu.add(JMenuItem("Send APIs to Management Tab", actionPerformed=self.send_to_tab))
        menu.add(JMenuItem("Export API's as Manual Sheet", actionPerformed=self.export_to_csv))
        menu.add(JMenuItem("Export cURL to File", actionPerformed=self.export_curl_to_file))  
        return menu

    # --- Tab UI ---
    def getTabCaption(self):
        return "API Management"

    def getUiComponent(self):
        return self._main_panel

    def _init_tab(self):
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setPreferredSize(Dimension(950, 420))

        # Top: Filter and Duplicate Control
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        
        # Filter panel
        filter_panel = JPanel()
        filter_panel.setLayout(BoxLayout(filter_panel, BoxLayout.X_AXIS))
        filter_panel.add(Box.createHorizontalStrut(10))
        filter_label = JLabel("Filter by HTTP Method: ")
        filter_label.setPreferredSize(Dimension(160, 30))
        filter_panel.add(filter_label)
        self.method_filter = JComboBox(["ALL"])
        self.method_filter.setPreferredSize(Dimension(120, 30))
        self.method_filter.addActionListener(self._filter_changed)
        filter_panel.add(self.method_filter)
        filter_panel.add(Box.createHorizontalGlue())
        filter_panel.setMaximumSize(Dimension(1000, 40))
        
        # Duplicate control panel
        duplicate_panel = JPanel()
        duplicate_panel.setLayout(BoxLayout(duplicate_panel, BoxLayout.X_AXIS))
        duplicate_panel.add(Box.createHorizontalStrut(10))
        self.duplicate_checkbox = JCheckBox("Allow duplicate APIs", self.allow_duplicates)
        self.duplicate_checkbox.addActionListener(self._duplicate_setting_changed)
        duplicate_panel.add(self.duplicate_checkbox)
        duplicate_panel.add(Box.createHorizontalGlue())
        duplicate_panel.setMaximumSize(Dimension(1000, 30))
        
        top_panel.add(filter_panel)
        top_panel.add(duplicate_panel)

        # Center: Table
        self.table_model = ReorderableTableModel(
            ["Method", "URL", "Parameters"], 0
        )
        self.api_table = JTable(self.table_model)
        self.api_table.setFillsViewportHeight(True)
        self.api_table.setRowHeight(28)
        self.api_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        scroll = JScrollPane(self.api_table)

        # Right: Rearrangement/Remove/Add
        button_panel = JPanel()
        button_panel.setLayout(BoxLayout(button_panel, BoxLayout.Y_AXIS))
        button_panel.setPreferredSize(Dimension(160, 240))

        btn_size = Dimension(140, 36)
        up_btn = JButton("Move Up", actionPerformed=self._move_up)
        up_btn.setMaximumSize(btn_size)
        up_btn.setPreferredSize(btn_size)
        down_btn = JButton("Move Down", actionPerformed=self._move_down)
        down_btn.setMaximumSize(btn_size)
        down_btn.setPreferredSize(btn_size)
        add_btn = JButton("Add Api", actionPerformed=self._add_row)
        add_btn.setMaximumSize(btn_size)
        add_btn.setPreferredSize(btn_size)
        remove_btn = JButton("Remove", actionPerformed=self._remove_row)
        remove_btn.setMaximumSize(btn_size)
        remove_btn.setPreferredSize(btn_size)
        export_btn = JButton("Export Filtered APIs", actionPerformed=self._export_from_tab)
        export_btn.setMaximumSize(btn_size)
        export_btn.setPreferredSize(btn_size)
        workflow_btn = JButton("Add Workflow", actionPerformed=self._add_workflow)
        workflow_btn.setMaximumSize(btn_size)
        workflow_btn.setPreferredSize(btn_size)

        button_panel.add(Box.createVerticalStrut(10))
        button_panel.add(up_btn)
        button_panel.add(Box.createVerticalStrut(10))
        button_panel.add(down_btn)
        button_panel.add(Box.createVerticalStrut(10))
        button_panel.add(add_btn)
        button_panel.add(Box.createVerticalStrut(10))
        button_panel.add(remove_btn)
        button_panel.add(Box.createVerticalStrut(10))           
        button_panel.add(workflow_btn)
        button_panel.add(Box.createVerticalStrut(30))            
        button_panel.add(export_btn)
        button_panel.add(Box.createVerticalGlue())

        # Layout
        center_panel = JPanel(BorderLayout())
        center_panel.add(scroll, BorderLayout.CENTER)
        center_panel.add(button_panel, BorderLayout.EAST)

        self._main_panel.add(top_panel, BorderLayout.NORTH)
        self._main_panel.add(center_panel, BorderLayout.CENTER)

    # --- Duplicate Control ---
    def _duplicate_setting_changed(self, event):
        self.allow_duplicates = self.duplicate_checkbox.isSelected()
        self._callbacks.printOutput("Duplicate setting changed: {}".format("Allowed" if self.allow_duplicates else "Filtered"))

    def _is_duplicate_api(self, method, url, params):
        """Check if an API already exists in api_rows"""
        for existing_method, existing_url, existing_params in self.api_rows:
            if (existing_method == method and 
                existing_url == url and 
                sorted(existing_params) == sorted(params)):
                return True
        return False

    def _is_duplicate_workflow(self, workflow_name):
        """Check if a workflow already exists"""
        for existing_method, existing_url, existing_params in self.api_rows:
            if existing_method == workflow_name and existing_url == "" and not existing_params:
                return True
        return False

    # --- Tab Table Actions ---
    def _refresh_table(self):
        self.table_model.setRowCount(0)
        self.filtered_rows = []
        for row in self.api_rows:
            if self.selected_method == "ALL" or row[0] == self.selected_method:
                method, url, param_names = row
                param_str = ", ".join(param_names)
                self.table_model.addRow([method, url, param_str])
                self.filtered_rows.append(row)

    def _filter_changed(self, event):
        self.selected_method = self.method_filter.getSelectedItem()
        self._refresh_table()

    def _move_up(self, event):
        idx = self.api_table.getSelectedRow()
        if idx > 0:
            row = self.filtered_rows[idx]
            orig_idx = self.api_rows.index(row)
            if orig_idx > 0:
                self.api_rows[orig_idx], self.api_rows[orig_idx-1] = self.api_rows[orig_idx-1], self.api_rows[orig_idx]
                self._refresh_table()
                self.api_table.setRowSelectionInterval(idx-1, idx-1)

    def _move_down(self, event):
        idx = self.api_table.getSelectedRow()
        if idx < len(self.filtered_rows) - 1 and idx >= 0:
            row = self.filtered_rows[idx]
            orig_idx = self.api_rows.index(row)
            if orig_idx < len(self.api_rows) - 1:
                self.api_rows[orig_idx], self.api_rows[orig_idx+1] = self.api_rows[orig_idx+1], self.api_rows[orig_idx]
                self._refresh_table()
                self.api_table.setRowSelectionInterval(idx+1, idx+1)

    def _add_row(self, event):
        # Prompt user for Method, URL, Parameters
        method = JOptionPane.showInputDialog(None, "Enter HTTP Method (e.g., GET, POST):", "Add API", JOptionPane.PLAIN_MESSAGE)
        if method is None or not method.strip():
            return
        url = JOptionPane.showInputDialog(None, "Enter URL:", "Add API", JOptionPane.PLAIN_MESSAGE)
        if url is None or not url.strip():
            return
        params = JOptionPane.showInputDialog(None, "Enter Parameters (comma-separated):", "Add API", JOptionPane.PLAIN_MESSAGE)
        if params is None:
            return
        param_names = [p.strip() for p in params.split(",") if p.strip()]
        
        # Check for duplicates if not allowed
        if not self.allow_duplicates and self._is_duplicate_api(method.strip(), url.strip(), param_names):
            JOptionPane.showMessageDialog(None, "This API already exists and duplicates are not allowed.")
            return
            
        selected_idx = self.api_table.getSelectedRow()
        if selected_idx >= 0 and selected_idx < len(self.filtered_rows):
            # Find the corresponding index in api_rows
            ref_row = self.filtered_rows[selected_idx]
            api_idx = self.api_rows.index(ref_row)
            self.api_rows.insert(api_idx + 1, [method.strip(), url.strip(), param_names])
        else:
            self.api_rows.append([method.strip(), url.strip(), param_names])
        self._refresh_table()

    def _remove_row(self, event):
        selected_indices = self.api_table.getSelectedRows()
        if not selected_indices or len(selected_indices) == 0:
            return
        for idx in sorted(selected_indices, reverse=True):
            if idx < len(self.filtered_rows):
                row = self.filtered_rows[idx]
                if row in self.api_rows:
                    self.api_rows.remove(row)
        self._refresh_table()

    def write_csv(self, file_path, api_rows):   
        with open(file_path, "wb") as f:  # Change to binary mode
            writer = csv.writer(f)
            # Manually encode strings to UTF-8
            writer.writerow([
                "SR.NO.", "API", "Parameters",
                "Attack tried", "Steps/procedure",
                "Observation", "Status-(Found/Not found)"
            ])
            writer.writerow([""] * 7)
            sr_no = 1
            for method, url, params in api_rows:
                filtered_params = [p for p in params if getattr(p, 'getType', lambda: None)() != 2] if params and hasattr(params[0], 'getType') else params
                if url == "" and not filtered_params:
                    writer.writerow(["", method] + [""] * 5)
                    writer.writerow([""] * 7)
                else:
                    api_line = "{} {}".format(method, url)
                    writer.writerow([str(sr_no), api_line, ""] + [""] * 4)
                    for pname in filtered_params:
                        writer.writerow(["", "", str(pname)] + [""] * 4)
                    writer.writerow([""] * 7)
                    sr_no += 1

    def _export_from_tab(self, event):
        if not self.filtered_rows:
            JOptionPane.showMessageDialog(None, "No APIs to export.")
            return

        options = ["CSV", "cURL"]
        choice = JOptionPane.showOptionDialog(
            None,
            "Choose export format:",
            "Export Filtered APIs",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            None,
            options,
            options[0]
        )

        if choice == 0:
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Save CSV")
            result = file_chooser.showSaveDialog(None)
            if result != JFileChooser.APPROVE_OPTION:
                return
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".csv"):
                file_path += ".csv"
            try:
                self.write_csv(file_path, self.filtered_rows)
                JOptionPane.showMessageDialog(None, "Exported successfully to:\n" + file_path)
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Write error:\n" + str(e))

        elif choice == 1:  # cURL
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Save cURL commands to file")
            result = file_chooser.showSaveDialog(None)
            if result != JFileChooser.APPROVE_OPTION:
                return
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".txt"):
                file_path += ".txt"
            try:
                with open(file_path, "w") as f:  # Remove encoding parameter
                    for idx, (method, url, params) in enumerate(self.filtered_rows):
                        if url == "" and not params:
                            content = method
                        else:
                            content = "curl -i -s -k -X '{}' '{}'".format(method, url)
                        f.write("####\n{}\n".format(content))
                    f.write("####\n")
                JOptionPane.showMessageDialog(None, "cURL commands exported to: {}".format(file_path))
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Error exporting to file: {}".format(e))

    # --- Context Menu Actions ---
    def send_to_tab(self, event):
        messages = self._invocation.getSelectedMessages()
        if not messages:
            JOptionPane.showMessageDialog(None, "No HTTP requests selected.")
            return

        new_methods = set()
        added_count = 0
        skipped_count = 0
        
        for message in messages:
            try:
                req_info = self._helpers.analyzeRequest(message)
                url = req_info.getUrl()
                method = req_info.getMethod()
                params = req_info.getParameters()
                param_names = sorted(set(
                    p.getName() for p in params if p.getType() != 2
                ))
                
                # Check for duplicates if not allowed
                if not self.allow_duplicates and self._is_duplicate_api(method, url.toString(), param_names):
                    skipped_count += 1
                    continue
                    
                self.api_rows.append([method, url.toString(), param_names])
                new_methods.add(method)
                added_count += 1
                
            except Exception as e:
                self._callbacks.printOutput("Error: " + str(e))
                
        if new_methods:
            self.methods.update(new_methods)
            self.method_filter.removeAllItems()
            self.method_filter.addItem("ALL")
            for m in sorted(self.methods):
                self.method_filter.addItem(m)
                
        self._refresh_table()
        
        # Show results summary
        if skipped_count > 0:
            JOptionPane.showMessageDialog(None, 
                "Added {} APIs to tab.\nSkipped {} duplicates.".format(added_count, skipped_count))
        else:
            JOptionPane.showMessageDialog(None, "Added {} APIs to tab.".format(added_count))

    def export_to_csv(self, event):
        messages = self._invocation.getSelectedMessages()
        if not messages:
            JOptionPane.showMessageDialog(None, "No HTTP requests selected.")
            return

        # Ask user about duplicate handling for this export
        options = ["Include duplicates", "Remove duplicates"]
        choice = JOptionPane.showOptionDialog(
            None,
            "How to handle duplicate APIs?",
            "Duplicate Handling",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            None,
            options,
            options[0] if self.allow_duplicates else options[1]
        )
        
        include_duplicates = (choice == 0)

        api_rows = []
        seen_apis = set()
        added_count = 0
        skipped_count = 0
        
        for message in messages:
            try:
                req_info = self._helpers.analyzeRequest(message)
                url = req_info.getUrl()
                method = req_info.getMethod()
                params = req_info.getParameters()
                param_names = sorted(set(p.getName() for p in params if p.getType() != 2))
                
                api_key = (method, url.toString(), tuple(sorted(param_names)))
                
                # Check for duplicates if not including them
                if not include_duplicates:
                    if api_key in seen_apis:
                        skipped_count += 1
                        continue
                    seen_apis.add(api_key)
                
                api_rows.append([method, url.toString(), param_names])
                added_count += 1
                
            except Exception as e:
                self._callbacks.printOutput("Error: " + str(e))

        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Save CSV")
        result = file_chooser.showSaveDialog(None)
        if result != JFileChooser.APPROVE_OPTION:
            return

        file_path = file_chooser.getSelectedFile().getAbsolutePath()
        if not file_path.endswith(".csv"):
            file_path += ".csv"

        try:
            self.write_csv(file_path, api_rows)
            if skipped_count > 0:
                JOptionPane.showMessageDialog(None, 
                    "Exported {} APIs to CSV.\nSkipped {} duplicates.".format(added_count, skipped_count))
            else:
                JOptionPane.showMessageDialog(None, "Exported {} APIs to CSV.".format(added_count))
        except Exception as e:
            JOptionPane.showMessageDialog(None, "Write error:\n" + str(e))

    # --- cURL Export Feature ---
    def convert_to_curl(self, method, url, headers, body):
        curl_parts = ["curl -i -s -k"]
        curl_parts.append("-X $'{0}'".format(method))

        content_type = None
        for header in headers:
            if ": " in header:
                key, value = header.split(": ", 1)
                if key.lower() not in ['content-length', 'host', 'connection']:
                    escaped_value = value.replace("'", "'\"'\"'")
                    curl_parts.append("-H '{}: {}'".format(key, escaped_value))
                if key.lower() == "content-type":
                    content_type = value.strip().lower()

        if content_type and "multipart/form-data" in content_type:
            return None

        if body and len(body) > 0:
            try:
                sanitized_body = body.replace("'", "'\"'\"'")
                if content_type and "application/json" in content_type:
                    curl_parts.append("--data $'{0}'".format(sanitized_body))
                else:
                    curl_parts.append("--data-binary $'{0}'".format(sanitized_body))
            except Exception as e:
                self._callbacks.printOutput("Body processing error: {}".format(e))

        curl_parts.append("$'{0}'".format(url))
        return " ".join(curl_parts)

    def export_curl_to_file(self, event):
        http_traffic = self._invocation.getSelectedMessages()
        if not http_traffic:
            JOptionPane.showMessageDialog(None, "No HTTP requests selected.")
            return

        # Ask user about duplicate handling for this export
        options = ["Include duplicates", "Remove duplicates"]
        choice = JOptionPane.showOptionDialog(
            None,
            "How to handle duplicate APIs?",
            "Duplicate Handling",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            None,
            options,
            options[0] if self.allow_duplicates else options[1]
        )
        
        include_duplicates = (choice == 0)

        cURL_commands = []
        seen_commands = set()
        added_count = 0
        skipped_count = 0
        
        for message in http_traffic:
            try:
                request = message.getRequest()
                if request is None:
                    continue

                request_info = self._helpers.analyzeRequest(message)
                headers = list(request_info.getHeaders())
                body_bytes = request[request_info.getBodyOffset():]
                body = self._helpers.bytesToString(body_bytes) if body_bytes else ""
                url = str(request_info.getUrl())
                method = request_info.getMethod()

                curl_command = self.convert_to_curl(method, url, headers, body)
                if curl_command:
                    # Check for duplicates if not including them
                    if not include_duplicates:
                        if curl_command in seen_commands:
                            skipped_count += 1
                            continue
                        seen_commands.add(curl_command)
                    
                    cURL_commands.append(curl_command)
                    added_count += 1

            except Exception as e:
                self._callbacks.printOutput("Error processing request: {}".format(e))

        if cURL_commands:
            try:
                file_path = self.get_output_file_path()
                if not file_path:
                    self._callbacks.printOutput("Export canceled by user.")
                    return

                with open(file_path, "w") as f:
                    for curl in cURL_commands:
                        f.write("####\n")
                        f.write(curl + "\n")
                    f.write("####\n")

                if skipped_count > 0:
                    JOptionPane.showMessageDialog(None, 
                        "Exported {} cURL commands.\nSkipped {} duplicates.".format(added_count, skipped_count))
                else:
                    JOptionPane.showMessageDialog(None, "Exported {} cURL commands.".format(added_count))
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Error exporting to file: {}".format(e))
        else:
            JOptionPane.showMessageDialog(None, "No cURL commands generated (possibly due to multipart requests).")

    def get_output_file_path(self):
        chooser = JFileChooser()
        chooser.setDialogTitle("Save cURL commands to file")
        result = chooser.showSaveDialog(None)
        if result == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".txt"):
                file_path += ".txt"
            return file_path
        else:
            return None

    def _add_workflow(self, event):
        workflow = JOptionPane.showInputDialog(None, "Enter Workflow Name:", "Add Workflow", JOptionPane.PLAIN_MESSAGE)
        if workflow is None or not workflow.strip():
            return
            
        # Check for duplicate workflow if not allowed
        if not self.allow_duplicates and self._is_duplicate_workflow(workflow.strip()):
            JOptionPane.showMessageDialog(None, "This workflow already exists and duplicates are not allowed.")
            return
            
        selected_idx = self.api_table.getSelectedRow()
        if selected_idx >= 0 and selected_idx < len(self.filtered_rows):
            ref_row = self.filtered_rows[selected_idx]
            api_idx = self.api_rows.index(ref_row)
            self.api_rows.insert(api_idx + 1, [workflow.strip(), "", []])
        else:
            self.api_rows.append([workflow.strip(), "", []])
        self._refresh_table()