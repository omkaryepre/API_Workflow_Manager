<div align="left">

**🔐 API & Workflow Manager — Burp Suite Extension**

API & Workflow Manager is a Burp Suite extension that provides centralized management and organization for API endpoints during security testing. It allows security professionals to collect, categorize, and export HTTP requests with workflow labels, enabling structured testing methodologies and comprehensive documentation through CSV and cURL exports.

**Key capabilities:**

- Collect and organize APIs from Proxy/Repeater 
- Add workflow markers to structure testing phases 
- Filter and manage endpoints by HTTP method    
- Export to manual testing sheets or cURL commands 
- Control duplicate entries for clean inventories 

**Perfect for API security testing where organized workflow management and documentation are essential.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Professional-orange)](#)
[![Python](https://img.shields.io/badge/Python-2.7%20(Jython)-yellow)](#)
[![Version](https://img.shields.io/badge/Version-1.0-green)](#)

</div>

---

## 🚀 Features

### 📋 Core Management
- **Centralized API Management** — Collect and organize HTTP requests in a dedicated tab  
- **Smart Filtering** — Filter APIs by HTTP methods (GET, POST, PUT, DELETE, etc.)  
- **Duplicate Control** — Configurable duplicate detection to maintain clean API inventories  
- **Visual Workflow Creation** — Add workflow markers to structure testing processes  

### ⚡ Quick Actions
- **Context Menu Integration** — Direct access from Proxy/Repeater  
- **Drag & Drop Reordering** — Intuitive UI for organizing API sequences  
- **Bulk Operations** — Multi-select support for efficient management  

### 📤 Export Capabilities
- **CSV Manual Sheets** — Generate documentation for manual testing  
- **cURL Commands** — Convert requests to cURL format for external testing  
- **Flexible Formats** — Multiple export options with duplicate handling  

---

## 🖼️ Interface Overview

### 🔹 API Management Tab
![API Management Tab](assets/api_tab.png)

Manage your captured APIs efficiently:
- **View all collected APIs.**
- **Filter by HTTP method.**
- **Reorder or remove entries.**
- **Add new APIs or workflows manually.**

---

### 🔹 Context Menu Integration
![Context Menu](assets/context_menu.png)

Right-click any request in **Proxy**, **Repeater**, or **HTTP history**, and choose:
- **Send APIs to Management Tab**
- **Export API’s as Manual Sheet**
- **Export cURL to File**

---

### 🔹 CSV Export Example
![CSV Export Example](assets/csv_export.png)

The exported CSV file includes structured columns for:
- **API & parameters**  
- **Attack steps & observations**  
- **Manual test tracking (Found/Not found)**

---

## 🛠️ Installation

### 🧩 Prerequisites
- **Burp Suite Professional**
- **Jython 2.7+** configured in Burp Suite

### 📦 Installation Steps
```bash
# 1. Clone the repository
git clone https://github.com/yourusername/burp-api-workflow-manager.git
```
### 1. Configure Jython in Burp Suite

Go to Extender → Options

Set Python environment to your Jython standalone JAR

Ensure Jython 2.7+ is properly configured

### 2. Load the Extension

Open Burp Suite → Extender → Extensions

Click Add → Python as extension type

Browse and select the extension file

Click Next to load

### 3. Verify Installation

Check for the “API Management” tab

Confirm context menu options in Proxy/Repeater

---

## 📖 Usage Guide
➕ Adding APIs to Management

### From Context Menu: 
Right-click request → Extensions → Send APIs to Management Tab

### Manual Addition:

-Use the Add API button in the management tab
-Enter Method, URL, and Parameters manually

| Feature               | Description                             | Shortcut             |
| --------------------- | --------------------------------------- | -------------------- |
| **Filtering**         | Filter by HTTP method                   | Dropdown             |
| **Reordering**        | Move APIs up/down                       | Move Up/Down buttons |
| **Workflows**         | Add workflow markers for testing phases | Add Workflow button  |
| **Duplicate Control** | Toggle duplicate prevention             | Checkbox (top panel) |

---

## 📤 Exporting Data
### CSV Export Format
```CSV
SR.NO.,API,Parameters,Attack tried,Steps/procedure,Observation,Status
1,GET /api/users,"id,name",,,,
```
### cURL Export Example
``` bash
####
curl -i -s -k -X 'GET' -H 'Authorization: Bearer token' 'https://api.example.com/users'
####
```

---

## 🎯 Use Cases
**🧪 API Security Testing**

-Comprehensive documentation to track testing progress
-Structured workflows for repeatable test phases
-Team collaboration via organized inventories

**🧍‍♂️ Manual Testing Support**
1. Collect all endpoints via Proxy
2. Organize by functionality in management tab
3. Export to CSV for manual testing documentation
4. Use cURL exports for automated tool integration

### 🔗 Tool Integration
```bash
# Export cURL commands and pipe to external tools
burp_export_curl.txt | while read cmd; do
    [ "$cmd" != "####" ] && eval "$cmd"
done
```
---

## 🔧 Technical Details
**Supported HTTP Methods**

**Standard**: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS

**Custom**: Any HTTP method supported by Burp Suite

| Format  | Encoding       | Use Case                     |
| ------- | -------------- | ---------------------------- |
| **CSV** | UTF-8          | Manual testing documentation |
| **TXT** | System default | cURL command export          |

### ❗ Troubleshooting

| Issue                     | Solution                                |
| ------------------------- | --------------------------------------- |
| **Extension not loading** | Verify Jython configuration in Burp     |
| **Missing context menu**  | Restart Burp or reload extension        |
| **Export failures**       | Check file permissions and disk space   |
| **Performance issues**    | Reduce number of APIs in management tab |

---

## 📜 License

This project is licensed under the MIT License — see the LICENSE

