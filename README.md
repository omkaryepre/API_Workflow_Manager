# 🔍 BurpSuite Extension — API & Workflow Manager

![BurpSuite Extension Banner](assets/banner.png)

> **An advanced BurpSuite extension** for managing, organizing, and exporting API endpoints & workflows discovered during penetration testing.

---

## 🚀 Overview

The **API & Workflow Manager** extension provides BurpSuite users with a clean, interactive interface to:
- Capture API endpoints directly from Burp’s proxy or repeater.
- Manage and reorder APIs for better workflow organization.
- Filter APIs by HTTP method.
- Export APIs and cURL commands to CSV or TXT for manual testing documentation.

This extension is ideal for **penetration testers**, **API security auditors**, and **red teamers** who want to streamline API mapping and workflow documentation during engagements.

---

## 🧩 Key Features

| Feature | Description |
|----------|-------------|
| **API Capture** | Right-click any HTTP request and send it to the **API Management** tab. |
| **Workflow Management** | Add workflows or logical test sequences to visually organize attack chains. |
| **Filtering** | Filter captured APIs by HTTP method (GET, POST, etc.). |
| **Reordering** | Move APIs up or down to maintain testing sequences. |
| **Duplicate Control** | Option to allow or block duplicate API entries. |
| **Export Options** | Export filtered APIs as a formatted CSV sheet or as ready-to-use cURL commands. |
| **Manual Testing Sheet** | Generate CSV-based "Manual Test Sheets" for structured vulnerability reporting. |

---

## 🖼️ Interface Overview

### 🔹 API Management Tab
![API Management Tab](assets/api_tab.png)

Manage your captured APIs efficiently:
- View all collected APIs.
- Filter by HTTP method.
- Reorder or remove entries.
- Add new APIs or workflows manually.

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
- API & parameters  
- Attack steps & observations  
- Manual test tracking (Found/Not found)

---

## ⚙️ Installation

### Prerequisites
- **BurpSuite Professional or Community Edition**
- **Jython 2.7.x** configured in BurpSuite (`Extender > Options > Python Environment`)

### Steps
1. Download the extension source:
   ```bash
   git clone https://github.com/<yourusername>/burp-api-workflow-manager.git
   cd burp-api-workflow-manager
