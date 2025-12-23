# AKOptimizer - Windows PC Optimizer

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/PyQt6-6.5%2B-green)](https://pypi.org/project/PyQt6/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6)](https://www.microsoft.com/windows)

A comprehensive Windows 10/11 PC optimization tool designed specifically for low-end systems. Built with Python and PyQt6, featuring a modern dark-themed GUI.

![AKOptimizer Dashboard](dashboard.png)

## ✨ Features

### 🎯 **System Optimization**
- **Memory Management**: Trim working sets to free up RAM
- **CPU Monitoring**: Real-time CPU usage tracking
- **Disk Optimization**: SSD/HDD detection and optimization
- **Power Management**: Switch between power plans (Balanced/High Performance/Power Saver)

### 🧹 **Cleaning Tools**
- Temporary files cleaner (TEMP, Windows Temp)
- Browser cache cleaner (Chrome, Edge, Firefox)
- Recycle Bin emptying
- System service management

### ⚙️ **Advanced Tools**
- **Startup Manager**: Enable/disable startup programs
- **Process Manager**: View and end background processes
- **Service Manager**: Start/stop Windows services
- **Network Optimizer**: Flush DNS, reset Winsock
- **Disk Analyzer**: Detect SSD/HDD, run defrag/TRIM

### 🛡️ **Admin Features**
- Automatic UAC elevation
- Safe operation with confirmation dialogs
- Logging of all actions performed

## 📋 Requirements

- **Windows 10/11** (x64/x86)
- **Python 3.10 or higher**
- **Administrator privileges** (for full functionality)

### Python Dependencies
```bash
pip install PyQt6 psutil pywin32 qdarkstyle
