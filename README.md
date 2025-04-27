
<div align="center">

# 🔍 TraceLens

### Network Traffic Analysis and Reporting Tool

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

TraceLens is a Python-based tool for capturing and analyzing network traffic. It generates detailed reports of accessed domains and categorizes them for better insights.

## Features

- Captures HTTP and HTTPS traffic
- Extracts and analyzes accessed domains
- Generates Markdown and HTML reports
- Categorizes domains for better insights
- Highlights suspicious or privacy-focused domains

## Requirements

- Python 3.6+
- OpenAI API key
- Scapy library

## 🚀 Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/mihir20/TraceLens
cd TraceLens
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Configuration

Set up your OpenAI API key:
```bash
# Linux/macOS
export OPENAI_API_KEY=your-api-key-here

# Windows (PowerShell)
$env:OPENAI_API_KEY="your-api-key-here"
```

### Usage

Run the tool to start capturing network traffic:
```bash
python main.py
```

> 💡 **Note:** Ensure you have the necessary permissions to capture network traffic on your system.

## 📚 How It Works

1. Captures HTTP and HTTPS packets using Scapy.
2. Extracts domain information from the packets.
3. Generates a detailed Markdown report using OpenAI's API.
4. Converts the Markdown report to an HTML file for easy viewing.

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed description of your changes.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Show Your Support

If you find TraceLens useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting issues
- 🤝 Contributing to the code
- 📢 Sharing it with others

---

<div align="center">
Made by <a href="https://github.com/mihir20">Mihir Gandhi</a>
</div>
