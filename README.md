# AI Security Copilot

**Local LLM-Powered Security Incident Analysis**

A Python-based cybersecurity application that detects suspicious authentication patterns, correlates security alerts, and assists incident investigation using a local Large Language Model (LLM).

## Features

- **Threat Detection:** Detect suspicious authentication activity using configurable rules and time windows.
- **Incident Correlation:** Group related security alerts into incidents.
- **Risk Classification:** Assign risk levels based on detected patterns.
- **Interactive Dashboard:** Visualize security events, timelines, and failed login attempts.
- **CSV Analysis:** Upload authentication logs for analysis.
- **AI Security Assistant:** Investigate incidents using Python-based evidence retrieval and locally generated recommendations.
- **Automated Testing:** Validate core functionality using Python's unittest framework.

## Tech Stack

- Python
- Pandas
- Streamlit
- Ollama + Llama 3.2
- JSON
- Unittest

## Architecture

`CSV Logs → Rule-Based Detector → Alert Correlation → Security Incidents`

The application provides two interfaces:

**Reports:** Interactive dashboard for reviewing logs, incidents, risk levels, and AI-assisted reports.

**AI Agent:** Investigation assistant combining deterministic Python tools with a locally hosted LLM.

Verified facts are separated from AI-generated recommendations to reduce unsupported conclusions.

## Installation

**1. Clone the repository**

`git clone https://github.com/Gonzadiev/AI-Security-Copilot.git`

**2. Install dependencies**

`python -m pip install -r requirements.txt`

**3. Install Ollama**

Download Ollama from https://ollama.com/download.

**4. Download the local model**

`ollama pull llama3.2:1b`

**5. Run the application**

`python -m streamlit run app.py`

Open the local URL displayed in the terminal.

## Testing

Run the automated tests:

`python -m unittest -v test_proyecto.py`

## Sample Data

The repository includes synthetic authentication logs for demonstration purposes.

Supported CSV columns:

`timestamp,ip,status`

Authentication status values: `SUCCESS` and `FAIL`.

## Limitations

- Detection currently relies on predefined rules rather than trained machine-learning models.
- Risk scores are heuristic and do not confirm malicious activity.
- The LLM may produce inaccurate interpretations.
- The application is an educational prototype, not a production-ready security platform.

## Project Goals

This project explores the integration of cybersecurity monitoring, Python-based investigation tools, local LLMs, and interactive applications.

**Developed as a personal AI and cybersecurity engineering portfolio project.**