# Software Requirements Specification (SRS)

# Project: Multi-Source IoT Camera Data Collection Framework

Version: 1.0

Author: Kevin Lindemark Holm

Date: 2026-08-18

---

# 1. Overview

## 1.1 Purpose

Develop a Python-based data collection framework capable of collecting, synchronizing, and storing data from multiple sources during IoT camera experiments.

The framework will be used for:

- IoT protocol analysis
- Reverse engineering
- Network analysis
- Future fuzzing campaigns
- Machine learning dataset generation
- Vulnerability research

The initial target device is a TP-Link Tapo C310 camera.

---

## 1.2 Research Goal

Create a unified dataset containing:

- Full network traffic
- SPI communication traces
- User annotations
- Experiment metadata

All data must be correlated using a common UTC timeline.

# 1.3 Acceptance Criteria

The implementation is considered complete when all criteria below are satisfied.

## AC-1 SSH Connectivity

The system successfully:

- Connects to the router through SSH.
- Verifies access before captures begin.
- Retrieves router timestamps.
- Transfers PCAP files to the Lab PC.

Pass condition:

A PCAP generated on the router is successfully downloaded and archived.

---

## AC-2 Network Capture

The system successfully:

- Starts tcpdump remotely.
- Records traffic while the camera is configured.
- Stops tcpdump automatically.
- Produces a valid PCAP file.

Pass condition:

PCAP opens successfully in Wireshark.

---

## AC-3 Saleae Capture

The system successfully:

- Starts a Logic 2 capture.
- Stops the capture.
- Exports SPI CSV data.

Pass condition:

CSV contains timestamped SPI transactions.

---

## AC-4 Time Synchronization

The system successfully:

- Records UTC timestamps on the Lab PC.
- Records UTC timestamps from the router.
- Calculates offset between devices.

Pass condition:

Offset stored in the synchronization table.

---

## AC-5 Unified Timeline

The system successfully:

- Converts all timestamps into UTC epoch format.
- Stores packet timestamps.
- Stores SPI timestamps.
- Stores annotations.

Pass condition:

All records can be queried using a common timestamp field.

---

## AC-6 Database Population

The system successfully populates:

- experiments
- packets
- spi_events
- annotations
- synchronization

Pass condition:

Database contains imported records from a completed experiment.

---

## AC-7 Annotation System

Operator can create annotations during an experiment.

Example:

CAMERA_FOUND
WIFI_CONFIGURED
CAMERA_ONLINE

Pass condition:

Annotations are stored with timestamps.

---

## AC-8 Experiment Reproducibility

A complete camera setup session can be reconstructed using:

- PCAP data
- SPI traces
- Annotations
- Experiment metadata

Pass condition:

An independent researcher can follow the timeline and identify:

- user actions
- network activity
- corresponding SPI activity

from the collected dataset.

---

## AC-9 Dataset Quality

A completed experiment shall produce:

- capture.pcap
- spi_capture.csv
- experiment metadata
- SQLite database

Pass condition:

No required artifact is missing.

---

## AC-10 Machine Learning Readiness

The resulting database shall support extraction into:

- CSV
- JSON
- Parquet

with timestamps preserved.

Pass condition:

Data can be loaded into Pandas without additional preprocessing.

---

## AC-11 Initial Camera Setup Experiment

The framework shall successfully record a full Tapo C310 onboarding workflow.

Workflow:

1. Start capture.
2. Launch Android application.
3. Configure camera.
4. Join Wi-Fi network.
5. Reach operational state.
6. Stop capture.

Pass condition:

The full workflow is visible in:

- packet timeline
- SPI timeline
- annotations

and can be correlated through timestamps.