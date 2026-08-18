#!/usr/bin/env python3
"""
Multi-Source IoT Camera Data Collection Framework
Implements SRS_MultiSource_IoT_Data_Collector.md v1.0, including
acceptance criteria AC-1 through AC-11.

Pipeline for one experiment run:
  1. SSH to the router, verify tcpdump is available, measure clock offset
     between the router and the Lab PC (AC-1, AC-4).
  2. Start tcpdump on the router, start a Saleae Logic 2 SPI capture on the
     Lab PC, and accept operator annotations from stdin (AC-2, AC-3, AC-7).
  3. On stop: download+validate the PCAP, export the SPI analyzer CSV, and
     ingest all three streams into a SQLite database on a shared UTC-epoch
     timestamp field (AC-5, AC-6).
  4. Write experiment metadata.json and verify all required artifacts exist
     (AC-9), optionally exporting the database to CSV/JSON/Parquet (AC-10).

Dependencies (see requirements.txt):
  paramiko, scapy, pandas, logic2-automation, (pyarrow for parquet export)

Router prerequisites: tcpdump installed and on PATH, SSH access, and a
writable directory for temporary capture files (default /tmp).

Saleae prerequisites: Logic 2 desktop app running with the Automation
server enabled (Preferences -> Automation server, default port 10430).

Usage:
  python iot_collector.py \
      --experiment-name tapo_c310_onboarding \
      --router-host 192.168.1.1 --router-user root --router-key ~/.ssh/id_rsa \
      --router-iface br-lan \
      --spi-mosi 0 --spi-miso 1 --spi-clock 2 --spi-enable 3

  During the run, type annotations + Enter (e.g. CAMERA_FOUND,
  WIFI_CONFIGURED, CAMERA_ONLINE). Type 'quit' or press Ctrl+C to stop.
"""

import argparse
import csv
import json
import os
import queue
import signal
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

TARGET_DEVICE = "TP-Link Tapo C310"

PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4",  # pcap, little-endian
    b"\xd4\xc3\xb2\xa1",  # pcap, big-endian
    b"\xa1\xb2\x3c\x4d",  # pcap, nanosecond resolution
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",  # pcapng
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS experiments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_device TEXT,
    start_time_utc TEXT,
    end_time_utc TEXT,
    router_host TEXT,
    router_iface TEXT,
    pcap_file TEXT,
    spi_csv_file TEXT
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id),
    timestamp_utc REAL NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS spi_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id),
    timestamp_utc REAL,
    saleae_packet_id TEXT,
    mosi TEXT,
    miso TEXT,
    raw_row TEXT
);

CREATE TABLE IF NOT EXISTS annotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id),
    timestamp_utc REAL NOT NULL,
    text TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS synchronization (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id),
    measured_at_utc REAL,
    local_epoch REAL,
    router_epoch REAL,
    offset_seconds REAL
);
"""

DB_TABLES = ("experiments", "packets", "spi_events", "annotations", "synchronization")


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def utc_now_epoch():
    return time.time()


def utc_stamp_for_filename():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def validate_pcap(path):
    with open(path, "rb") as f:
        header = f.read(4)
    if header not in PCAP_MAGIC_NUMBERS:
        raise RuntimeError(f"Downloaded file is not a valid pcap/pcapng: {path}")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class Database:
    def __init__(self, path):
        self.conn = sqlite3.connect(str(path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def create_experiment(self, name, router_host, router_iface, pcap_file, spi_csv_file):
        cur = self.conn.execute(
            "INSERT INTO experiments "
            "(name, target_device, start_time_utc, router_host, router_iface, pcap_file, spi_csv_file) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, TARGET_DEVICE, utc_now_iso(), router_host, router_iface, str(pcap_file), str(spi_csv_file)),
        )
        self.conn.commit()
        return cur.lastrowid

    def finalize_experiment(self, experiment_id):
        self.conn.execute(
            "UPDATE experiments SET end_time_utc = ? WHERE id = ?",
            (utc_now_iso(), experiment_id),
        )
        self.conn.commit()

    def insert_sync(self, experiment_id, measured_at_utc, local_epoch, router_epoch, offset_seconds):
        self.conn.execute(
            "INSERT INTO synchronization "
            "(experiment_id, measured_at_utc, local_epoch, router_epoch, offset_seconds) "
            "VALUES (?, ?, ?, ?, ?)",
            (experiment_id, measured_at_utc, local_epoch, router_epoch, offset_seconds),
        )
        self.conn.commit()

    def insert_annotation(self, experiment_id, timestamp_utc, text):
        self.conn.execute(
            "INSERT INTO annotations (experiment_id, timestamp_utc, text) VALUES (?, ?, ?)",
            (experiment_id, timestamp_utc, text),
        )
        self.conn.commit()

    def insert_packets_bulk(self, rows):
        self.conn.executemany(
            "INSERT INTO packets "
            "(experiment_id, timestamp_utc, src_ip, dst_ip, src_port, dst_port, protocol, length, summary) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def insert_spi_events_bulk(self, rows):
        self.conn.executemany(
            "INSERT INTO spi_events "
            "(experiment_id, timestamp_utc, saleae_packet_id, mosi, miso, raw_row) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def count(self, table, experiment_id):
        cur = self.conn.execute(f"SELECT COUNT(*) FROM {table} WHERE experiment_id = ?", (experiment_id,))
        return cur.fetchone()[0]

    def close(self):
        self.conn.close()


def export_database(db_path, export_dir, fmt):
    import pandas as pd

    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        for table in DB_TABLES:
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
            out_path = export_dir / f"{table}.{fmt}"
            if fmt == "csv":
                df.to_csv(out_path, index=False)
            elif fmt == "json":
                df.to_json(out_path, orient="records")
            elif fmt == "parquet":
                df.to_parquet(out_path, index=False)
            else:
                raise ValueError(f"Unsupported export format: {fmt}")
            print(f"[+] Exported {table} -> {out_path}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Router network capture (AC-1, AC-2, AC-4)
# ---------------------------------------------------------------------------

class RouterCapture:
    def __init__(self, args):
        self.host = args.router_host
        self.port = args.router_port
        self.user = args.router_user
        self.key_path = args.router_key
        self.password = args.router_password
        self.iface = args.router_iface
        self.remote_dir = args.router_remote_dir.rstrip("/")
        self.remote_path = f"{self.remote_dir}/iot_capture_{utc_stamp_for_filename()}.pcap"
        self.keep_remote = args.keep_remote_pcap
        self.client = None
        self.pid = None

    def connect(self):
        import paramiko

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {"hostname": self.host, "port": self.port, "username": self.user, "timeout": 10}
        if self.key_path:
            kwargs["key_filename"] = self.key_path
        if self.password:
            kwargs["password"] = self.password
        self.client.connect(**kwargs)

    def _run(self, cmd):
        _, stdout, stderr = self.client.exec_command(cmd)
        return stdout.read().decode().strip(), stderr.read().decode().strip()

    def verify_access(self):
        out = self._run("timeout 1000 tcpdump -i any")

        print(out)
        if not out:
            raise RuntimeError("tcpdump not found on router PATH")
        out, _ = self._run(f"test -w {self.remote_dir} && echo ok")
        if out != "ok":
            raise RuntimeError(f"Remote directory {self.remote_dir} is not writable")

    def get_remote_utc_epoch(self):
        out, err = self._run("date -u +%s")
        if not out:
            raise RuntimeError(f"Failed to read router UTC time: {err}")
        return float(out)

    def start_capture(self):
        cmd = f"nohup tcpdump -i {self.iface} -w {self.remote_path} > /tmp/iot_tcpdump.log 2>&1 & echo $!"
        out, err = self._run(cmd)
        if not out.isdigit():
            raise RuntimeError(f"Failed to start remote tcpdump: {err}")
        self.pid = out
        time.sleep(1)
        out, _ = self._run(f"kill -0 {self.pid} 2>/dev/null && echo alive")
        if out != "alive":
            raise RuntimeError("Remote tcpdump process died immediately after start")

    def stop_capture(self):
        self._run(f"kill -INT {self.pid}")
        time.sleep(2)

    def download_pcap(self, local_path):
        sftp = self.client.open_sftp()
        try:
            sftp.get(self.remote_path, str(local_path))
            if not self.keep_remote:
                sftp.remove(self.remote_path)
        finally:
            sftp.close()

    def close(self):
        if self.client:
            self.client.close()


# ---------------------------------------------------------------------------
# Saleae SPI capture (AC-3)
# ---------------------------------------------------------------------------

class SPICapture:
    def __init__(self, args):
        self.args = args
        self.manager = None
        self.capture = None
        self.channels = {
            "MOSI": args.spi_mosi,
            "MISO": args.spi_miso,
            "Clock": args.spi_clock,
            "Enable": args.spi_enable,
        }
        self.start_epoch = None

    def start(self):
        try:
            from saleae import automation
        except ImportError as exc:
            raise RuntimeError("logic2-automation not installed. Run: pip install logic2-automation") from exc

        self.manager = automation.Manager.connect(port=self.args.saleae_port)
        device_config = automation.LogicDeviceConfiguration(
            enabled_digital_channels=sorted(set(self.channels.values())),
            digital_sample_rate=self.args.spi_sample_rate,
        )
        capture_config = automation.CaptureConfiguration(capture_mode=automation.ManualCaptureMode())
        # Wall-clock time is stamped immediately around the automation call and used as
        # t=0 for converting Saleae's capture-relative seconds into UTC epoch timestamps.
        # This is an approximation (bounded by automation-call latency), not a hardware sync.
        self.start_epoch = utc_now_epoch()
        self.capture = self.manager.start_capture(
            device_id=self.args.saleae_device_id,
            device_configuration=device_config,
            capture_configuration=capture_config,
        )

    def stop_and_export(self, csv_path):
        self.capture.stop()
        analyzer = self.capture.add_analyzer(
            "SPI",
            label="SPI",
            settings={
                "MOSI": self.channels["MOSI"],
                "MISO": self.channels["MISO"],
                "Clock": self.channels["Clock"],
                "Enable": self.channels["Enable"],
            },
        )
        self.capture.export_data_table(filepath=str(csv_path), analyzers=[analyzer])
        self.capture.close()
        self.manager.close()


def ingest_spi_csv(csv_path, db, experiment_id, spi_start_epoch):
    if not csv_path.exists():
        return 0
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        time_col = next((c for c in ("Time [s]", "Time[s]", "time") if c in (reader.fieldnames or [])), None)
        rows = []
        for row in reader:
            ts = None
            if time_col and row.get(time_col):
                ts = spi_start_epoch + float(row[time_col])
            rows.append((
                experiment_id,
                ts,
                row.get("Packet ID"),
                row.get("MOSI"),
                row.get("MISO"),
                json.dumps(row),
            ))
    db.insert_spi_events_bulk(rows)
    return len(rows)


# ---------------------------------------------------------------------------
# Packet ingestion (AC-5)
# ---------------------------------------------------------------------------

def ingest_pcap(pcap_path, db, experiment_id, offset_seconds):
    from scapy.all import rdpcap, IP, TCP, UDP

    packets = rdpcap(str(pcap_path))
    rows = []
    for pkt in packets:
        # pkt.time is in the router's clock domain; subtract the measured
        # router-vs-lab-PC offset so all timestamps land on the Lab PC's UTC timeline.
        ts = float(pkt.time) - offset_seconds
        src = dst = proto = None
        sport = dport = None
        if IP in pkt:
            src, dst, proto = pkt[IP].src, pkt[IP].dst, str(pkt[IP].proto)
        if TCP in pkt:
            sport, dport, proto = pkt[TCP].sport, pkt[TCP].dport, "TCP"
        elif UDP in pkt:
            sport, dport, proto = pkt[UDP].sport, pkt[UDP].dport, "UDP"
        rows.append((experiment_id, ts, src, dst, sport, dport, proto, len(pkt), pkt.summary()))
    db.insert_packets_bulk(rows)
    return len(rows)


# ---------------------------------------------------------------------------
# Annotations (AC-7)
# ---------------------------------------------------------------------------

class AnnotationLogger:
    def __init__(self, stop_event):
        self.stop_event = stop_event
        self._lines = queue.Queue()
        self._thread = threading.Thread(target=self._read_stdin, daemon=True)

    def start(self):
        self._thread.start()

    def _read_stdin(self):
        for line in sys.stdin:
            text = line.strip()
            if not text:
                continue
            if text.lower() in ("quit", "exit"):
                self.stop_event.set()
                return
            self._lines.put((utc_now_epoch(), text))

    def drain(self):
        items = []
        while not self._lines.empty():
            items.append(self._lines.get_nowait())
        return items


# ---------------------------------------------------------------------------
# Artifact verification (AC-9)
# ---------------------------------------------------------------------------

def verify_artifacts(pcap_path, spi_csv_path, metadata_path, db_path, spi_enabled):
    checks = {
        "capture.pcap": pcap_path.exists() and pcap_path.stat().st_size > 0,
        "spi_capture.csv": (not spi_enabled) or (spi_csv_path.exists() and spi_csv_path.stat().st_size > 0),
        "metadata.json": metadata_path.exists(),
        "experiment.db": db_path.exists(),
    }
    print("[+] Artifact check (AC-9):")
    for name, ok in checks.items():
        print(f"    {'PASS' if ok else 'FAIL'} - {name}")
    return all(checks.values())


def parse_args():
    p = argparse.ArgumentParser(description="Multi-source IoT data collector")
    p.add_argument("--experiment-name", required=True)
    p.add_argument("--output-dir", default="./captures")
    p.add_argument("--duration", type=int, default=0,
                    help="Stop automatically after N seconds (0 = run until quit/Ctrl+C)")

    p.add_argument("--router-host", required=True)
    p.add_argument("--router-port", type=int, default=22)
    p.add_argument("--router-user", required=True)
    p.add_argument("--router-key", default=None, help="Path to SSH private key")
    p.add_argument("--router-password", default=os.environ.get("IOT_ROUTER_PASSWORD"),
                    help="SSH password; prefer --router-key or IOT_ROUTER_PASSWORD env var")
    p.add_argument("--router-iface", required=True, help="Interface tcpdump listens on, on the router")
    p.add_argument("--router-remote-dir", default="/tmp")
    p.add_argument("--keep-remote-pcap", action="store_true",
                    help="Do not delete the pcap on the router after downloading it")

    p.add_argument("--no-spi", action="store_true", help="Disable SPI capture")
    p.add_argument("--saleae-port", type=int, default=10430)
    p.add_argument("--saleae-device-id", default=None)
    p.add_argument("--spi-sample-rate", type=int, default=4_000_000)
    p.add_argument("--spi-mosi", type=int, default=0)
    p.add_argument("--spi-miso", type=int, default=1)
    p.add_argument("--spi-clock", type=int, default=2)
    p.add_argument("--spi-enable", type=int, default=3)

    p.add_argument("--export-format", choices=["csv", "json", "parquet"], default=None,
                    help="Also export the SQLite database to this format (AC-10)")
    p.add_argument("--export-existing-db", default=None,
                    help="Skip capture entirely; just export an existing experiment.db")

    return p.parse_args()


def main():
    args = parse_args()

    if args.export_existing_db:
        fmt = args.export_format or "csv"
        db_path = Path(args.export_existing_db)
        export_database(db_path, db_path.parent / "export", fmt)
        return

    run_dir = Path(args.output_dir) / f"{args.experiment_name}_{utc_stamp_for_filename()}"
    run_dir.mkdir(parents=True, exist_ok=True)

    pcap_path = run_dir / "capture.pcap"
    spi_csv_path = run_dir / "spi_capture.csv"
    db_path = run_dir / "experiment.db"
    metadata_path = run_dir / "metadata.json"
    annotations_path = run_dir / "annotations.jsonl"

    db = Database(db_path)
    experiment_id = db.create_experiment(
        args.experiment_name, args.router_host, args.router_iface, pcap_path, spi_csv_path
    )

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda signum, frame: stop_event.set())

    # --- AC-1 / AC-4: connect, verify, sync clocks -------------------------
    print(f"[+] Connecting to router {args.router_host}")
    router = RouterCapture(args)
    router.connect()
    router.verify_access()
    print("[+] Router SSH access verified")

    t0 = utc_now_epoch()
    router_epoch = router.get_remote_utc_epoch()
    t1 = utc_now_epoch()
    local_epoch = (t0 + t1) / 2  # midpoint compensates for SSH round-trip latency
    offset_seconds = router_epoch - local_epoch
    db.insert_sync(experiment_id, utc_now_iso(), local_epoch, router_epoch, offset_seconds)
    print(f"[+] Clock offset (router - lab PC): {offset_seconds:.6f}s")

    # --- AC-2: start remote network capture ---------------------------------
    print(f"[+] Starting tcpdump on router interface {args.router_iface}")
    router.start_capture()

    # --- AC-3: start SPI capture --------------------------------------------
    spi_capture = None
    if not args.no_spi:
        print(f"[+] Connecting to Saleae Logic 2 automation server on port {args.saleae_port}")
        spi_capture = SPICapture(args)
        spi_capture.start()
        print("[+] SPI capture running")

    # --- AC-7: annotations ---------------------------------------------------
    annotations = AnnotationLogger(stop_event)
    annotations.start()
    print("[+] Type annotations + Enter to log them. Type 'quit' or Ctrl+C to stop.")

    deadline = time.time() + args.duration if args.duration > 0 else None
    try:
        while not stop_event.is_set():
            for ts, text in annotations.drain():
                db.insert_annotation(experiment_id, ts, text)
                with open(annotations_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"timestamp_utc": ts, "text": text}) + "\n")
            if deadline and time.time() >= deadline:
                stop_event.set()
            else:
                time.sleep(0.5)
    finally:
        for ts, text in annotations.drain():
            db.insert_annotation(experiment_id, ts, text)
            with open(annotations_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"timestamp_utc": ts, "text": text}) + "\n")

        print("[+] Stopping router capture and downloading PCAP")
        router.stop_capture()
        router.download_pcap(pcap_path)
        router.close()
        validate_pcap(pcap_path)
        print(f"[+] PCAP downloaded and validated: {pcap_path}")

        if spi_capture is not None:
            print("[+] Stopping SPI capture and exporting CSV")
            spi_capture.stop_and_export(spi_csv_path)
            n_spi = ingest_spi_csv(spi_csv_path, db, experiment_id, spi_capture.start_epoch)
            print(f"[+] Ingested {n_spi} SPI events")

        n_packets = ingest_pcap(pcap_path, db, experiment_id, offset_seconds)
        print(f"[+] Ingested {n_packets} packets")

        db.finalize_experiment(experiment_id)

        metadata = {
            "experiment_name": args.experiment_name,
            "experiment_id": experiment_id,
            "target_device": TARGET_DEVICE,
            "host": {"hostname": socket.gethostname(), "python_version": sys.version},
            "router": {"host": args.router_host, "iface": args.router_iface},
            "clock_offset_seconds": offset_seconds,
            "artifacts": {
                "pcap_file": str(pcap_path),
                "spi_csv_file": str(spi_csv_path) if spi_capture else None,
                "database": str(db_path),
                "annotations_file": str(annotations_path),
            },
            "counts": {
                "packets": db.count("packets", experiment_id),
                "spi_events": db.count("spi_events", experiment_id),
                "annotations": db.count("annotations", experiment_id),
            },
        }
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        db.close()

        ok = verify_artifacts(pcap_path, spi_csv_path, metadata_path, db_path, spi_capture is not None)

        if args.export_format:
            export_database(db_path, run_dir / "export", args.export_format)

        print(f"[+] Experiment complete. Data written to: {run_dir}")
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
