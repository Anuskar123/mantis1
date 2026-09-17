# MANTIS Testing Guide

Use only a machine or isolated virtual lab that you own. The commands below
target loopback (`127.0.0.1`) so no test traffic is sent to another system.
Keep active defence disabled unless a test explicitly covers firewall response.

## 1. Install the current build

```bash
cd ~/Desktop/mantis/src
sudo ./install.sh
```

Verify the commands:

```bash
command -v mantis
command -v mantis-replay
command -v mantis-demo-attacks
sudo /usr/bin/mantis-demo-attacks --help 2>/dev/null || true
```

## 2. Automated regression suite

```bash
cd ~/Desktop/mantis/src
python3 -m unittest discover -s tests -v
```

Expected result:

```text
Ran 119 tests
OK
```

The suite covers engine mathematics, zero-port scan prevention, guarded DDoS
detection, privacy, parsing, source attribution, blocking policy, PCAP,
replay, SIEM APIs, training and state persistence.

## 3. Repeatable five-engine replay

```bash
mantis-replay --generate ~/mantis-all-engines.pcap
mantis-replay \
  --pcap ~/mantis-all-engines.pcap \
  --out-json ~/mantis-all-engines-results.json
```

Expected:

- Baseline window from 0-14 seconds: no alerts.
- KNN: port scan with a non-zero unique-port count.
- Z-Score: one guarded DDoS episode alert.
- Naive Bayes: SQLi, XSS and traversal payload alerts.
- K-Means: behavioural anomaly alerts.
- Bloom Filter: known-bad source alerts marked `Flagged`.
- Parser: zero malformed packets in the generated capture.

## 4. Live dashboard test

Terminal A:

```bash
mantis --mode web \
  --ddos-min-pps 500 \
  --ddos-consecutive 3 \
  --alert-dedup-seconds 5
```

Open `http://127.0.0.1:8080` and wait at least 30 seconds for a normal
baseline.

Terminal B:

```bash
sudo /usr/bin/mantis-demo-attacks lo 5
```

Expected:

- `PORT SCAN DETECTED` with a source IP and more than zero unique ports.
- `DDoS DETECTED` after sustained traffic above the minimum PPS guard.
- One `MALICIOUS PAYLOAD` event containing `UNION` and `SELECT`.
- No duplicate payload event inside the deduplication window.

## 5. Live Bloom Filter test

MANTIS seeds `10.0.0.66` as a known-bad demonstration address. Send one
spoofed packet only over loopback:

```bash
sudo hping3 -I lo -c 1 \
  -a 10.0.0.66 \
  -S -p 80 127.0.0.1
```

Expected with blocking disabled:

```text
BLACKLISTED IP DETECTED: 10.0.0.66 (Flagged)
```

If blocking is explicitly enabled and the firewall rule succeeds, the status
is `Blocked`. It must never say `Blocked` merely because the Bloom Filter
matched.

## 6. Normal-traffic false-positive observation

Restart MANTIS without running attacks:

```bash
mantis --mode web
```

For at least three minutes, browse ordinary local/Internet pages and leave the
dashboard open. Record:

- Observation start and end times.
- Total packets seen.
- Queue drops.
- Any alerts by engine.

Acceptance criteria:

- No DDoS event below 500 PPS.
- No scan event with zero unique ports.
- No repeated identical payload alert inside five seconds.
- Preferably zero attack alerts during the controlled normal period.

## 7. Kali performance evidence

Record hardware and software first:

```bash
uname -a
python3 --version
lscpu
free -h
```

Find the sensor PID and collect five one-second samples:

```bash
pgrep -f '/opt/mantis/main.py'
pidstat -p <PID> 1 5
ps -o pid,%cpu,rss,etime,cmd -p <PID>
```

Also record the MANTIS shutdown summary:

- Uptime
- Frames decoded
- Non-IPv4 and malformed counts
- Queue drops
- Alerts raised
- Audit-log rows

Do not use the dashboard's total host memory percentage as the sensor's
process memory. Convert the `ps` RSS value from KiB to MiB by dividing by 1024.

## 8. Optional active-defence test

Run only inside a disposable VM you own:

```bash
sudo mantis --mode web --block --block-on blacklist
```

Use a non-whitelisted test source. Confirm that the event says `Blocked` only
after iptables succeeds, then stop MANTIS and verify that its temporary rule is
removed. Do not enable blocking during ordinary development or normal-traffic
testing.

## 9. Evidence to retain

- Dashboard screenshots with timestamps
- `mantis_logs.csv`
- `mantis-all-engines.pcap`
- `mantis-all-engines-results.json`
- Unit-test output
- `pidstat` and `ps` output
- Hardware and Kali version details

The PCAP, JSON and test commands make the evaluation reproducible.
