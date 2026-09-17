# MANTIS

**Minimalist Alert Network for Threat Intelligence System**

MANTIS is an academic network intrusion detection prototype with five detection engines, a browser dashboard, offline PCAP replay, dataset training, and incident reporting. The core detection and dashboard code uses the Python standard library.

## Detection engines

| Engine | Purpose |
| --- | --- |
| Z-Score | Detect unusual packet-rate increases against a rolling baseline |
| K-Nearest Neighbours | Classify scan behaviour from unique ports and packet counts |
| K-Means | Identify unusual traffic patterns using online clustering |
| Naive Bayes | Classify visible payload tokens |
| Bloom Filter | Check source addresses against a threat intelligence feed |

The project also provides JSON model-state persistence, CSV audit logs, HTML reports, PCAP export, UDP sensor telemetry, and optional Linux firewall response. Blocking is disabled by default.

## Quick start

Live packet capture requires Linux with AF_PACKET and root privileges or the capabilities configured by the installer. Offline training, evaluation, replay, and tests can run on Windows. Python 3.14.6 was used for the publication checks.

```bash
git clone https://github.com/Anuskar123/mantis1.git
cd mantis1/src
sudo python3 main.py --mode web
```

Open `http://localhost:8080` on the host. For the terminal interface, use `sudo python3 main.py --mode cli`.

To install the command-line entry points on Linux:

```bash
cd mantis1/src
sudo bash install.sh
mantis --help
```

Run each example from the stated directory. If already inside `mantis1/src`, skip its `cd` line. On Windows, use `python` instead of `python3` for offline commands.

## Offline demonstration

From `mantis1/src`:

```bash
python3 replay.py --generate demo.pcap
python3 replay.py --pcap demo.pcap --out-json demo-results.json
```

This generates synthetic test traffic locally and replays it through the detection pipeline. It does not require live capture.

## Train and evaluate

Small labelled datasets and deterministic train, validation, and test splits are included. See the [dataset guide](datasets/README.md) for the five-engine training commands, saved-model selection, evaluation, and dataset provenance.

```bash
cd mantis1/src
python3 -m training.train --knn-csv ../datasets/processed/stage_1/train/knn_sample.csv --payload-csv ../datasets/processed/stage_1/train/payload_sample.csv --kmeans-csv ../datasets/processed/stage_1/train/kmeans_sample.csv --zscore-csv ../datasets/processed/stage_1/train/zscore_sample.csv --bloom-csv ../datasets/processed/stage_1/train/bloom_sample.csv --out data/mantis_brain_stage_1.json
```

The trainer prints the timestamped model path it saves. Generated model states and live capture logs are excluded from version control.

The 20,000-row and 300,000-row CIC flow exports are included for the supported flow-rate comparison. They lack genuine `unique_ports` aggregates and are not valid direct KNN or K-Means training inputs. The raw archive and its multipart files are not included in Git because of their size. [Raw dataset metadata](datasets/raw/README.md) explains the available checksums and reconstruction scripts.

## Tests

```bash
cd mantis1/src
python3 -m unittest discover -s tests -v
```

The current suite has 119 tests covering engines, dataset splits, parsing, privacy, replay, alert dispatch, SIEM APIs, training, and model persistence. All passed locally on Windows with Python 3.14.6 before publication. GitHub Actions runs the suite on Linux and Windows with Python 3.11 and 3.14.

These tests and synthetic replays verify controlled behaviour. They do not establish production detection accuracy or performance across the full external dataset. Existing evaluation output files and report figures are historical evidence, not newly rerun benchmark results.

## Repository guide

| Location | Contents |
| --- | --- |
| [src](src/) | Sensor, detection engines, dashboard, training, evaluation, replay, and tests |
| [datasets](datasets/) | Sample data, processed CIC exports, deterministic splits, and manifests |
| [docs/figures](docs/figures/) | Diagram sources and exported figures |
| [Project deliverables](docs/deliverables/README.md) | Dissertation versions, presentations, proposal, interim reports, Gantt charts, and viva/demo documents |
| [scripts](scripts/) | Dataset preparation and raw archive packaging utilities |
| [How to run](HOW_TO_RUN.md) | Detailed operation instructions |
| [Installation](INSTALL.md) | Installation guide |
| [Testing guide](TEST_GUIDE.md) | Automated checks and lab demonstrations |
| [Troubleshooting](TROUBLESHOOTING.md) | Common setup issues |

## Scope and limitations

This is a final-year research prototype for controlled lab use. The dashboard has no built-in authentication and UDP telemetry is unencrypted. Keep dashboard and sensor ports within an isolated lab or authenticated VPN. Only capture or test traffic on systems you own or are authorised to use.

Encrypted HTTPS payloads are not decrypted. Source IP attribution depends on observed packets and can be affected by spoofing. Python capture performance and model quality depend on the workload and the data used. Portability of saved JSON state does not constitute federated learning.

Reports and presentations are preserved as supplied and may describe different development stages. Consult the executable source and current test results for present behaviour. Working backups, university handouts, temporary renders, packet captures, live logs, and virtual environments are excluded from this publishing copy.

## License

The project source code is provided under the [MIT License](LICENSE). External datasets retain their original terms and attribution.
