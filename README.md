# Network Security Traffic Analyzer — Public Demo

Educational Python/Jupyter network-log analyzer demonstrating DNS/ICMP, HTTP and TCP SYN observations with source-line provenance. **All included example traffic is synthetic.** This is not a production IDS and cannot establish attack intent or server exhaustion.

## Run locally

Extract the ZIP, open `Network_Security_Traffic_Analyzer_Public_Demo.ipynb` from this directory in Jupyter, and Run All; or run `python run_demo.py`. For tests, install pytest (`python -m pip install pytest`) then run `python -m pytest -q`. The demo analyzer uses the Python standard library.

## Google Colab

Open the notebook and Run All. If the project is not already present in the Colab runtime, the first code cell asks you to upload `Network_Security_Traffic_Analyzer_Public_Release.zip`. It extracts the files and runs the synthetic demo.

## Scope and limitations

- Input parsers accept limited tcpdump/Wireshark *text* formats, not raw PCAP.
- Results include source-line references; findings are observed or suspicious, never definitive attribution.
- Synthetic demo report is written to `reports/synthetic_demo_report.json`.
- The internal code retains an educational, fixed-IP ACK counterexample rule; this is **not** a general-purpose ACK correlation algorithm.
- The underlying analyzer was originally developed for private course evidence, which is intentionally **not** included.

## Layout

`analyzer_v04.py`: parsing/detection; `run_demo.py`: CLI demo; `synthetic_data/`: synthetic inputs; `tests/`: public tests; notebook: interactive demonstration.
