"""Run synthetic examples only; no private course evidence required."""
from pathlib import Path
from analyzer_v04 import extract_tcpdump, extract_wireshark, summarize, save
root = Path(__file__).resolve().parent
sources = {'dns_icmp': ('dns_icmp.txt', extract_tcpdump), 'http': ('http.txt', extract_tcpdump), 'syn': ('syn.txt', extract_wireshark)}
evidence = {}
for name, (filename, parser) in sources.items():
    events, rejected = parser((root/'synthetic_data'/filename).read_text(encoding='utf-8'), filename)
    evidence[name] = {'events': events, 'rejected': rejected}
report = summarize(evidence)
report['evidence_origin'] = 'synthetic_demo'
report['limitations'] = ['Synthetic demonstration, not evidence of a real incident.']
out = root/'reports'/'synthetic_demo_report.json'
out.parent.mkdir(exist_ok=True)
save(report, out)
for name, result in report['reports'].items():
    print(name, result['counts'], [(f['id'],f['classification']) for f in result['findings']])
print('Saved:',out)
