from pathlib import Path
import pytest
from analyzer_v04 import extract_tcpdump, extract_wireshark, summarize
ROOT=Path(__file__).resolve().parents[1]
def load(name): return (ROOT/'synthetic_data'/name).read_text(encoding='utf-8')
def test_dns():
    e,b=extract_tcpdump(load('dns_icmp.txt'),'dns_icmp.txt'); assert not b; assert {x['type'] for x in e}=={'dns_query','icmp_port_unreachable'}
def test_http():
    e,b=extract_tcpdump(load('http.txt'),'http.txt'); assert not b; assert any(x.get('http_method')=='GET' for x in e)
def test_syn():
    e,b=extract_wireshark(load('syn.txt'),'syn.txt'); assert not b; assert any(x.get('flags')=='ACK' for x in e)
    f=summarize({'syn':{'events':e,'rejected':b}})['reports']['syn']['findings']; assert any(x['id']=='syn_burst' and x['classification']=='suspicious' for x in f)
def test_empty(): assert extract_tcpdump('not a record','empty')==([],[])
def test_invalid():
    with pytest.raises(ValueError): summarize({},syn_window=0)
def test_provenance():
    e,_=extract_tcpdump(load('http.txt'),'http.txt'); assert all(x['source_line']>0 for x in e)
