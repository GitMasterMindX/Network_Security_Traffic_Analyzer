"""v0.4 read-only extraction of limited course evidence, with provenance and abstention."""
import re, json, math
from collections import Counter, defaultdict
from pathlib import Path

STAMP = re.compile(r'^\s*(\d{2}:\d{2}:\d{2}\.\d{1,6})\s+IP\s+(.+)$')
WIRESHARK = re.compile(r'^\s*(\d+)\s+(\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(TCP|HTTP)\s+(.*)$')
FLAGS = re.compile(r'Flags\s*\[([^]]+)\]')
WSFLAGS = re.compile(r'\[(SYN(?:, ACK)?|ACK|RST(?:, ACK)?)(?:\]|\s)')
DNS_QUERY = re.compile(r'\b(\d+)\+\s+A\?\s*([\w.-]+)')
DNS_RESPONSE = re.compile(r'\b(\d+)\s+1/0/0\s+A\s+(\d+\.\d+\.\d+\.\d+)')
HTTP = re.compile(r'\b(?:HTTP:\s*)?(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)\s+HTTP/1\.[01]')

def logical_records(text):
    """Join wrapped PDF-extracted tcpdump lines; keep source physical line references."""
    rows=[]; current=None
    for n,line in enumerate(text.replace('\u200b','').replace('\ufeff','').splitlines(),1):
        line=line.strip()
        if not line or line=='\x0c': continue
        if STAMP.match(line):
            if current: rows.append(current)
            current={'line':n,'raw':line}
        elif current and not line.startswith('…') and not line.startswith('...'):
            current['raw']+=' '+line
    if current: rows.append(current)
    return rows

def extract_tcpdump(text, source):
    events=[]; rejected=[]
    for row in logical_records(text):
        line=row['raw']; m=STAMP.match(line)
        if not m: continue
        ts,body=m.groups()
        if ' > ' not in body or ': ' not in body:
            rejected.append({'source':source,'line':row['line'],'reason':'unrecognized_header'}); continue
        head,content=body.split(': ',1)
        src,dst=head.split(' > ',1)
        kind=None; extra={}
        if 'ICMP' in content and 'udp port 53 unreachable' in content.lower(): kind='icmp_port_unreachable'
        elif DNS_QUERY.search(content):
            kind='dns_query'; q=DNS_QUERY.search(content);extra={'dns_id':int(q[1]),'domain':q[2].rstrip('.')}
        elif DNS_RESPONSE.search(content):
            kind='dns_response';q=DNS_RESPONSE.search(content);extra={'dns_id':int(q[1]),'answer_ip':q[2]}
        elif FLAGS.search(content):
            kind='tcp';extra={'flags':FLAGS.search(content)[1]}
            h=HTTP.search(content)
            if h: extra.update({'http_method':h[1],'http_path':h[2]})
        elif HTTP.search(content):
            kind='http';h=HTTP.search(content);extra={'http_method':h[1],'http_path':h[2]}
        if kind:
            events.append({'source':source,'source_line':row['line'],'timestamp':ts,'src':src,'dst':dst,'type':kind,**extra})
        else: rejected.append({'source':source,'line':row['line'],'reason':'unsupported_payload'})
    return events,rejected

def extract_wireshark(text,source):
    events=[]; rejected=[]
    for line_no,line in enumerate(text.splitlines(),1):
        m=WIRESHARK.match(line)
        if not m: continue
        packet,t,src,dst,proto,info=m.groups()
        flag=WSFLAGS.search(info)
        kind='tcp' if proto=='TCP' else 'http'
        event={'source':source,'source_line':line_no,'packet_number':int(packet), 'timestamp':float(t),
               'src':src,'dst':dst,'type':kind}
        if flag: event['flags']=flag[1]
        http=HTTP.search(info)
        if http: event.update({'http_method':http[1],'http_path':http[2]})
        if '504 Gateway Time-out' in info: event['http_status']=504
        events.append(event)
    return events,rejected

def summarize(evidence, syn_window=10.0, syn_threshold=5):
    if not isinstance(syn_window,(float,int)) or not math.isfinite(syn_window) or syn_window<=0 or not isinstance(syn_threshold,int) or isinstance(syn_threshold,bool) or syn_threshold<1:
        raise ValueError('invalid detector settings')
    result={'schema_version':'0.4','evidence_origin':'course_lab_materials','reports':{},'limitations':[
        'PDF text extraction and manual screenshot transcription are not original PCAP captures',
        'Wireshark display time is relative to capture, not a wall-clock timestamp',
        'Repeated SYN packets alone do not prove attack, exhaustion, or intent',
        'HTTP excerpt contains omissions; request volume and brute-force cannot be established',
        'DNS/ICMP temporal proximity alone does not prove packet-level causality']}
    for name,items in evidence.items():
        events=items['events']; rejected=items['rejected']; counts=Counter(e['type'] for e in events)
        findings=[]
        if name=='dns_icmp':
            dns=[e for e in events if e['type']=='dns_query'];icmp=[e for e in events if e['type']=='icmp_port_unreachable']
            if dns and icmp: findings.append({'id':'dns_icmp_pattern','classification':'observed','dns_queries':len(dns),'icmp_errors':len(icmp),'detail':'Both types occur; individual packet causality unverified','evidence':[{'source':e['source'],'line':e['source_line']} for e in dns+icmp]})
        if name=='http':
            queries=[e for e in events if e['type']=='dns_query']; replies=[e for e in events if e['type']=='dns_response']; gets=[e for e in events if e.get('http_method')=='GET']
            if gets: findings.append({'id':'http_get','classification':'observed','count':len(gets),'detail':'Visible HTTP GETs; total requests unknown','evidence':[{'source':e['source'],'line':e['source_line']} for e in gets]})
            if queries and replies: findings.append({'id':'dns_answers','classification':'observed','queries':len(queries),'answers':len(replies)})
        if name=='syn':
            by_source=defaultdict(list)
            for e in events:
                if e.get('flags')=='SYN':by_source[e['src']].append(e)
            for src,arr in by_source.items():
                arr.sort(key=lambda x:x['timestamp']); left=0; best=[]
                for right,e in enumerate(arr):
                    while e['timestamp']-arr[left]['timestamp']>syn_window:left+=1
                    if right-left+1>len(best):best=arr[left:right+1]
                if len(best)>=syn_threshold:
                    findings.append({'id':'syn_burst','classification':'suspicious','source_ip':src,'count_in_window':len(best),'window_seconds':syn_window,
                        'detail':'SYN burst observed; cannot establish exhaustion or intent',
                        'evidence':[{'source':e['source'],'line':e['source_line'],'packet':e['packet_number']} for e in best]})
            ack=[e for e in events if e['src']=='203.0.113.0' and e.get('flags')=='ACK']
            if ack: findings.append({'id':'ack_counterexample','classification':'observed','count':len(ack),'detail':'At least one ACK from the suspected source contradicts a never-ACK assertion',
                'evidence':[{'source':e['source'],'line':e['source_line'],'packet':e['packet_number']} for e in ack]})
            statuses=[e for e in events if e.get('http_status')==504]
            if statuses: findings.append({'id':'http_504','classification':'observed','count':len(statuses)})
        result['reports'][name]={'parsed':len(events),'rejected':len(rejected),'counts':dict(counts),'findings':findings,'rejection_samples':rejected[:10]}
    return result

def save(report,path):Path(path).write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
