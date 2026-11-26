"""Offline audit of classic Ethernet PCAP and original CSV. No network activity."""
from pathlib import Path
import csv,io,re,struct,json,math,statistics,collections,datetime,argparse

def writecsv(path, rows):
    if not rows:return
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def wilson(k,n):
    z=1.959963984540054;p=k/n;d=1+z*z/n
    c=(p+z*z/(2*n))/d;h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [max(0,c-h)*100,min(1,c+h)*100]
def pcap_read(p):
    b=p.read_bytes(); endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}.get(b[:4])
    if not endian:raise ValueError(f'Unsupported PCAP: {p}')
    if struct.unpack_from(endian+'I',b,20)[0]!=1:raise ValueError('Not Ethernet')
    off=24
    while off<len(b):
        sec,us,n,orig=struct.unpack_from(endian+'IIII',b,off);off+=16
        d=b[off:off+n];off+=n
        if len(d)!=n:raise ValueError('Truncated packet')
        yield sec+us/1e6,d
def normtag(t):
    m=re.fullmatch(r'(cit|eltex)_(on|off)_(\d+)',t)
    return f'{m[1]}_{m[2]}_{int(m[3]):02}' if m else t
def analyze(src,pcaps,out):
    out.mkdir(parents=True,exist_ok=True)
    victim_csv = src / 'results.csv'
    if not victim_csv.is_file():
        victim_csv = src / 'victim/results.csv'
    raw=victim_csv.read_text(encoding='utf-8-sig').splitlines()
    head=raw[0].split(','); logical=[]; repairs=[]
    for ln,line in enumerate(raw[1:],2):
        if re.match(r'^\d{4}-\d\d-\d\dT',line):logical.append([ln,line])
        elif line.strip():
            repairs.append({'source_line':ln,'action':'joined unquoted multiline victim_ip using semicolon'})
            logical[-1][1]+=';'+line
    victims=[]
    for ln,line in logical:
        vals=next(csv.reader([line]));assert len(vals)==len(head),(ln,vals)
        r=dict(zip(head,vals));r['source_line']=ln;r['tag']=f"{r['stand']}_{r['dai']}_{int(r['trial']):02}"
        victims.append(r)
    kali=list(csv.DictReader((src/'kali_intercept.csv').open(encoding='utf-8-sig')))
    writecsv(out/'victim_normalized_all.csv',victims)
    writecsv(out/'csv_repairs.csv',repairs)
    last={r['tag']:r for r in victims}; first={}
    for r in victims:first.setdefault(r['tag'],r)
    km=bytes.fromhex('080027ce96be');gm=bytes.fromhex('001ae2e225c1')
    vip=bytes([192,168,10,14]);gw=bytes([192,168,10,1])
    rows=[]; details=[]
    for p in sorted(pcaps.glob('*.pcap')):
        tag=normtag(p.stem);cts=collections.Counter();ins={};fwds={};replies=set();ts=[]; patterns=collections.Counter();ownips=set()
        for num,(t,d) in enumerate(pcap_read(p),1):
            ts.append(t);cts['packets']+=1
            if len(d)<14:continue
            dst,srcmac=d[:6],d[6:12];etype=int.from_bytes(d[12:14],'big');o=14
            if etype==0x8100:etype=int.from_bytes(d[16:18],'big');o=18
            if etype==0x806 and len(d)>=o+28:
                a=d[o:]; op=int.from_bytes(a[6:8],'big')
                if srcmac==km and op==2 and a[14:18]==gw:
                    cts['arp_gateway_claims']+=1
                    if a[8:14]==km:cts['forged_gateway_arp']+=1
                if srcmac==km and a[8:14]==km and a[14:18]!=gw:ownips.add('.'.join(map(str,a[14:18])))
                continue
            if etype!=0x800 or len(d)<o+20:continue
            ip=d[o:];ihl=(ip[0]&15)*4
            if ip[9]!=1 or len(ip)<ihl+8:continue
            sip,dip=ip[12:16],ip[16:20];ic=ip[ihl:];typ=ic[0]
            if sip==vip and dst==km:cts['original_in_filter']+=1
            if sip==vip and srcmac==km:cts['original_fwd_filter']+=1
            key=(ic[4:8].hex(),ic[8:].hex())
            if sip==vip and dip==gw and typ==8:
                patterns[ic[24:27].hex()]+=1
                if dst==km:ins[key]=(t,num);cts['request_frames_in']+=1
                if srcmac==km and dst==gm:fwds[key]=(t,num);cts['request_frames_forwarded']+=1
            if sip==gw and dip==vip and typ==0:replies.add(key)
        matched=set(ins)&set(fwds)
        row={'tag':tag,'pcap':p.name,'packets':cts['packets'],'start_utc':datetime.datetime.fromtimestamp(ts[0],datetime.timezone.utc).isoformat() if ts else '', 'duration_s':round(ts[-1]-ts[0],3) if ts else 0,
             'end_utc':datetime.datetime.fromtimestamp(ts[-1],datetime.timezone.utc).isoformat() if ts else '', 'kali_arp_source_ips':';'.join(sorted(ownips)), 'forged_gateway_arp':cts['forged_gateway_arp'],'original_in_filter':cts['original_in_filter'],'original_fwd_filter':cts['original_fwd_filter'],'unique_gateway_requests_in':len(ins),'unique_gateway_requests_forwarded':len(fwds),'matched_in_forwarded':len(matched),'requests_with_reply_seen':len(set(ins)&replies)}
        rows.append(row)
        for key in sorted(matched):
            details.append({'tag':tag,'icmp_id_seq_hex':key[0],'in_frame':ins[key][1],'out_frame':fwds[key][1],'delay_ms':round((fwds[key][0]-ins[key][0])*1000,3)})
    writecsv(out/'pcap_metrics.csv',rows);writecsv(out/'forwarding_pairs.csv',details)
    pm={r['tag']:r for r in rows};joined=[]
    for tag,r in sorted(last.items()):
        row=dict(r);row.update({k:v for k,v in pm[tag].items() if k!='tag'});joined.append(row)
    writecsv(out/'trials_last_record.csv',joined)
    summary=[]
    for stand in ['cit','eltex']:
      for dai in ['off','on']:
        rr=[r for r in joined if r['stand']==stand and r['dai']==dai];allr=[r for r in victims if r['stand']==stand and r['dai']==dai]
        loss=[float(r['att_loss']) for r in rr];n=len(rr);k=sum(int(r['spoof']) for r in rr)
        intercepted=sum(r['unique_gateway_requests_in'] for r in rr)
        summary.append(dict(stand=stand,dai=dai,n=n,all_records=len(allr),spoof_last=k,spoof_first=sum(int(first[r['tag']]['spoof']) for r in rr),spoof_all=sum(int(r['spoof']) for r in allr),wilson95=wilson(k,n),loss_mean=statistics.mean(loss),loss_max=max(loss),loss_nonzero=sum(v>0 for v in loss),loss_sum=sum(loss),sent_sum=sum(int(r['sent']) for r in rr),intercepted=intercepted,forwarded=sum(r['matched_in_forwarded'] for r in rr),captures_with_attack=sum(r['forged_gateway_arp']>0 for r in rr),intercepted_runs=sum(r['unique_gateway_requests_in']>0 for r in rr),pre_loss_nonzero=sum(float(r['pre_loss'])!=0 for r in rr)))
    (out/'summary.json').write_text(json.dumps({'summary':summary,'victim_records':len(victims),'kali_records':len(kali),'repaired_lines':len(repairs),'pcaps':len(rows)},indent=2),encoding='utf-8')
if __name__=='__main__':
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=repository / 'csv')
    parser.add_argument('--pcaps', type=Path, default=repository / 'pcaps')
    parser.add_argument('--out', type=Path, default=repository / 'analysis/derived')
    args = parser.parse_args()
    analyze(args.source, args.pcaps, args.out)
