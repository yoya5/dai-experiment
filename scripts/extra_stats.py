from analyze_experiment import *
import random
repository = Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,default=repository/'analysis/derived');a=ap.parse_args();out=a.out
v=list(csv.DictReader((out/'victim_normalized_all.csv').open()));p=list(csv.DictReader((out/'pcap_metrics.csv').open()))
timing=[]
for r in p:
    matches=[x for x in v if x['tag']==r['tag']]
    if not matches or not r['end_utc']:continue
    end=datetime.datetime.fromisoformat(r['end_utc'])
    closest=min(matches,key=lambda x:abs((datetime.datetime.fromisoformat(x['time'])-end).total_seconds()))
    delta=(datetime.datetime.fromisoformat(closest['time'])-end).total_seconds()
    timing.append({'tag':r['tag'],'nearest_csv_line':closest['source_line'],'latest_csv_line':matches[-1]['source_line'],'csv_end_minus_pcap_end_s':round(delta,3),'same_attempt_unproven':closest!=matches[-1]})
writecsv(out/'capture_time_alignment.csv',timing)
stats=[];rng=random.Random(20261125)
for stand in ['cit','eltex']:
 for dai in ['off','on']:
    rr=[x for x in p if re.fullmatch(stand+'_'+dai+'_\\d+',x['tag']) and int(x['forged_gateway_arp'])>0]
    vals=[int(x['unique_gateway_requests_in']) for x in rr]
    boot=sorted(statistics.mean(rng.choices(vals,k=len(vals))) for _ in range(20000))
    stats.append({'stand':stand,'dai':dai,'pcap_n':len(vals),'observed_requests':sum(vals),'nominal_sent':100*len(vals),'observed_pct':statistics.mean(vals),'bootstrap95_exploratory':[boot[499],boot[19499]],'zero_runs_wilson95':wilson(0,len(vals)) if not sum(vals) else None})
(out/'traffic_stats.json').write_text(json.dumps(stats,indent=2))
