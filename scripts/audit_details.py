from analyze_experiment import *
repository = Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,default=repository/'analysis');ap.add_argument('--victim-logs',type=Path,default=repository/'logs/victim_logs');ap.add_argument('--pcaps',type=Path);a=ap.parse_args()
root=a.root; rows=list(csv.DictReader((root/'derived/trials_last_record.csv').open(encoding='utf-8')))
allrows=list(csv.DictReader((root/'derived/victim_normalized_all.csv').open(encoding='utf-8')))
audit=[]
for r in rows:
    tag=r['tag'];log=(a.victim_logs/f'{tag}.log').read_text(encoding='utf-8',errors='replace')
    matches=re.findall(r'подмена=(\d+)\s+потери=([\d.]+)%',log)
    expected=[(x['spoof'],x['att_loss']) for x in allrows if x['tag']==tag]
    audit.append({'tag':tag,'logged_complete_attempts':len(matches),'csv_last_agrees_log':bool(matches and matches[-1]==(r['spoof'],r['att_loss'])),'all_csv_attempts_agree_log':matches==expected})
writecsv(root/'derived/log_checks.csv',audit)
