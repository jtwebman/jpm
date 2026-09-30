import sys, collections
# p5-ana.py <log>: timeline of a JPM_TRACE=1 install
ev=[]
for l in open(sys.argv[1]):
    if l.startswith('T '):
        p=l.split(' ',3); ev.append((int(p[1]),int(p[2]),p[3].strip()))
ev.sort()
marks=[(t,w) for t,th,w in ev if not w.startswith(('e+','e-','w+','w-','f+','f-','dl '))]
for t,w in marks: print(f"{t/1000:8.1f}ms {w}")
# entries
start={}; spans=[]; waits={}; wspans=[]
for t,th,w in ev:
    k=w.split(' ',1)
    if k[0]=='e+': start[(th,k[1])]=t
    elif k[0]=='e-': spans.append((start.pop((th,k[1])),t,th,k[1]))
    elif k[0]=='w+': waits[(th,k[1])]=t
    elif k[0]=='w-': wspans.append((waits.pop((th,k[1])),t,th,k[1]))
if spans:
    s0=min(s for s,_,_,_ in spans); s1=max(e for _,e,_,_ in spans)
    print(f"entries {len(spans)} from {s0/1000:.1f} to {s1/1000:.1f}ms; threads {len(set(th for _,_,th,_ in spans))}")
    busy=sum(e-s for s,e,_,_ in spans); wt=sum(e-s for s,e,_,_ in wspans)
    print(f"entry time total {busy/1000:.0f}ms, of which waiting for downloads {wt/1000:.0f}ms; avg parallel {busy/(s1-s0):.2f}")
    B=int(sys.argv[2]) if len(sys.argv)>2 else 10000
    for b in range(s0//B*B, s1+B, B):
        act=sum(max(0,min(e,b+B)-max(s,b)) for s,e,_,_ in spans)/B
        wa=sum(max(0,min(e,b+B)-max(s,b)) for s,e,_,_ in wspans)/B
        print(f"  {b/1000:7.0f}ms busy {act:5.2f} waiting {wa:5.2f} " + '#'*int(act*4))
    top=sorted(spans,key=lambda x:x[0]-x[1])[:8]
    for s,e,th,k in top: print(f"   long {k} {(e-s)/1000:.1f}ms at {s/1000:.0f}")
dl=[l for _,_,l in ev if l.startswith('dl ')]
if dl:
    rows=[]
    for l in dl:
        _,a,b,n,u=l.split(' ',4); rows.append((int(a),int(b),int(n),u))
    print(f"downloads {len(rows)}: head wait p50 {sorted(b-a for a,b,_,_ in rows)[len(rows)//2]/1000:.1f}ms max {max(b-a for a,b,_,_ in rows)/1000:.1f}ms; bytes {sum(n for _,_,n,_ in rows)/1e6:.1f}MB")
    fe={}
    for t,th,w in ev:
        k=w.split(' ')
        if k[0]=='f+': fe[k[1]]=[t]
        elif k[0]=='f-' and k[1] in fe: fe[k[1]].append(t); fe[k[1]].append(k[2] if len(k)>2 else '')
    fs=sorted([(v[0],v[1],v[2]) for v in fe.values() if len(v)==3],key=lambda x:x[1])
    print("last 12 fetches to finish (start, end, dur, url):")
    for a,b,u in fs[-12:]: print(f"   {a/1000:7.1f} {b/1000:7.1f} {(b-a)/1000:6.1f} {u[-70:]}")
    print("longest 10 fetches:")
    for a,b,u in sorted(fs,key=lambda x:x[0]-x[1])[:10]: print(f"   {a/1000:7.1f} {b/1000:7.1f} {(b-a)/1000:6.1f} {u[-70:]}")
