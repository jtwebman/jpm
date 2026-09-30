# Throwaway: how fast nuxt's tarballs download over HTTP/1.1 (32 connections, one request each at
# a time), HTTP/1.1 pipelined, and HTTP/2 (one connection, many streams). Bytes only, no unpack.
import asyncio, re, socket, ssl, sys, time
import httpx

names = []
for line in open(sys.argv[1]):
    m = re.match(r'package (.+)@([^@\s]+)$', line.strip())
    if m and not m.group(2).startswith(('link:', 'file:', 'workspace:')):
        names.append((m.group(1), m.group(2)))
def url(n, v):
    base = n.split('/')[-1]
    return f"https://registry.npmjs.org/{n}/-/{base}-{v}.tgz"
urls = [url(n, v) for n, v in names]
print(len(urls), "tarballs")

async def run(http2, conns, streams):
    limits = httpx.Limits(max_connections=conns, max_keepalive_connections=conns)
    async with httpx.AsyncClient(http2=http2, limits=limits, timeout=60) as c:
        sem = asyncio.Semaphore(streams)
        heads = []
        async def one(u):
            async with sem:
                t0 = time.perf_counter()
                async with c.stream("GET", u) as r:
                    t1 = time.perf_counter()
                    n = 0
                    async for b in r.aiter_bytes():
                        n += len(b)
                    heads.append(t1 - t0)
                    return n, r.http_version
        t = time.perf_counter()
        res = await asyncio.gather(*[one(u) for u in urls])
        dt = time.perf_counter() - t
        heads.sort()
        print(f"http2={http2} conns={conns} inflight={streams}: {dt*1000:.0f} ms, {sum(n for n,_ in res)/1e6:.1f} MB, "
              f"{res[0][1]}, head p50 {heads[len(heads)//2]*1000:.0f} p90 {heads[int(len(heads)*.9)]*1000:.0f} max {heads[-1]*1000:.0f} ms")

def pipelined(k):
    # k small tarballs on one TLS connection: sent back to back, then read in order.
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection(("registry.npmjs.org", 443)), server_hostname="registry.npmjs.org")
    f = s.makefile("rb")
    def get(u):
        return f"GET {u[len('https://registry.npmjs.org'):]} HTTP/1.1\r\nHost: registry.npmjs.org\r\nUser-Agent: probe\r\n\r\n".encode()
    def read_one():
        status = f.readline()
        length = 0
        while True:
            h = f.readline()
            if h in (b"\r\n", b""):
                break
            if h.lower().startswith(b"content-length:"):
                length = int(h.split(b":")[1])
        f.read(length)
        return status
    us = urls[:k]
    # warm the connection
    s.sendall(get(us[0])); read_one()
    t = time.perf_counter()
    for u in us:
        s.sendall(get(u)); read_one()
    seq = time.perf_counter() - t
    t = time.perf_counter()
    s.sendall(b"".join(get(u) for u in us))
    times = []
    for u in us:
        read_one(); times.append(time.perf_counter() - t)
    pip = time.perf_counter() - t
    print(f"one connection, {k} tarballs: one at a time {seq*1000:.0f} ms, pipelined {pip*1000:.0f} ms; "
          f"pipelined arrivals ms: {' '.join(str(int(x*1000)) for x in times[:10])} ...")
    s.close()

for _ in range(2):
    pipelined(20)
for _ in range(3):
    asyncio.run(run(False, 32, 32))
    asyncio.run(run(False, 64, 64))
    asyncio.run(run(True, 1, 100))
    asyncio.run(run(True, 4, 200))
    asyncio.run(run(True, 1, 600))
