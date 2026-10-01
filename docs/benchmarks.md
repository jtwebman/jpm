# Benchmarks

`bench/bench.sh` installs three projects with each package manager in four phases:

- **cold**: no cache, no lockfile, no `node_modules`
- **warm**: cache and lockfile kept, `node_modules` deleted: CI with its cache restored
- **ci**: lockfile kept, no cache, no `node_modules`: CI with no cache
- **repeat**: nothing changed

Fixtures: `nitro` (62 packages), `nuxt` (591), `next` (275). Every manager has its own home,
caches and store, a fresh copy of the fixture, and lifecycle scripts off; rounds run every
manager once before the next round, so a slow minute on the network is spread over all of them.
CPU time is what a CI runner's two to four cores pay for, and the cache is what CI saves and
restores between runs. The best value in each column is bold.

## GitHub Actions, Linux

`ubuntu-latest` (4 cores), 2026-09-30, medians of 5 runs against the live npm registry; 480 runs,
0 failed.

**Wall time**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci | nitro repeat | nuxt repeat | next repeat |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | 482 ms | **1.22 s** | **924 ms** | **4 ms** | 206 ms | **115 ms** | **168 ms** | 734 ms | **770 ms** | **1 ms** | **2 ms** | **1 ms** |
| bun 1.4.2 | **377 ms** | 1.28 s | 1.72 s | 29 ms | 234 ms | 149 ms | 188 ms | **676 ms** | 1.02 s | 4 ms | 18 ms | 3 ms |
| aube 2.6.0 | 522 ms | 3.00 s | 1.52 s | 43 ms | **186 ms** | 134 ms | 240 ms | 896 ms | 818 ms | 5 ms | 7 ms | 4 ms |
| pnpm 12.8.1 | 634 ms | 1.72 s | 2.87 s | 65 ms | 435 ms | 200 ms | 461 ms | 1.53 s | 2.10 s | 10 ms | 11 ms | 10 ms |
| deno 2.9.6 | 532 ms | 7.64 s | 2.72 s | 33 ms | 338 ms | 219 ms | 307 ms | 1.20 s | 1.45 s | 7 ms | 28 ms | 8 ms |
| upm 1.3.1 | 1.12 s | 3.52 s | 2.47 s | 99 ms | 447 ms | 209 ms | 530 ms | 2.06 s | 1.84 s | 40 ms | 44 ms | 38 ms |
| yarn 4.18.1 | 1.75 s | 9.63 s | 8.36 s | 690 ms | 3.13 s | 3.54 s | 1.28 s | 5.58 s | 6.50 s | 385 ms | 1.02 s | 771 ms |
| npm 12.1.0 | 2.07 s | 18.54 s | 10.55 s | 930 ms | 4.69 s | 6.53 s | 1.22 s | 6.62 s | 7.48 s | 326 ms | 794 ms | 334 ms |

**CPU time (every process the install starts)**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci | nitro repeat | nuxt repeat | next repeat |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | **350 ms** | 3.05 s | **2.47 s** | **0 ms** | 440 ms | 190 ms | **230 ms** | 2.14 s | **1.79 s** | **0 ms** | **0 ms** | **0 ms** |
| bun 1.4.2 | 420 ms | **2.60 s** | 2.87 s | 20 ms | **220 ms** | **140 ms** | 340 ms | **1.92 s** | 2.24 s | **0 ms** | 10 ms | **0 ms** |
| aube 2.6.0 | 470 ms | 3.32 s | 2.76 s | 60 ms | 530 ms | 270 ms | 340 ms | 2.24 s | 1.93 s | **0 ms** | **0 ms** | **0 ms** |
| pnpm 12.8.1 | 700 ms | 4.48 s | 4.56 s | 100 ms | 840 ms | 390 ms | 710 ms | 3.85 s | 4.71 s | **0 ms** | **0 ms** | **0 ms** |
| deno 2.9.6 | 540 ms | 4.35 s | 2.98 s | 50 ms | 520 ms | 220 ms | 380 ms | 2.56 s | 1.98 s | **0 ms** | 20 ms | **0 ms** |
| upm 1.3.1 | 2.52 s | 11.03 s | 6.92 s | 130 ms | 1.06 s | 540 ms | 1.12 s | 5.77 s | 4.82 s | 30 ms | 40 ms | 30 ms |
| yarn 4.18.1 | 3.27 s | 17.08 s | 13.99 s | 1.00 s | 5.17 s | 4.60 s | 2.62 s | 11.95 s | 10.12 s | 480 ms | 1.45 s | 890 ms |
| npm 12.1.0 | 2.56 s | 19.62 s | 13.18 s | 1.51 s | 8.27 s | 8.70 s | 1.87 s | 11.08 s | 10.31 s | 420 ms | 1.05 s | 430 ms |

**Peak memory (RSS)**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci | nitro repeat | nuxt repeat | next repeat |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | **42 MB** | 152 MB | **140 MB** | **3.9 MB** | **7.1 MB** | **5.2 MB** | **9.7 MB** | **34 MB** | **23 MB** | **3.6 MB** | **3.7 MB** | **3.6 MB** |
| bun 1.4.2 | 61 MB | **121 MB** | 148 MB | 16 MB | 18 MB | 16 MB | 42 MB | 89 MB | 93 MB | 14 MB | 18 MB | 14 MB |
| aube 2.6.0 | 215 MB | 568 MB | 416 MB | 56 MB | 95 MB | 69 MB | 155 MB | 299 MB | 248 MB | 14 MB | 24 MB | 14 MB |
| pnpm 12.8.1 | 110 MB | 226 MB | 361 MB | 37 MB | 59 MB | 51 MB | 78 MB | 184 MB | 346 MB | 20 MB | 20 MB | 20 MB |
| deno 2.9.6 | 116 MB | 393 MB | 508 MB | 26 MB | 33 MB | 27 MB | 86 MB | 165 MB | 307 MB | 25 MB | 30 MB | 25 MB |
| upm 1.3.1 | 259 MB | 599 MB | 672 MB | 64 MB | 131 MB | 126 MB | 182 MB | 368 MB | 513 MB | 52 MB | 52 MB | 52 MB |
| yarn 4.18.1 | 560 MB | 979 MB | 2974 MB | 211 MB | 379 MB | 812 MB | 527 MB | 870 MB | 2718 MB | 122 MB | 187 MB | 122 MB |
| npm 12.1.0 | 199 MB | 692 MB | 383 MB | 153 MB | 507 MB | 590 MB | 157 MB | 387 MB | 316 MB | 99 MB | 134 MB | 103 MB |

**Disk after a cold install (`node_modules` and the store, a hardlinked file once)**

| manager | nitro | nuxt | next |
| --- | ---: | ---: | ---: |
| **jpm** | **34 MB** | **244 MB** | **351 MB** |
| bun 1.4.2 | 54 MB | 261 MB | 469 MB |
| aube 2.6.0 | 53 MB | 365 MB | 452 MB |
| pnpm 12.8.1 | 51 MB | 290 MB | 437 MB |
| deno 2.9.6 | 55 MB | 280 MB | 467 MB |
| upm 1.3.1 | 47 MB | 293 MB | 352 MB |
| yarn 4.18.1 | 60 MB | 382 MB | 658 MB |
| npm 12.1.0 | 62 MB | 443 MB | 524 MB |

**Cache after a cold install (what CI saves and restores)**

| manager | nitro | nuxt | next |
| --- | ---: | ---: | ---: |
| **jpm** | 34 MB | 229 MB | 347 MB |
| bun 1.4.2 | 53 MB | 253 MB | 466 MB |
| aube 2.6.0 | 52 MB | 349 MB | 448 MB |
| pnpm 12.8.1 | 49 MB | 273 MB | 433 MB |
| deno 2.9.6 | 53 MB | 266 MB | 463 MB |
| upm 1.3.1 | 46 MB | 274 MB | 348 MB |
| yarn 4.18.1 | **30 MB** | **184 MB** | 328 MB |
| npm 12.1.0 | 32 MB | 237 MB | **194 MB** |

## A developer machine, Linux (WSL2)

Ubuntu 24.04 in WSL2 on an i9-12900K, on a home connection about 15 ms from the registry,
2026-09-30, medians of 5 runs; 480 runs, 0 failed.

**Wall time**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci | nitro repeat | nuxt repeat | next repeat |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | **661 ms** | **2.99 s** | **4.00 s** | **4 ms** | 120 ms | **66 ms** | 506 ms | **2.01 s** | 3.29 s | **1 ms** | **1 ms** | **1 ms** |
| bun 1.4.2 | 942 ms | 4.11 s | 5.80 s | 29 ms | 202 ms | 97 ms | 722 ms | 2.52 s | 5.24 s | 2 ms | 9 ms | 2 ms |
| aube 2.6.0 | 731 ms | 4.71 s | 4.60 s | 16 ms | **115 ms** | 97 ms | **468 ms** | 3.44 s | **3.26 s** | 5 ms | 24 ms | 3 ms |
| pnpm 12.8.1 | 771 ms | 3.19 s | 5.18 s | 43 ms | 226 ms | 140 ms | 635 ms | 2.58 s | 4.53 s | 6 ms | 6 ms | 6 ms |
| deno 2.9.6 | 1.05 s | 7.98 s | 6.49 s | 23 ms | 178 ms | 110 ms | 755 ms | 5.74 s | 5.24 s | 6 ms | 18 ms | 12 ms |
| upm 1.3.1 | 863 ms | 3.40 s | 4.03 s | 68 ms | 291 ms | 117 ms | 527 ms | 2.74 s | 3.44 s | 23 ms | 25 ms | 25 ms |
| yarn 4.18.1 | 1.45 s | 6.39 s | 9.46 s | 408 ms | 1.93 s | 2.37 s | 1.02 s | 4.01 s | 8.05 s | 235 ms | 586 ms | 495 ms |
| npm 12.1.0 | 1.36 s | 13.81 s | 8.50 s | 584 ms | 3.20 s | 4.40 s | 812 ms | 4.66 s | 5.67 s | 173 ms | 407 ms | 180 ms |

**CPU time (every process the install starts)**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci | nitro repeat | nuxt repeat | next repeat |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | **220 ms** | 2.09 s | **1.63 s** | **0 ms** | 460 ms | 110 ms | **150 ms** | 1.50 s | **1.29 s** | **0 ms** | **0 ms** | **0 ms** |
| bun 1.4.2 | 290 ms | **1.87 s** | 2.03 s | 30 ms | **210 ms** | **100 ms** | 240 ms | **1.46 s** | 1.57 s | **0 ms** | **0 ms** | **0 ms** |
| aube 2.6.0 | 390 ms | 2.69 s | 2.26 s | 20 ms | **210 ms** | 170 ms | 250 ms | 1.85 s | 1.44 s | **0 ms** | 20 ms | **0 ms** |
| pnpm 12.8.1 | 430 ms | 3.05 s | 2.87 s | 70 ms | 680 ms | 190 ms | 450 ms | 2.56 s | 2.82 s | **0 ms** | **0 ms** | **0 ms** |
| deno 2.9.6 | 340 ms | 2.70 s | 2.31 s | 40 ms | 520 ms | 140 ms | 260 ms | 1.78 s | 1.44 s | **0 ms** | 10 ms | **0 ms** |
| upm 1.3.1 | 1.43 s | 6.83 s | 4.77 s | 130 ms | 920 ms | 310 ms | 680 ms | 3.66 s | 3.26 s | 20 ms | 20 ms | 20 ms |
| yarn 4.18.1 | 1.91 s | 10.56 s | 10.62 s | 610 ms | 3.25 s | 2.94 s | 1.49 s | 7.17 s | 7.04 s | 270 ms | 830 ms | 570 ms |
| npm 12.1.0 | 1.56 s | 13.20 s | 10.08 s | 870 ms | 5.12 s | 5.41 s | 1.16 s | 7.19 s | 7.24 s | 220 ms | 570 ms | 230 ms |

**Peak memory (RSS)**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci | nitro repeat | nuxt repeat | next repeat |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | **42 MB** | 146 MB | **120 MB** | **3.8 MB** | **7.1 MB** | **5.2 MB** | **8.5 MB** | **25 MB** | **23 MB** | **3.5 MB** | **3.5 MB** | **3.5 MB** |
| bun 1.4.2 | 47 MB | **96 MB** | 125 MB | 11 MB | 13 MB | 11 MB | 26 MB | 50 MB | 34 MB | 10 MB | 13 MB | 10 MB |
| aube 2.6.0 | 194 MB | 521 MB | 351 MB | 41 MB | 84 MB | 65 MB | 115 MB | 239 MB | 192 MB | 20 MB | 24 MB | 14 MB |
| pnpm 12.8.1 | 106 MB | 229 MB | 368 MB | 37 MB | 57 MB | 51 MB | 79 MB | 161 MB | 334 MB | 20 MB | 20 MB | 20 MB |
| deno 2.9.6 | 110 MB | 392 MB | 425 MB | 21 MB | 28 MB | 21 MB | 80 MB | 248 MB | 286 MB | 20 MB | 25 MB | 20 MB |
| upm 1.3.1 | 254 MB | 547 MB | 562 MB | 61 MB | 119 MB | 117 MB | 169 MB | 335 MB | 461 MB | 48 MB | 49 MB | 48 MB |
| yarn 4.18.1 | 489 MB | 931 MB | 2372 MB | 192 MB | 350 MB | 804 MB | 495 MB | 844 MB | 2253 MB | 118 MB | 183 MB | 120 MB |
| npm 12.1.0 | 153 MB | 693 MB | 328 MB | 147 MB | 496 MB | 553 MB | 144 MB | 370 MB | 233 MB | 94 MB | 130 MB | 98 MB |

**Disk after a cold install (`node_modules` and the store, a hardlinked file once)**

| manager | nitro | nuxt | next |
| --- | ---: | ---: | ---: |
| **jpm** | **34 MB** | **244 MB** | **351 MB** |
| bun 1.4.2 | 54 MB | 261 MB | 469 MB |
| aube 2.6.0 | 54 MB | 373 MB | 452 MB |
| pnpm 12.8.1 | 51 MB | 290 MB | 437 MB |
| deno 2.9.6 | 55 MB | 280 MB | 467 MB |
| upm 1.3.1 | 48 MB | 293 MB | 352 MB |
| yarn 4.18.1 | 60 MB | 382 MB | 658 MB |
| npm 12.1.0 | 62 MB | 443 MB | 524 MB |

**Cache after a cold install (what CI saves and restores)**

| manager | nitro | nuxt | next |
| --- | ---: | ---: | ---: |
| **jpm** | 34 MB | 229 MB | 347 MB |
| bun 1.4.2 | 53 MB | 252 MB | 466 MB |
| aube 2.6.0 | 54 MB | 369 MB | 448 MB |
| pnpm 12.8.1 | 49 MB | 273 MB | 433 MB |
| deno 2.9.6 | 53 MB | 266 MB | 463 MB |
| upm 1.3.1 | 46 MB | 274 MB | 348 MB |
| yarn 4.18.1 | **30 MB** | **184 MB** | 328 MB |
| npm 12.1.0 | 32 MB | 237 MB | **194 MB** |

## The same machine, Windows

Windows 11, Defender real-time protection on, 2026-09-30, medians of 3 runs of five managers;
135 runs, 0 failed. Defender scans every file an install writes, and it scans files written
by `node.exe` far more cheaply than files written by other programs: npm, upm and yarn run under
Node, while jpm, aube, pnpm, bun and deno are native. Windows keeps no peak RSS for a tree of
processes, so the memory here is the tree's peak committed memory: compare it only with other
Windows runs.

**Wall time**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | 1.32 s | 8.53 s | **6.91 s** | **28 ms** | 1.45 s | **1.25 s** | 1.03 s | 8.01 s | **6.76 s** |
| upm 1.3.1 | 1.77 s | **7.40 s** | 8.00 s | 1.02 s | 4.41 s | 2.97 s | 1.49 s | 6.80 s | 7.56 s |
| npm 12.1.0 | 1.67 s | 11.88 s | 12.07 s | 1.27 s | 4.84 s | 10.82 s | 1.31 s | **5.15 s** | 10.94 s |
| pnpm 12.8.1 | **994 ms** | 9.14 s | 9.06 s | 418 ms | 3.75 s | 2.44 s | **1.02 s** | 8.81 s | 8.35 s |
| aube 2.6.1 | 1.77 s | 17.45 s | 13.83 s | 98 ms | **491 ms** | 2.54 s | 1.33 s | 16.01 s | 12.08 s |

**CPU time (every process the install starts)**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | 2.98 s | 27.91 s | 15.17 s | **31 ms** | 7.02 s | **5.22 s** | 2.70 s | 25.38 s | 13.25 s |
| upm 1.3.1 | 3.19 s | 33.20 s | 17.84 s | 1.06 s | 14.67 s | 9.50 s | 2.31 s | 27.94 s | 16.50 s |
| npm 12.1.0 | **2.78 s** | **23.80 s** | **14.41 s** | 2.14 s | 12.97 s | 11.05 s | **2.16 s** | **15.88 s** | **12.59 s** |
| pnpm 12.8.1 | 4.44 s | 30.89 s | 31.25 s | 2.97 s | 29.08 s | 19.05 s | 2.97 s | 27.12 s | 24.44 s |
| aube 2.6.1 | 6.80 s | 81.98 s | 44.14 s | 250 ms | **2.83 s** | 20.23 s | 4.70 s | 74.78 s | 39.61 s |

**Peak memory (the process tree's peak committed memory)**

| manager | nitro cold | nuxt cold | next cold | nitro warm | nuxt warm | next warm | nitro ci | nuxt ci | next ci |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **jpm** | **49 MB** | **170 MB** | **128 MB** | **1.4 MB** | **5.3 MB** | **4.2 MB** | **8.1 MB** | **43 MB** | **18 MB** |
| upm 1.3.1 | 244 MB | 663 MB | 603 MB | 68 MB | 162 MB | 151 MB | 175 MB | 503 MB | 540 MB |
| npm 12.1.0 | 224 MB | 694 MB | 278 MB | 151 MB | 508 MB | 521 MB | 148 MB | 392 MB | 216 MB |
| pnpm 12.8.1 | 57 MB | 173 MB | 149 MB | 14 MB | 29 MB | 19 MB | 54 MB | 138 MB | 183 MB |
| aube 2.6.1 | 340 MB | 1924 MB | 502 MB | 88 MB | 180 MB | 101 MB | 241 MB | 1548 MB | 320 MB |

**Disk after a cold install (`node_modules` and the store, a hardlinked file once)**

| manager | nitro | nuxt | next |
| --- | ---: | ---: | ---: |
| **jpm** | **34 MB** | **220 MB** | 352 MB |
| upm 1.3.1 | 44 MB | 261 MB | **347 MB** |
| npm 12.1.0 | 61 MB | 419 MB | 524 MB |
| pnpm 12.8.1 | 50 MB | 281 MB | 445 MB |
| aube 2.6.1 | 53 MB | 353 MB | 458 MB |

**Cache after a cold install (what CI saves and restores)**

| manager | nitro | nuxt | next |
| --- | ---: | ---: | ---: |
| **jpm** | 34 MB | **215 MB** | 350 MB |
| upm 1.3.1 | 44 MB | 256 MB | 344 MB |
| npm 12.1.0 | **31 MB** | 227 MB | **195 MB** |
| pnpm 12.8.1 | 50 MB | 273 MB | 442 MB |
| aube 2.6.1 | 53 MB | 352 MB | 455 MB |

## Running them

See [bench/README.md](../bench/README.md):

```sh
bench/bench.sh                              # every manager, every fixture
bench/bench.sh -r jpm,npm,pnpm,bun -f nuxt
```
