# Third-party notices

jpm is MIT licensed (see [LICENSE](LICENSE)). It builds on the work below, whose notices are
kept here as their licenses ask. The full texts of those licenses follow the list.

## Code jpm is derived from

| Work | License | Copyright | Where |
| --- | --- | --- | --- |
| [upm](https://github.com/unjs/upm) | MIT | Copyright (c) Pooya Parsa <pooya@pi0.io> | jpm started as a Rust port of upm; the bench harness and its fixtures came with it |
| [BearSSL](https://www.bearssl.org/) | MIT | Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> | `crates/crypto/src/aead/soft.rs`: bitsliced AES after `aes_ct64`, GHASH after `ghash_ctmul64` |
| [cmd-shim](https://github.com/npm/cmd-shim) | ISC | Copyright (c) npm, Inc. and Contributors | `src/shim.rs`: Windows bin shims in the form cmd-shim writes them |

## Built into jpm's binaries

Where a crate offers MIT or Apache-2.0, jpm takes it under MIT.

| Crate | License | Copyright |
| --- | --- | --- |
| [flate2](https://github.com/rust-lang/flate2-rs) | MIT | Copyright (c) 2014-2026 Alex Crichton |
| [zlib-rs](https://github.com/trifectatechfoundation/zlib-rs) | Zlib | (C) 2024 Trifecta Tech Foundation |
| [rustls-pki-types](https://github.com/rustls/pki-types) | MIT | Copyright (c) 2023 Dirkjan Ochtman <dirkjan@ochtman.nl> |
| [webpki-roots](https://github.com/rustls/webpki-roots) | CDLA-Permissive-2.0 | Mozilla's root certificate list, as the CCADB publishes it |
| [junction](https://github.com/tesuji/junction) (Windows) | MIT | Copyright (c) Lzu Tao <taolzu@gmail.com> |
| [scopeguard](https://github.com/bluss/scopeguard) (Windows) | MIT | Copyright (c) 2016-2019 Ulrik Sverdrup "bluss" and scopeguard developers |
| [windows-sys](https://github.com/microsoft/windows-rs), [windows-link](https://github.com/microsoft/windows-rs) (Windows) | MIT | Copyright (c) Microsoft Corporation |

## Data jpm uses

| Data | License | Copyright | Where |
| --- | --- | --- | --- |
| [Node.js release keys](https://github.com/nodejs/release-keys) | MIT | Copyright 2019 Devin Canterberry | `src/pgp.rs` keeps the keys' fingerprints; the keys are fetched from that repository |

## Test data in this repository

These are in the source repository only, never in jpm's binaries.

| Data | License | Copyright | Where |
| --- | --- | --- | --- |
| [Project Wycheproof](https://github.com/C2SP/wycheproof) test vectors | Apache-2.0 | Copyright 2016 Google Inc. | `crates/crypto/tests/data`, `crates/pk/tests/data` (stored gzipped; the license is beside them as `WYCHEPROOF-LICENSE`) |
| RFC test vectors (RFC 7748, 8032, 8439, 7541 and others) | IETF Trust | Copyright (c) the IETF Trust and the persons identified as the documents' authors | the crypto and HTTP crates' tests, where each names its RFC |
| [node-semver](https://github.com/npm/node-semver) test tables | ISC | Copyright (c) Isaac Z. Schlueter and Contributors | `tests/conformance/semver` (generated from them; the license is beside them) |
| [npm-package-arg](https://github.com/npm/npm-package-arg) test cases | ISC | Copyright (c) npm, Inc. | `tests/conformance/npm-package-arg` (generated from them; the license is beside them) |
| [hosted-git-info](https://github.com/npm/hosted-git-info) test cases | ISC | Copyright (c) 2015, Rebecca Turner | `tests/conformance/hosted-git-info` (generated from them; the license is beside them) |
| [@npmcli/arborist](https://github.com/npm/cli/tree/latest/workspaces/arborist) fixture lockfiles | ISC | Copyright npm, Inc. | `tests/conformance/arborist` (the license is beside them) |
| [Bun](https://github.com/oven-sh/bun) install tests and lockfiles | MIT | Copyright (c) Oven and Bun contributors | `tests/conformance/bun` (the license is beside them) and `tests/bun.rs` (scenarios re-created from bun's tests) |
| [pnpm registry-mock](https://github.com/pnpm/registry-mock) packages and pnpm's install outcomes | MIT | Copyright (c) 2017-2026 pnpm | `tests/conformance/pnpm-registry-mock` (the license is beside them) |
| [Yarn berry](https://github.com/yarnpkg/berry) acceptance scenarios | BSD-2-Clause | Copyright (c) 2016-present, Yarn Contributors | `tests/berry.rs` (scenarios and fixture manifests re-created from `packages/acceptance-tests`; the license is below) |

---

## License texts

### MIT License

Applies to upm, BearSSL, flate2, rustls-pki-types, junction, scopeguard, windows-sys,
windows-link, the Node.js release keys, Bun's tests and pnpm's registry-mock, each with its copyright line above.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### ISC License (cmd-shim)

The same terms cover node-semver, npm-package-arg, hosted-git-info and @npmcli/arborist, each under its own
copyright line above; their full license files are beside their test data.

```
The ISC License

Copyright (c) npm, Inc. and Contributors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### BSD 2-Clause License (Yarn berry)

```
BSD 2-Clause License

Copyright (c) 2016-present, Yarn Contributors.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### zlib License (zlib-rs)

```
(C) 2024 Trifecta Tech Foundation

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.

3. This notice may not be removed or altered from any source distribution.
```

### Community Data License Agreement - Permissive - Version 2.0 (webpki-roots)

```
This is the Community Data License Agreement - Permissive, Version
2.0 (the "agreement"). Data Provider(s) and Data Recipient(s) agree
as follows:

## 1. Provision of the Data

1.1. A Data Recipient may use, modify, and share the Data made
available by Data Provider(s) under this agreement if that Data
Recipient follows the terms of this agreement.

1.2. This agreement does not impose any restriction on a Data
Recipient's use, modification, or sharing of any portions of the
Data that are in the public domain or that may be used, modified,
or shared under any other legal exception or limitation.

## 2. Conditions for Sharing Data

2.1. A Data Recipient may share Data, with or without modifications, so
long as the Data Recipient makes available the text of this agreement
with the shared Data.

## 3. No Restrictions on Results

3.1. This agreement does not impose any restriction or obligations
with respect to the use, modification, or sharing of Results.

## 4. No Warranty; Limitation of Liability

4.1. All Data Recipients receive the Data subject to the following
terms:

THE DATA IS PROVIDED ON AN "AS IS" BASIS, WITHOUT REPRESENTATIONS,
WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED
INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE,
NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

NO DATA PROVIDER SHALL HAVE ANY LIABILITY FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING
WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE DATA OR RESULTS,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

## 5. Definitions

5.1. "Data" means the material received by a Data Recipient under
this agreement.

5.2. "Data Provider" means any person who is the source of Data
provided under this agreement and in reliance on a Data Recipient's
agreement to its terms.

5.3. "Data Recipient" means any person who receives Data directly
or indirectly from a Data Provider and agrees to the terms of this
agreement.

5.4. "Results" means any outcome obtained by computational analysis
of Data, including for example machine learning models and models'
insights.
```

### Apache License, Version 2.0 (Project Wycheproof test vectors)

The full text is kept beside the vectors, in `crates/crypto/tests/data/WYCHEPROOF-LICENSE` and
`crates/pk/tests/data/WYCHEPROOF-LICENSE`, and at https://www.apache.org/licenses/LICENSE-2.0.
