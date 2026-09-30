# hosted-git-info conformance cases

The `*.json` files here are derived from the test suite of
[hosted-git-info](https://github.com/npm/hosted-git-info), npm's reader of hosted git
urls, at commit `8c3bebb5e42142b7bce06b085b4c1bd1adba7371` (version 10.1.1). hosted-git-info
is licensed under the ISC license, `Copyright (c) 2015, Rebecca Turner`; its full text is in
[LICENSE](LICENSE).

They are generated, not written by hand:

    git clone https://github.com/npm/hosted-git-info
    git -C hosted-git-info checkout 8c3bebb5e42142b7bce06b085b4c1bd1adba7371
    node tests/conformance/gen/hosted-git-info.mjs hosted-git-info

Each file holds the inputs of one of hosted-git-info's `test/<host>.js` files (its `valid` and
`invalid` tables and every other url its tests read), with what hosted-git-info at that commit
reads from each: `null` for no hosted repository, else the host, user, project, ref, auth and
the urls it derives. `test/file.js`, `test/localhost.js` and `test/parse-url.js` are not read:
they test `fromManifest`, a host added at run time and `parseUrl`'s internals.

`tests/conformance/hosted_git_info.rs` checks jpm against them, with the differences jpm keeps
and why.
