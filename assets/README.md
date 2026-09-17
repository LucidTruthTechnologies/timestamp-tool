# Assets

Binary sources inlined into `dist/index.html` at build time as `data:` URIs. They are files
here rather than base64 blobs pasted into the HTML so that the repository holds one readable
copy of each, and `build.sh` is the only thing that ever encodes them.

| File | Use |
|---|---|
| `ltt-logo-light.png` | Lucid Truth Technologies® mark, colored, shown on a light background |
| `ltt-logo-dark.png` | the same mark in white, shown under `prefers-color-scheme: dark` |

Both are the canonical site logos, copied from `LucidTruthTechnologies.com`
(`LTT_Main-Logo_Colored_R.png` and `LTT_Main-Logo_White_R.png`), 1024x182.

**They are embedded, never linked.** An `<img src="https://lucidtruthtechnologies.com/...">`
would make the page fetch a third-party resource on load, which would break the guarantee that
the page is self-contained and would be refused by the external-resource check at the bottom
of `build.sh`. PNG rather than the smaller WebP siblings: the difference is about 3 KB and a
PNG will still decode in any browser that exists later.
