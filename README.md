# CLSID WebFinder

A small, dependency-free website for finding the decoder CLSID in **CLVSD.ax**. It also inspects compatible PE32 / PE32+ DirectShow AX and DLL files.

All analysis happens locally in the browser. Selected files are never uploaded, executed, registered, or modified. **The limit is 4 MiB (4,194,304 bytes), inclusive.** Larger files are rejected before their contents are read, with a second size check inside the parser.

## Use

Open the website, then choose or drop a file. The page shows the most likely decoder CLSID, class-factory candidates, PE information, SHA-256, and weaker GUID clues. Copy the primary CLSID or export a JSON report.

Files renamed to extensions such as `.ax1` or `.ax123` can also be selected. Validation uses the PE contents rather than the filename.

The site uses only relative asset paths, so it works at a GitHub Pages project URL such as `https://OWNER.github.io/CLSID-WebFinder/`. No backend or external libraries are required. The three site files also work when opened locally in a modern browser; clipboard and SHA-256 availability depend on browser permissions and secure-context support.

## GitHub Pages deployment

1. In the GitHub repository, open **Settings → Pages → Build and deployment → Source** and select **GitHub Actions**.
2. Push this repository to the `main` branch. The **Test and deploy Pages** workflow runs tests, builds the static site, and deploys it. You can also run the workflow manually from **Actions**.
3. Open the deployment URL shown in the workflow or **Settings → Pages**.

Pull requests run tests and build the site without deploying. The Pages artifact contains only `index.html`, `scanner.js`, `app.js`, and `.nojekyll`; no AX binaries or local analysis records are included.

## Identification and limitations

The parser checks PE headers, sections, named exports, and DirectShow [`CFactoryTemplate`](https://learn.microsoft.com/en-us/windows/win32/directshow/cfactorytemplate) structures. It validates the class-name, CLSID, creation-function, initialization-function, and optional filter-setup pointers. A unique class whose name contains `Decoder` is shown as the primary candidate; property pages are listed separately. GUID fields use the Windows COM little-endian layout.

Known CLVSD decoder classes:

| Variant | CLSID |
| --- | --- |
| Legacy CyberLink Video/SP Decoder | `{8ACD52ED-9C2D-4008-9129-DCE955D86065}` |
| CyberLink Video/SP Decoder (PDVD8) | `{37991D68-42A3-40E3-8C05-037170E1A42A}` |

Unknown structural matches remain candidates. Binary or text GUID occurrences are only clues, since an IID or unrelated GUID is not necessarily a CLSID. Packed binaries, runtime-generated GUIDs, and non-standard class factories may not be recognized. The website does not call `DllGetClassObject` or prove COM activation, dependencies, or video playback.

If no factory table is readable, a non-forwarded `DllGetClassObject` export exists, and exactly one known decoder GUID occurs as bytes, the page displays **Known decoder GUID clue · factory unverified**, with a **Copy GUID clue** button. The JSON `primary` field stays `null`; `knownDecoderClue` carries the weaker evidence. For example, the inspected protected 8.2.630 variants expose named COM exports and contain the PDVD8 GUID, but their factory names and pointers are not readable on disk. This result does not establish that the exported factory accepts that CLSID. Missing section names can produce a packing/protection warning; that warning alone is not proof of a packer.

## Development

Use Node.js 22 or newer; there are no npm dependencies to install.

```sh
npm test
npm run build
```

Serve `_site/` with any static HTTP server, or open `index.html` directly for a quick local preview. `scanner.js` contains the reusable parser; `app.js` handles the interface. Tests construct synthetic PE32 / PE32+ files, including an image base above JavaScript's safe-integer range, and check invalid input, pointer mapping, weak clues, exact size boundaries, and rejection before reading.

Real CLVSD binaries are not distributed here. Optional sample checks can be enabled with `CLVSD_V4_AX` and `CLVSD_V7_AX` environment variables pointing to local samples. These checks require the known sample hashes and verify both decoder and property-page classes.

`CLVSD_PROTECTED_AX` and `CLVSD_PROTECTED_DLL` optionally test the inspected 8.2.630 variants (SHA-256 `1393dbaa1c1b21d5f383d542cf90ae1ef93d19a525c2cf0ae3b4ab9a0ff20e1e` and `c540b83a53cea20dd9374b8aff4ee7408da62504f600670b2fb0a79ecfbc52a0`). They verify that the PDVD8 GUID at file offset `0xACD48` stays a clue and does not become a factory match.

Licensed under the [Unlicense](LICENSE).
