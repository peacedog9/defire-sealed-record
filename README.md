# DeFIRE Sealed Record witness

This public repository is the independent, append-only witness for DeFIRE's sealed signal history. The pipelines box copies only two public hash indexes here and pushes each change before the same bytes are published on DeFIRE's site.

- `daily-index.json` records each complete UTC batch, its signal count, issuance range, payload hash, reveal state, and Bitcoin proof state.
- `issuance-index.json` records the gap-free at-signal hash chain and external signed-time receipts.
- Neither file may contain a ticker, price, stop, thesis, source ID, or any other signal plaintext. The publisher rejects any unapproved field before committing.

GitHub's commit history gives the indexes an independent public retention point. A conflicting history cannot replace the first one without leaving a visible rewrite outside DeFIRE's servers.

## Check the live bytes

```bash
work="$(mktemp -d)" && \
curl -fsSL https://raw.githubusercontent.com/peacedog9/defire-sealed-record/main/daily-index.json -o "$work/github.json" && \
curl -fsSL https://decentralizedfire.com/wp-content/uploads/tools/sealed-record/index.json -o "$work/live.json" && \
cmp "$work/github.json" "$work/live.json" && echo "MATCH: GitHub witness equals DeFIRE live index"
```

For full pick verification after the 7-day reveal, use the paste-ready command on [the live Sealed Record page](https://decentralizedfire.com/sealed-record/). It checks the complete count, every revealed field, DigiCert's signed UTC receipt, and the OpenTimestamps Bitcoin proof.

## Independent fresh-machine check

The public [verification workflow](https://github.com/peacedog9/defire-sealed-record/actions/workflows/verify-latest-reveal.yml) runs on a new GitHub-hosted Ubuntu runner whenever either hash index changes, once daily, and on manual request. It first requires the commit-pinned GitHub index to byte-match DeFIRE's live index. Once a nonempty batch reveals, it runs the public verifier below 120 seconds and then alters one downloaded entry and requires a loud tamper failure.

The repository and workflow commit no signal plaintext. Revealed files exist only in the runner's temporary directory and are deleted with the runner.
