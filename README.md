# phishing-url-detector

Scores a URL from the string alone. No page fetch.

The host is split into a guessed registered domain (last two labels) and the labels to the left of it. A brand word in those left labels is treated as a lookalike. Other signals are length, digit ratio, an IP host, punycode, and a short token list.

`data/sample_urls.csv` is fake. The metrics from it are a smoke test.

## Run

Mark `src` as a source root, working directory at the repo root.

    pip install -r requirements.txt
    pytest tests
    python src/score_url.py "http://paypal.com.secure-login.example/verify"
    python src/train.py --data data/sample_urls.csv

## Limits

The registered-domain cut is wrong when the public suffix is more than one label (`co.uk`, `github.io`). The split is random, so it can leak a campaign into both sides. Benign and phishing labels are not from a published dataset yet.