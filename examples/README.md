# signbooth examples

Three small scripts covering the three roles in a signbooth deployment.
They are self-contained: run them in order from this directory and they
build the binary and stand up a throwaway booth under `/tmp/signbooth-demo`
(recreated on each run; `rm -rf /tmp/signbooth-demo` removes every trace).

| Script | Role | What it shows |
| --- | --- | --- |
| `booth-setup.sh` | operator | one-time init: key, caller policy, daemon |
| `ci-sign.sh` | CI job | hash + sign an artifact with a scoped token |
| `verify-artifact.sh` | consumer | offline verification against a pinned key |

```bash
bash booth-setup.sh     # prints the caller token and starts a daemon
SIGNBOOTH_TOKEN=sbt_… bash ci-sign.sh
bash verify-artifact.sh
```

The operator script is the only one that ever touches the booth home; the
CI script holds nothing but a token, and the consumer script needs only
the artifact, its `.sbsig` envelope, and the public key you published.
