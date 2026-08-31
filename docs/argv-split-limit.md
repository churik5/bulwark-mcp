# I tried to patch a blind spot in my own MCP tool. The patch and a false-positive bug cancel out.

I maintain [bulwark-mcp](https://github.com/churik5/bulwark-mcp), a local proxy that sits between an MCP client (Claude Desktop, Cursor) and the servers it talks to, and screens the traffic for dangerous patterns. A few weeks ago I wrote about [a class of prompt injection it can't catch](https://dev.to/churik5/i-tried-to-break-my-own-mcp-prompt-injection-detector-one-class-of-attack-walks-straight-through--4534). This is a companion finding from the layer that inspects tool *calls* rather than tool *results*, and it lands somewhere sharper: the fix for the gap is itself a second bug, and the two are the same line of code pulling in opposite directions.

## Seeing both at once

One job the proxy takes on is refusing dangerous tool *calls* before they reach a server — a hijacked or confused agent trying to invoke a shell tool with `rm -rf /`. These are client→server checks (the rule pack is scoped `apply_to: [client_to_server]`), and they work on the direct form.

I'll run the rule engine directly against two full JSON-RPC `tools/call` frames — the same `rm -rf /`, encoded two ways — and print both the score and, more importantly, the exact text the rule actually gets to look at:

```
$ uv run python -c '
from bulwark_mcp.detectors.rules import RulesEngine, _extract_arguments_text
import json
eng = RulesEngine.from_directory("src/bulwark_mcp/rules/builtin")

flat  = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell","arguments":{"argv":["rm","-rf","/"]}}})
split = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell","arguments":{"cmd":"rm","args":["-rf","/"]}}})

print("flat  extracted:", repr(_extract_arguments_text(flat)))
print("split extracted:", repr(_extract_arguments_text(split)))
r1 = eng.detect(flat,  direction="client_to_server")
r2 = eng.detect(split, direction="client_to_server")
print("flat :", r1.score, list(r1.hits))
print("split:", r2.score, list(r2.hits))
'
flat  extracted: 'rm -rf /'
split extracted: '-rf /'
flat : 0.95 ['shell.rm_rf_root_or_home']
split: 0.0 []
```

Two rows. The first frame — everything in one `argv` array — is assembled into `rm -rf /`, the rule `shell.rm_rf_root_or_home` matches, score 0.95. Blocked, correctly. The second frame is the *same command*: score 0.0, no hits, allowed through. The two middle lines are the whole story.

## Why `rm` disappears

The rule matches text, so something first has to turn a JSON argument object into a string. That extractor pulls strings out of *arrays* and joins them. In the first frame everything lived in one array, so it got `rm -rf /`. In the second, `"cmd": "rm"` is a scalar value, not an array element — so the extractor drops it. What reaches the regex is `-rf /`: the flags, with no command in front of them. The pattern looks for `rm` followed by `-rf`, sees `-rf /`, and correctly reports no match.

So the split form isn't slipping past a weak pattern. The pattern is working perfectly on the text it was handed. The text is just missing the word that made it dangerous.

## Why the fix is a second bug

The obvious fix: have the extractor collect scalar values too, not only array elements. Then `{"cmd":"rm","args":["-rf","/"]}` assembles into `rm -rf /` and the rule fires.

Here is what that breaks. Once the extractor concatenates scalar values from across an argument object, a *legitimate* call like

```json
{"keep": ["rm"], "flags": ["-rf", "/"]}
```

— an ordinary tool with a `keep` list and a `flags` list, nothing to do with shells — assembles into the phantom string `rm -rf /` and trips the very same rule. A false positive on a harmless call.

So the two requirements are one dial:

- To catch the separated command form, the extractor **must** join values across keys.
- To avoid false positives on legitimate multi-field calls, it **must not** join values across keys.

Catch the attack and you manufacture false positives; suppress the false positives and the attack walks through. No setting does both, because "malicious command spread across fields" and "innocent data spread across fields" produce the *identical* assembled string. The extractor is array-only on purpose — the separated form is left uncaught as the deliberate price of not firing on innocent calls.

This isn't a regex I haven't written yet. It's a regex that can't exist.

## The lesson underneath it

Argument inspection can't be the trust boundary for *"is this tool call dangerous,"* for the same reason content inspection can't be the boundary for *"is this text an instruction"* — the subject of the last post. The danger isn't in the surface form of the arguments; it's in what the tool *does* when it runs. And a single action has unbounded encodings: flat array, scalar-plus-array, nested, renamed keys, base64'd values — whatever the schema allows. You can't enumerate them any more than you can enumerate the phrasings of "ignore all previous instructions." Both are open sets, and the attacker gets to pick from them second.

## What actually holds

The control without this problem ignores the arguments entirely. bulwark's capability allowlist matches on the tool *name*: pin a workflow to `filesystem.read` and `github.create_issue`, and a call to `shell` is refused — not because its arguments looked bad, but because `shell` isn't on the list at all. Every encoding of `rm -rf /` dies at the same gate, because the gate never reads the arguments. The question changed from *"are these arguments dangerous?"* (unbounded, unanswerable) to *"is this tool allowed here?"* (finite, and mine to define).

I want to be precise about the limits. The allowlist is coarse — exact name match, no argument awareness. It's off until you configure it. And it only helps when the dangerous call is to a tool that shouldn't be reachable in the first place; if the tool is already allowed and an injection abuses it, the allowlist does nothing. It shrinks what a hijack can reach; it does not inspect what it does. Like everything here, it's one layer, defeatable on its own.

## It's a failing test, not a footnote

I didn't patch the extractor, because the patch *is* the false-positive bug. Instead both halves are pinned as an executable spec — `TestArgvShellDetectionLimits` in `tests/test_detectors_rules.py`: three separated-command forms asserted as *uncaught by design*, and the direct array form asserted as still caught. The day someone finds an extractor that catches the separated form without manufacturing phantom matches on innocent calls, those tests go red — and red would mean the contradiction I think is real turned out not to be. I would be glad to be wrong.

bulwark-mcp is AGPL-3.0, Python, runs entirely locally, and sends nothing anywhere by default. It's firmly v0.x, and the detector ships off by default — on purpose. If you've got a tool-call shape the rules miss, or — better — an argument-level control that doesn't trade catch-rate for false positives, opening an issue is the single most useful thing you could do. Repo and the test above: https://github.com/churik5/bulwark-mcp
