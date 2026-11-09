# RE-015: one node115 literal-prefix consumer

## Question and target

Which instruction consumes the entry containing the previously inventoried `hl-node` token at VA `0x440f36`? Component: constants; bounded static RE-015 research, no gate change. Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Sole target: `artifacts/node/115/hl-node`, 105896032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses below are linked ELF VAs before load bias.

## Observation

The instruction at VA `0x15a230b` / file offset `0x15a130b` is `488d351eece9fe`, an RSI RIP-relative LEA. Independent signed-displacement decoding resolves it to VA/file offset `0x440f30`, six bytes before the inventoried token. The 13 selected entry bytes are `c0012fc0082f686c2d6e6f6465`; they are not simply the seven-byte token as an ASCII argument.

GNU readelf 2.40 reports FDE section offset `0x3ae32c`, CIE `0x39672c`, actual interval `[0x15a20a0,0x15a37fe)`. GNU objdump 2.40 decoded continuously from that FDE start; the sole retained selected excerpt is 221 bytes at `[0x15a22cb,0x15a23a8)`. Every retained instruction byte was checked independently through its ELF PT_LOAD mapping. Decoding from the FDE start is an instruction alignment control, not a complete control-flow or equivalence proof.

The selected entry address is passed in RSI alongside RDI=`rsp+0x150` and RDX=`rsp+0x210` to the indirect call at `0x15a2322`. Independent call-displacement decoding names slot `0x64df6e8`. Its actual R_X86_64_RELATIVE writer (type 8, symbol 0) at file `0x135048` has addend `0x141e3a0`. The nearby callback slot `0x64e0a98` has writer at file `0x138810` and addend `0x1689420`. No target call was executed.

This establishes a selected native prefix-entry consumer and boundary, not the encoded entry grammar, default path, formatter implementation, release-wide xref census, source ownership or runtime reachability. In particular, no trailing zero is treated as an authoritative entry boundary.

## Originality and overlap

The integrated RE-015-node115-literal-inventory explicitly leaves instruction consumers open and records no xref. The other inventoried token at `0x605ccd` was excluded because RE-005-node115-key-consumers already covers it. The selected FDE occurs in three generic indirect-call caller lists at later call sites; those do not supply this selected prefix entry or LEA. Private triage found only the three generic caller lists described above; it is not a release-wide semantic-overlap proof. One current open-PR literal query `15a20a0` returned zero at 2026-11-07T05:08:24Z; that is not a complete semantic-overlap check. Exact open PR #3975 at head `542d2a4fd9f2d8882e103b053a1dd39ca0c89cd2` describes the RPC format interpreter at `0x1680594` and implicit callback order, not this selected caller/entry xref. Its interpreter semantics are excluded. Additional literal `15a23` and `440f` open-PR queries returned zero on 2026-11-07; query absence is not a complete semantic-overlap proof. Trusted publication clearance remains required. No inferred can1357 source was copied; new scripts are independently authored. Captured excerpts retain upstream rights.

## Local reproduction and controls

From the repository root, run `python3 research/work-items/RE-015-literal-prefix-consumer-115/verify_consumer.py` and `python3 tests/test_literal_prefix_consumer_115.py`. GNU readelf 2.40 is required; Python uses only its standard library. verify_consumer.py authenticates the complete target, derives VA/file translations, LEA and call destinations, actual RELA records and the containing GNU readelf FDE. Its saved output is verified-consumer.json. `tests/test_literal_prefix_consumer_115.py` rederives on the real target and tests authentic records plus per-field saved-record mutations; these are comparator controls, not native target-byte corruption experiments. The retained LOCAL-PROOF.json records the final-layout verifier exiting 0 and 2 tests passing in 3.420 seconds; its hashes identify that local-proof snapshot, not subsequent documentation edits. No captured code, network, signing or chain actions were used.


## Implementation and comparison

Independently authored static Python proof only; no Rust equivalent, byte transplantation, normalization masks or runtime comparison. The input is the pinned target above; the saved output and selected excerpt are retained beside this record. Two scoped tests compare the authentic record and reject per-field record mutations; passing them does not establish executable equivalence. No completed component gate is requested.

## Related callee evidence and open question

The same base already contains RE-012-generated-name-115, RE-012-temp-path-factory-115 and RE-012-path-error-handler-115 for callee 0x141e3a0 and RE-015-node115-out-buffer-owner for additional discussion of the same format consumer. None of those attribution excerpts establishes semantics for callback target `0x1689420`, which remains an unnamed coordinate here. These are prior evidence, not new callee implementations or justification for an inferred path/default. The new claim is restricted to the selected caller's prefix-entry LEA, indirect-call slot and containing FDE. Next question: does the full native caller assign an application-level meaning to this encoded prefix? That is not established here.

## Validation status

Local proof only; full required checks, trusted publication clearance, useful progress push and independent validation remain pending. Nothing here claims hosted CI, accepted contribution or payment.
