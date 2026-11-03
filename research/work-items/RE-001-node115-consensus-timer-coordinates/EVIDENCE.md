# RE-001: one node #115 consensus timer source coordinate

- Component: consensus; bounded supporting RE-001 static coordinate research.
- Target: Linux x86-64 hl-node #115, 105896032 bytes.
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Claim: observed Location/native reference/unwind extent, not recovered timeout behavior.
- Included: one source Location and one native reference in one FDE-described extent.
- Excluded: timer semantics, quorum, round transitions, helper closure, node #94 and visor.

## Reproduce

From repository root, Python 3.11.11 and GNU binutils 2.40 on Linux:

```sh
python3 research/work-items/RE-001-node115-consensus-timer-coordinates/proof.py
python3 -W error::ResourceWarning tests/test_node115_consensus_timer_coordinates.py -v
objdump -d --start-address=0x4eca5d0 --stop-address=0x4eca82c artifacts/node/115/hl-node
```

The proof reparses ELF PT_LOAD/RELA and .eh_frame CIE/FDE data, then streams
`readelf --debug-dump=frames` and runs the bounded objdump command. It reads
only the captured target; no target execution, emulation, network, installation
or chain operation. Python standard library and installed readelf/objdump only.
The FDE decoder deliberately accepts this target's pcrel/sdata4 profile, not an
arbitrary ELF/DWARF implementation. No imported inferred source was used.

## Evidence

Unrebased ELF virtual addresses; file offsets are recorded in proof.json.
The symbol-zero R_X86_64_RELATIVE relocation at file offset 0xd2198
connects Location 0x649dcf8 to the exact source-path bytes
`node/src/consensus/timer.rs`, line17, column30. LEA 0x4eca743, bytes
`488d0dae355d01`, resolves to that Location. GNU disassembly beginning
at the FDE start confirms the instruction boundary rather than accepting a
raw substring scan. The unique containing FDE is [0x4eca5d0,0x4eca82c),
604 bytes. Its raw code SHA-256 is `8ed46d0d802b46b9527c8352615507f1b0285aaa2e8ba43848d7cdfe1d4d3305`.
An FDE extent does not prove an original source-function boundary or name.
The selected native excerpt is retained; other instructions and calls are not
semantically interpreted. The Location can be an inlined diagnostic, not proof
that the complete containing extent implements timer.rs alone.

## Implementation and comparison

Independently authored fixed-coordinate proof, not a reconstructed Rust path.
No compiler equivalence, source/target normalization or helper closure claimed.
The initial bounded search found two timer Locations; only17:30 is selected.
The other record and its references are not part of this result. No module-wide
coverage denominator is asserted. This packet validates 1/1 selected Location,
reference and containing FDE, not all source references or consensus functions.
Tests exercise actual target bytes plus deliberately corrupt copies of path,
Location fields, relocation type/addend/presence/uniqueness, opcode/displacement,
FDE range/CIE link and target identity; native-output controls remove or shift
the reference boundary. Corrupt copies are never executed or written as targets.

## Results and limitations

Scoped command passed; exact test count and names are in SCOPED-TESTS.txt.
The earlier13-test run passed but exposed an unclosed readelf pipe and a weak
identity control. Both were fixed; final run treats ResourceWarning as error.
No independent validation or project-wide checks have run for this tree yet.
Do not interpret scoped tooling success as target behavioral equivalence.
No component/progress gates changed or requested. All existing gates remain as-is.
Focused open-PR checks and bounded integrated evidence search found no same
selected-coordinate result; this is not exhaustive semantic novelty proof.
Next question: independently bind the caller and timer-input domains before
attempting any timeout or round-transition semantics.

Root MIT applies to new checker/tests/research; captured native excerpts retain
upstream rights and are not offered as reconstructed or relicensed source.

## File identities before independent validation

- `research/work-items/RE-001-node115-consensus-timer-coordinates/proof.py`: `dbd283175058ceb0442bc6f4e7d334474dde2df94dfd26d5d980a75643555e7b`
- `research/work-items/RE-001-node115-consensus-timer-coordinates/proof.json`: `0bc24721ebba513280e1956683e8e83862b477eaeb80b8c3e9a3f2be03379463`
- `research/work-items/RE-001-node115-consensus-timer-coordinates/selected.objdump.txt`: `328833a6d7ecc1cb2edc0763c20ca8d6810589e07aacb51160c1f5198ae26be1`
- `research/work-items/RE-001-node115-consensus-timer-coordinates/SCOPED-TESTS.txt`: `246dc67b58577b912b5e560f17f7ba625a1958b11512aaf29ccbefc4396707a9`
- `tests/test_node115_consensus_timer_coordinates.py`: `a2d465f7b67d3b704ed8a0663833b8722f36345c0c8e7f510a61033d932f9090`
