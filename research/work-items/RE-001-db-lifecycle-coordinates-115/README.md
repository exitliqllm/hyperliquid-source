# RE-001: node #115 db_home source-reference coordinate

- Component: `storage`; bounded RE-001 coordinate research, not RE-009 schema recovery.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Repository baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Status: static observation. No component gate or equivalent-byte claim.

## Question and observation

Which native function contains the selected `db/src/db_home.rs:85:13` source
reference? The authenticated ELF contains one selected RIP-relative LEA at VA
`0x4469b64` (file offset `0x4468b64`), bytes `488d15f51d0202`, referring to
Location VA `0x648b960` (file offset `0x6489960`). GNU objdump independently
decodes that instruction at the selected boundary. GNU readelf reports its
unique containing FDE as `[0x44699c0,0x4469bd8)` (536 bytes).

The 24-byte Location has a zero pre-relocation pointer, path length 17, line 85
and column 13. The real RELA entry at file offset `0xbc1a8` has r_offset
`0x648b960`, r_info 8 (`R_X86_64_RELATIVE`) and addend `0x448051`, which maps
to the exact path bytes. Addresses are linked ELF virtual addresses before
runtime load bias; file coordinates are separately recorded in observation.json.
This maps a source diagnostic to an extent; it does not identify its semantics.

## Reproduce

From the repository root, with Python 3, GNU readelf/objdump and the pinned ELF:

```sh
python3 tools/node115_db_home_coordinates.py --output work/db-home-observation.json
python3 -m unittest discover -s tests -p test_node115_db_home_coordinates.py -v
make doctor
make verify catalogue-check
make reproduce
make test
```

The verifier authenticates the full target size and SHA-256 before native tools.
Its exact commands and observed binutils versions are in observation.json;
environment.json records the generating environment. The native output is
restricted to the selected extent; readelf frame output is consumed internally,
not included as a full dump. No captured program, network service or imported
reference source is executed. The verifier and tests are independently authored.
No inferred can1357 source is copied.

## Controls and measured result

The implementation scoped run passed 15/15 tests in 5.396 seconds, with no skips
(complete output in SCOPED-TESTS.txt). Two target-grounded tests bind the real
native reference, FDE and relocation-backed Location. Ten operand controls
mutate the opcode, displacement, relocation offset/type/addend, Location
pointer/length/line/column and source bytes. Three further controls reject a
truncated ELF, wrong-sized target and same-size wrong digest. The latter two
also require rejection before native tools. Counterfactual operand tests use
identity-free recover(); the public analyse() always authenticates the capture.
These are sensitivity tests, not execution or equivalence comparisons.
Required independent validation and the global suite are still outstanding;
the scoped result is not a claim that repository-wide checks pass.

## Overlap and limits

Exact active PR #2085 at `cf043c74ac019e398114181de7d5a6c85be1eabc`
records four different FDEs: `[0x44681e0,0x4468b62)`,
`[0x15028f0,0x1502b78)`, `[0x1500a60,0x1500b83)`,
`[0x1500d20,0x1500e43)`, with different db_home source lines.
PR #2091 at `88acf29436b9e373235decae3eccfc60e6efa0b4` selects
db_hub FDE `[0x1692ca0,0x1692fe9)`. PR #2130 at
`85574058549d9d37eeec6b83d4815bd20cd13fe5` concerns EVM post-frame state.
These documentary comparisons do not reproduce those authors' semantics/tests
or prove absence of every possible overlapping packet.

Only one selected source reference and one containing FDE are validated (1/1);
there is no complete-function-map denominator. Source-path naming does not
establish database lifecycle behavior, schema, replay, call/data closure,
all references, function equivalence or runtime behavior. No Rust node or
component implementation is supplied; all gates remain false and no new
matched bytes are claimed. Next question: which caller reaches this extent,
and does its distinct source evidence justify a separately scoped analysis?
