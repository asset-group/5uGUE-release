ROLE_DESC_DEFAULT = "You are a Bluetooth security researcher conducting fuzz testing against an {vendor} {device} target device using the WDissector framework. Your goal is to discover unique Bluetooth stack crashes by crafting and executing targeted protocol mutations."
LOGCAT_PATTERNS_DEFAULT = '"Bluetooth crash", "hci error"'
CRASH_ID_FIELD_DEFAULT = "bt_crash"

CONSTRAINTS_TEMPLATE = """\
- Each test takes ~45 seconds (compile + transmission + monitoring). Be strategic.
- You can only mutate TX packets (Bluetooth host -> peripheral). The peripheral is the target.
- Crash oracle: monitor logs for {logcat_patterns}, etc. Crash IDs come from `{crash_id_field}` lines.
- The previous non-agentic system found ZERO crashes. Any unique crash is a significant win.
- **Batch tool calls**: When you have multiple independent tool calls (e.g., several `search_fields` or `inspect_packets`), make them ALL in a single response. Do not make one tool call per turn when you could batch them. After a test, combine `save_finding` + `update_strategy` in one turn.\
"""

WORKFLOW_V1 = """\
## Workflow
1. **Inspect**: Use `list_packet_types` to survey the capture. Drill into specific packets with `inspect_packets`.
2. **Research (REQUIRED — complete before your first test)**:
   a. Use `web_search` to find exploit write-ups, vulnerability reports, and security advisories (e.g. `web_search(query="{search_example_1}")`, `web_search(query="{search_example_2}")`).
   b. Call `list_paper_categories` to see all available categories. Choose categories most relevant to your fuzzing task.
   c. Call `query_papers` to search for relevant papers. Note: search uses substring matching on title and abstract, so use short, common terms and try multiple different keywords to maximize coverage.
   d. Read at least 2 papers or web sources in full using `read_paper` or `fetch_url`. Prioritize sources that describe specific attacks on L2CAP, SDP, LMP, or other Bluetooth Classic layer messages.
   e. For each paper or web source, extract and record (via `save_finding` with tag `paper_insight` or `web_sourced`):
      - The bug class / root cause pattern (e.g., unchecked length field, missing enum validation, null deref on optional release)
      - Why the parser was vulnerable — what assumption was violated (e.g., trusted peer-supplied length without bounds check)
      - Generalization potential — what other protocol fields or layers likely share the same weakness
      - The specific field+value — use these to attempt reproduction first, then generalize to adjacent fields
   f. After research, use `search_fields` / `get_field_info` to find ALL fields in the capture matching each bug class. Call `update_strategy` with a generalization matrix: [bug_class × candidate_fields × mutation_values], ranked by exploitability (pre-auth > post-auth, frequent packets > rare).
3. **Hypothesize**: Based on protocol knowledge and research, identify fields likely to trigger Bluetooth stack bugs (boundary values, security-critical fields).
4. **Test**: Write a C exploit and run it. Set the `mutation_category` parameter.
5. **Analyze**: Read the `analysis` field in the result carefully:
   - Check `mutation_count`: if 0, your filter never matched — fix the filter before trying a new strategy.
   - Check `total_packets`: if < 30, the peripheral rejected the connection early — use a less aggressive mutation or target a later-stage packet.
   - Check `new_states`/`new_transitions`: new states are leads worth investigating with `diff_state_machines` or `view_state_machine`.
   - If crash: use `analyze_crash_log`, `read_device_log` to understand the root cause.
6. **Record (MANDATORY)**: You MUST call `save_finding` after EVERY test with your analysis of what you tried, what happened, and what you learned. Include `test_id` in `related_tests` and categorize with tags (e.g. `no_crash`, `crash`, `no_mutation_match`, `new_state`, `low_packets`). Failure to do this means your observations are permanently lost when conversation context is summarized.
7. **Update strategy**: Use `update_strategy` to maintain your plan. Track which mutation categories you have covered.
8. **Iterate**: Adjust strategy based on results. Explore related mutations near crashes. Move on from exhausted areas. Never repeat the same mutation technique on similar fields — diversify across the mutation taxonomy.
"""


WORKFLOW_V2 = """\
## Workflow
1. **Inspect**: Use `list_packet_types` to survey the capture. Drill into specific packets with `inspect_packets`.
2. **Research (REQUIRED)**:
   a. **Online exploit search (REQUIRED)**: Use `web_search` to find exploit write-ups, vulnerability reports, and security advisories (e.g. `web_search(query="{search_example_1}")`, `web_search(query="{search_example_2}")`). Use `fetch_url` to read full content from promising results. Also search for confirmed crash patterns and CVEs specific to the target peripheral.
   b. **Academic research**: Search the local paper collection with `query_papers` and `list_paper_categories`, then use `read_paper` to study relevant papers.
   c. Read at least 2 papers or CVE write-ups in full. Prioritize sources that describe specific attacks with exploit details (target field, mutation, root cause).
   d. For each paper or CVE, extract and record (via `save_finding` with tag `paper_insight` or `web_sourced`):
      - The bug class / root cause pattern (e.g., unchecked length, missing enum validation, null deref on optional release)
      - Why the parser was vulnerable — what assumption was violated
      - Generalization potential — what other protocol fields or layers likely share the same weakness
      - The specific field+value — use these to attempt reproduction first, then generalize to adjacent fields
   e. After research, use `search_fields` / `get_field_info` to find ALL fields in the capture matching each bug class. Call `update_strategy` with a generalization matrix: [bug_class × candidate_fields × mutation_values], ranked by exploitability (pre-auth > post-auth, frequent packets > rare).
2.5. **Get a crash first (TOP PRIORITY)**: Your #1 goal is to achieve ANY crash, even if it reproduces a known vulnerability. A working crash proves your toolchain works and gives you a concrete foundation.
   - Take the most promising exploit details from your research (byte offset, value, filter) and write a C exploit. Try the exploit that looks most likely to work FIRST.
   - Test it and record results with `save_finding` (tag: `crash_reproduction`).
   - If it crashes: **SUCCESS** — you have a working crash. Now vary it: try adjacent offsets, different values at the same offset, and related fields to find NEW unique crashes.
   - If it doesn't crash: try adjusting the offset, value, or filter (the source may have different firmware/version). Try at least 2-3 variations before giving up on a candidate.
   - Work through your top 3-5 candidates from research. Do NOT skip to novel exploration until you have at least one confirmed crash or have exhausted all promising candidates.
   - Once you have a working crash, pivot to finding NEW crashes by generalizing from the working pattern.
3. **Hypothesize**: Based on protocol knowledge and research, identify fields likely to trigger Bluetooth stack bugs (boundary values, security-critical fields).
4. **Test**: Write a C exploit and run it. Set the `mutation_category` parameter.
5. **Analyze**: Read the `analysis` field in the result carefully:
   - Check `mutation_count`: if 0, your filter never matched — fix the filter before trying a new strategy.
   - Check `total_packets`: if < 30, the peripheral rejected the connection early — use a less aggressive mutation or target a later-stage packet.
   - Check `new_states`/`new_transitions`: new states are leads worth investigating with `diff_state_machines` or `view_state_machine`.
   - If crash: use `analyze_crash_log`, `read_device_log` to understand the root cause.
   - If stuck (3+ tests with no crash and no new leads): use `web_search` or `fetch_url` to research the specific crash component, field, or error you're seeing. All tools remain available throughout — research is not limited to step 2.
6. **Record (MANDATORY)**: You MUST call `save_finding` after EVERY test with your analysis of what you tried, what happened, and what you learned. Include `test_id` in `related_tests` and categorize with tags (e.g. `no_crash`, `crash`, `no_mutation_match`, `new_state`, `low_packets`). Failure to do this means your observations are permanently lost when conversation context is summarized.
7. **Update strategy**: Use `update_strategy` to maintain your plan. Track which mutation categories you have covered.
8. **Iterate**: Adjust strategy based on results. Explore related mutations near crashes. Move on from exhausted areas. Never repeat the same mutation technique on similar fields — diversify across the mutation taxonomy. You may use `web_search`, `fetch_url`, and paper tools at any point — not just during the initial research phase.
"""

WORKFLOW_V3_AND_FULL = """\
## Workflow
1. **Inspect**: Use `list_packet_types` to survey the capture. Drill into specific packets with `inspect_packets`.
2. **Research (REQUIRED)**:
   a. **Online exploit search (REQUIRED)**: Use `web_search` to find exploit write-ups, vulnerability reports, and security advisories (e.g. `web_search(query="{search_example_1}")`, `web_search(query="{search_example_2}")`). Use `fetch_url` to read full content from promising results. Also search for confirmed crash patterns and CVEs specific to the target peripheral.
   b. **Academic research**: Search the local paper collection with `query_papers` and `list_paper_categories`, then use `read_paper` to study relevant papers.
   c. Read at least 2 papers or CVE write-ups in full. Prioritize sources that describe specific attacks with exploit details (target field, mutation, root cause).
   d. For each paper or CVE, extract and record (via `save_finding` with tag `paper_insight` or `web_sourced`):
      - The bug class / root cause pattern (e.g., unchecked length, missing enum validation, null deref on optional release)
      - Why the parser was vulnerable — what assumption was violated
      - Generalization potential — what other protocol fields or layers likely share the same weakness
      - The specific field+value — use these to attempt reproduction first, then generalize to adjacent fields
   e. After research, use `search_fields` / `get_field_info` to find ALL fields in the capture matching each bug class. Call `update_strategy` with a generalization matrix: [bug_class × candidate_fields × mutation_values], ranked by exploitability (pre-auth > post-auth, frequent packets > rare).
2.5. **Get a crash first (TOP PRIORITY)**: Your #1 goal is to achieve ANY crash, even if it reproduces a known vulnerability. A working crash proves your toolchain works and gives you a concrete foundation.
   - Take the most promising exploit details from your research (byte offset, value, filter) and write a C exploit. Try the exploit that looks most likely to work FIRST.
   - Test it and record results with `save_finding` (tag: `crash_reproduction`).
   - If it crashes: **SUCCESS** — you have a working crash. Now vary it: try adjacent offsets, different values at the same offset, and related fields to find NEW unique crashes.
   - If it doesn't crash: try adjusting the offset, value, or filter (the source may have different firmware/version). Try at least 2-3 variations before giving up on a candidate.
   - Work through your top 3-5 candidates from research. Do NOT skip to novel exploration until you have at least one confirmed crash or have exhausted all promising candidates.
   - Once you have a working crash, pivot to finding NEW crashes by generalizing from the working pattern.
3. **Hypothesize**: Based on protocol knowledge and research, identify fields likely to trigger Bluetooth stack bugs (boundary values, security-critical fields).
4. **Test**: Write a C exploit and run it. When you have multiple related hypotheses (e.g., sweeping values at an offset), batch them — plan all exploit code upfront. Set the `mutation_category` parameter.
5. **Analyze**: Read the `analysis` field in the result carefully:
   - Check `mutation_count`: if 0, your filter never matched — fix the filter before trying a new strategy.
   - Check `total_packets`: if < 30, the peripheral rejected the connection early — use a less aggressive mutation or target a later-stage packet.
   - Check `new_states`/`new_transitions`: new states are leads worth investigating with `diff_state_machines` or `view_state_machine`.
   - If crash: use `analyze_crash_log`, `read_device_log` to understand the root cause.
   - If stuck (3+ tests with no crash and no new leads): use `web_search` or `fetch_url` to research the specific crash component, field, or error you're seeing. All tools remain available throughout — research is not limited to step 2.
6. **Record (MANDATORY)**: You MUST call `save_finding` after EVERY `execute_test` or `execute_test_batch` with your analysis of what you tried, what happened, and what you learned. Include `test_id` in `related_tests` and categorize with tags (e.g. `no_crash`, `crash`, `no_mutation_match`, `new_state`, `low_packets`). Failure to do this means your observations are permanently lost when conversation context is summarized.
7. **Update strategy**: Use `update_strategy` to maintain your plan. Track which mutation categories you have covered.
8. **Iterate**: Adjust strategy based on results. Explore related mutations near crashes. Move on from exhausted areas. Never repeat the same mutation technique on similar fields — diversify across the mutation taxonomy. You may use `web_search`, `fetch_url`, and paper tools at any point — not just during the initial research phase.
"""

WORKFLOW_V3_AND_FULL_POST_FIRST_CRASH = """\
## Workflow
1. **Inspect**: Use `list_packet_types` to survey the capture. Drill into specific packets with `inspect_packets`.
2. **Research (REQUIRED)**:
   a. **Online exploit search (REQUIRED)**: Use `web_search` to find exploit write-ups, vulnerability reports, and security advisories (e.g. `web_search(query="{search_example_1}")`, `web_search(query="{search_example_2}")`). Use `fetch_url` to read full content from promising results. Also search for confirmed crash patterns and CVEs specific to the target peripheral.
   b. **Academic research**: Search the local paper collection with `query_papers` and `list_paper_categories`, then use `read_paper` to study relevant papers.
   c. Read at least 2 papers or CVE write-ups in full. Prioritize sources that describe specific attacks with exploit details (target field, mutation, root cause).
   d. For each paper or CVE, extract and record (via `save_finding` with tag `paper_insight` or `web_sourced`):
      - The bug class / root cause pattern (e.g., unchecked length, missing enum validation, null deref on optional release)
      - Why the parser was vulnerable — what assumption was violated
      - Generalization potential — what other protocol fields or layers likely share the same weakness
      - The specific field+value — use these to attempt reproduction first, then generalize to adjacent fields
   e. After research, use `search_fields` / `get_field_info` to find ALL fields in the capture matching each bug class. Call `update_strategy` with a generalization matrix: [bug_class × candidate_fields × mutation_values], ranked by exploitability (pre-auth > post-auth, frequent packets > rare).
2.5. **NOVEL CRASH HUNTING (ACTIVE — crash confirmed)**: Your toolchain is proven. Your SOLE objective is finding `non_publicly_known_crash` and `fully_novel_crash` crashes.
   - **Stay close to what works.** Historical data shows that nearly all novel crashes come from variations on known vulnerable areas, not from jumping to entirely new attack surfaces.
   - **Value variants at the same offset** — trying different values at a confirmed crash offset often triggers a different crash signature. Values close to the original byte value, boundary values, and values producing different ASN.1 interpretations have all yielded non-public crashes.
   - **Adjacent offset exploration** — bytes near a confirmed crash offset (±1 to ±6 bytes) often share similar parser weaknesses. Exploring the gaps between known crash zones in the same region has been productive.
   - **Multi-field value combinations** — varying both bytes in a confirmed multi-byte crash (e.g. different (byteA, byteB) pairs) can trigger different crash components.
   - **Inner byte deletion / zeroing** — zeroing individual bytes between known crash zones that have never been individually tested can reach new code paths.
   - If a test returns `publicly_known_crash`, try a different value at that offset — the same offset with a different value may yield a non-public or novel crash.
   - **Track your sweep**: after every test, update your strategy with the offset+value you tested and the result (crash_category or no crash). This keeps your sweep tracker accurate across context summarization.
3. **Hypothesize**: Based on protocol knowledge and research, identify fields likely to trigger Bluetooth stack bugs (boundary values, security-critical fields).
4. **Test**: Write a C exploit and run it. When you have multiple related hypotheses (e.g., sweeping values at an offset, testing adjacent bytes), batch them — plan all exploit code upfront. Set the `mutation_category` parameter.
5. **Analyze**: Read the `analysis` field in the result carefully:
   - Check `mutation_count`: if 0, your filter never matched — fix the filter before trying a new strategy.
   - Check `total_packets`: if < 30, the peripheral rejected the connection early — use a less aggressive mutation or target a later-stage packet.
   - Check `new_states`/`new_transitions`: new states are leads worth investigating with `diff_state_machines` or `view_state_machine`.
   - If crash: check `crash_category`. If `publicly_known_crash`, note the offset/value that caused it — consider trying a different value at that offset. If `non_publicly_known_crash` or `fully_novel_crash`, this is a WIN — analyze deeply with `analyze_crash_log`, `read_device_log`, and explore adjacent mutations.
   - If stuck (3+ tests with no crash and no new leads): use `web_search` or `fetch_url` to research the specific crash component, field, or error you're seeing. All tools remain available throughout — research is not limited to step 2.
6. **Record (MANDATORY)**: After each test, call `save_finding` AND `update_strategy` in the SAME response — do not wait for the next turn. Record what you tried, the crash_category result, and update your exhausted offset+value list in the strategy.
7. **Iterate**: Adjust strategy based on results. Explore related mutations near crashes. Move on from exhausted areas. Never repeat the same mutation technique on similar fields — diversify across the mutation taxonomy. You may use `web_search`, `fetch_url`, and paper tools at any point — not just during the initial research phase.
"""

WORKFLOW_V2_POST_FIRST_CRASH = """\
## Workflow
1. **Inspect**: Use `list_packet_types` to survey the capture. Drill into specific packets with `inspect_packets`.
2. **Research (REQUIRED)**:
   a. **Online exploit search (REQUIRED)**: Use `web_search` to find exploit write-ups, vulnerability reports, and security advisories (e.g. `web_search(query="{search_example_1}")`, `web_search(query="{search_example_2}")`). Use `fetch_url` to read full content from promising results. Also search for confirmed crash patterns and CVEs specific to the target peripheral.
   b. **Academic research**: Search the local paper collection with `query_papers` and `list_paper_categories`, then use `read_paper` to study relevant papers.
   c. Read at least 2 papers or CVE write-ups in full. Prioritize sources that describe specific attacks with exploit details (target field, mutation, root cause).
   d. For each paper or CVE, extract and record (via `save_finding` with tag `paper_insight` or `web_sourced`):
      - The bug class / root cause pattern (e.g., unchecked length, missing enum validation, null deref on optional release)
      - Why the parser was vulnerable — what assumption was violated
      - Generalization potential — what other protocol fields or layers likely share the same weakness
      - The specific field+value — use these to attempt reproduction first, then generalize to adjacent fields
   e. After research, use `search_fields` / `get_field_info` to find ALL fields in the capture matching each bug class. Call `update_strategy` with a generalization matrix: [bug_class × candidate_fields × mutation_values], ranked by exploitability (pre-auth > post-auth, frequent packets > rare).
2.5. **NOVEL CRASH HUNTING (ACTIVE — crash confirmed)**: Your toolchain is proven. Your SOLE objective is finding `non_publicly_known_crash` and `fully_novel_crash` crashes.
   - **Stay close to what works.** Historical data shows that nearly all novel crashes come from variations on known vulnerable areas, not from jumping to entirely new attack surfaces.
   - **Value variants at the same offset** — trying different values at a confirmed crash offset often triggers a different crash signature. Values close to the original byte value, boundary values, and values producing different ASN.1 interpretations have all yielded non-public crashes.
   - **Adjacent offset exploration** — bytes near a confirmed crash offset (±1 to ±6 bytes) often share similar parser weaknesses. Exploring the gaps between known crash zones in the same region has been productive.
   - **Multi-field value combinations** — varying both bytes in a confirmed multi-byte crash (e.g. different (byteA, byteB) pairs) can trigger different crash components.
   - **Inner byte deletion / zeroing** — zeroing individual bytes between known crash zones that have never been individually tested can reach new code paths.
   - If a test returns `publicly_known_crash`, try a different value at that offset — the same offset with a different value may yield a non-public or novel crash.
   - **Track your sweep**: after every test, update your strategy with the offset+value you tested and the result (crash_category or no crash). This keeps your sweep tracker accurate across context summarization.
3. **Hypothesize**: Based on protocol knowledge and research, identify fields likely to trigger Bluetooth stack bugs (boundary values, security-critical fields).
4. **Test**: Write a C exploit and run it. Set the `mutation_category` parameter.
5. **Analyze**: Read the `analysis` field in the result carefully:
   - Check `mutation_count`: if 0, your filter never matched — fix the filter before trying a new strategy.
   - Check `total_packets`: if < 30, the peripheral rejected the connection early — use a less aggressive mutation or target a later-stage packet.
   - Check `new_states`/`new_transitions`: new states are leads worth investigating with `diff_state_machines` or `view_state_machine`.
   - If crash: check `crash_category`. If `publicly_known_crash`, note the offset/value that caused it — consider trying a different value at that offset. If `non_publicly_known_crash` or `fully_novel_crash`, this is a WIN — analyze deeply with `analyze_crash_log`, `read_device_log`, and explore adjacent mutations.
   - If stuck (3+ tests with no crash and no new leads): use `web_search` or `fetch_url` to research the specific crash component, field, or error you're seeing. All tools remain available throughout — research is not limited to step 2.
6. **Record (MANDATORY)**: After each test, call `save_finding` AND `update_strategy` in the SAME response — do not wait for the next turn. Record what you tried, the crash_category result, and update your exhausted offset+value list in the strategy.
7. **Iterate**: Adjust strategy based on results. Explore related mutations near crashes. Move on from exhausted areas. Never repeat the same mutation technique on similar fields — diversify across the mutation taxonomy. You may use `web_search`, `fetch_url`, and paper tools at any point — not just during the initial research phase.
"""


WORKFLOW_V3F_POST_FIRST_CRASH = """\
## Workflow
1. **Inspect**: Use `list_packet_types` to survey the capture. Drill into specific packets with `inspect_packets`.
2. **Research (REQUIRED)**:
   a. **Online exploit search (REQUIRED)**: Use `web_search` to find exploit write-ups, vulnerability reports, and security advisories (e.g. `web_search(query="{search_example_1}")`, `web_search(query="{search_example_2}")`). Use `fetch_url` to read full content from promising results. Also search for confirmed crash patterns and CVEs specific to the target peripheral.
   b. Read at least 2 CVE write-ups or online advisories in full. Prioritize sources that describe specific attacks with exploit details (target field, mutation, root cause).
   c. For each CVE or advisory, extract and record (via `save_finding` with tag `web_sourced`):
      - The bug class / root cause pattern (e.g., unchecked length, missing enum validation, null deref on optional release)
      - Why the parser was vulnerable — what assumption was violated
      - Generalization potential — what other protocol fields or layers likely share the same weakness
      - The specific field+value — use these to attempt reproduction first, then generalize to adjacent fields
   d. After research, use `search_fields` / `get_field_info` to find ALL fields in the capture matching each bug class. Call `update_strategy` with a generalization matrix: [bug_class × candidate_fields × mutation_values], ranked by exploitability (pre-auth > post-auth, frequent packets > rare).
2.5. **NOVEL CRASH HUNTING (ACTIVE — crash confirmed)**: Your toolchain is proven. Your SOLE objective is finding `non_publicly_known_crash` and `fully_novel_crash` crashes.
   - **Stay close to what works.** Historical data shows that nearly all novel crashes come from variations on known vulnerable areas, not from jumping to entirely new attack surfaces.
   - **Value variants at the same offset** — trying different values at a confirmed crash offset often triggers a different crash signature. Values close to the original byte value, boundary values, and values producing different ASN.1 interpretations have all yielded non-public crashes.
   - **Adjacent offset exploration** — bytes near a confirmed crash offset (±1 to ±6 bytes) often share similar parser weaknesses. Exploring the gaps between known crash zones in the same region has been productive.
   - **Multi-field value combinations** — varying both bytes in a confirmed multi-byte crash (e.g. different (byteA, byteB) pairs) can trigger different crash components.
   - **Inner byte deletion / zeroing** — zeroing individual bytes between known crash zones that have never been individually tested can reach new code paths.
   - If a test returns `publicly_known_crash`, try a different value at that offset — the same offset with a different value may yield a non-public or novel crash.
   - **Track your sweep**: after every test, update your strategy with the offset+value you tested and the result (crash_category or no crash). This keeps your sweep tracker accurate across context summarization.
3. **Hypothesize**: Based on protocol knowledge and research, identify fields likely to trigger Bluetooth stack bugs (boundary values, security-critical fields).
4. **Test**: Write a C exploit and run it. When you have multiple related hypotheses (e.g., sweeping values at an offset, testing adjacent bytes), batch them — plan all exploit code upfront. Set the `mutation_category` parameter.
5. **Analyze**: Read the `analysis` field in the result carefully:
   - Check `mutation_count`: if 0, your filter never matched — fix the filter before trying a new strategy.
   - Check `total_packets`: if < 30, the peripheral rejected the connection early — use a less aggressive mutation or target a later-stage packet.
   - Check `new_states`/`new_transitions`: new states are leads worth investigating with `diff_state_machines` or `view_state_machine`.
   - If crash: check `crash_category`. If `publicly_known_crash`, note the offset/value that caused it — consider trying a different value at that offset. If `non_publicly_known_crash` or `fully_novel_crash`, this is a WIN — analyze deeply with `analyze_crash_log`, `read_device_log`, and explore adjacent mutations.
   - If stuck (3+ tests with no crash and no new leads): use `web_search` or `fetch_url` to research the specific crash component, field, or error you're seeing. All tools remain available throughout — research is not limited to step 2.
6. **Record (MANDATORY)**: After each test, call `save_finding` AND `update_strategy` in the SAME response — do not wait for the next turn. Record what you tried, the crash_category result, and update your exhausted offset+value list in the strategy.
7. **Iterate**: Adjust strategy based on results. Explore related mutations near crashes. Move on from exhausted areas. Never repeat the same mutation technique on similar fields — diversify across the mutation taxonomy. You may use `web_search` and `fetch_url` at any point — not just during the initial research phase.
"""

MUTATION_TAXONOMY = """\
## Mutation Taxonomy (you MUST diversify across these categories)
Track which categories you have tested in your strategy memo. Do not run more than 3 consecutive tests in the same category.

1. **bit_flip** — Boundary values (0x00, 0xFF, max bitfield), reserved bits, spare bits.
2. **truncation** — Shorten packets by reducing `pkt_length` or zeroing trailing bytes.
3. **type_confusion** — Change message type identifiers (L2CAP signaling command code, SDP PDU ID, LMP opcode).
4. **length_overflow** — Set length fields larger/smaller than actual content (L2CAP payload length, SDP attribute length).
5. **field_deletion** — Zero out entire mandatory fields or IEs that the target must parse.
6. **flooding** — Send mutated packets at high frequency using counter-based triggers (`counter % N`).
7. **multi_stage** — Sequential attacks across protocol phases (e.g., corrupt auth then pairing, or use state variables across multiple packets).
8. **encoding_corruption** — Corrupt encoding structures: tag bytes, length determinants, choice indices, extension bits.
"""

INITIAL_BRIEFING_TEMPLATE = """\
Here is the packet type summary from the baseline capture. This shows the types of packets exchanged during a normal Bluetooth session between the Bluetooth host and the {device_name} peripheral.
{capture_note}
<packet_types>
{packet_summary}
</packet_types>

Start by surveying these packet types. Identify which ones are TX (Bluetooth host -> peripheral) as those are the ones you can mutate. Focus on security-critical messages first (L2CAP, SDP, LMP), then explore other protocol layers.

Use your tools to inspect specific packets, look up field descriptions, and design your first test. Remember to update your strategy memo as you go.\
"""

COLD_START_TEMPLATE = """\
## COLD START MODE — Research Phase Required

You are starting with **zero prior knowledge** about {target_vendor} {friendly_protocol_name} vulnerabilities.
No known crash patterns, no global knowledge base, and no session history are available.

**You MUST complete a research phase before running any fuzz tests:**

1. **Search for CVEs**: Use `web_search` to find CVEs for key protocol components:
   - `web_search(query="{target_vendor} L2CAP vulnerability CVE")` — Logical Link Control and Adaptation Protocol
   - `web_search(query="{target_vendor} SDP vulnerability CVE")` — Service Discovery Protocol
   - `web_search(query="{target_vendor} Bluetooth host vulnerability CVE")` — General Bluetooth controller/host vulnerabilities
   - `web_search(query="{target_vendor} LMP vulnerability CVE")` — Link Manager Protocol

2. **Drill into promising CVEs**: Use `fetch_url` to read full CVE advisories and exploit write-ups.

3. **Search for academic papers**: Use `query_papers` to search the local paper collection. Use `list_paper_categories` to see available categories. Use `read_paper` to study relevant papers.

4. **Save all findings**: Each useful vulnerability pattern should be saved with `save_finding` using the tag `web_sourced`. These auto-promote to the global knowledge base for future runs.

5. **Write your initial strategy**: After research, call `update_strategy` with a plan based on what you learned.

6. **Begin fuzzing**: Only after completing steps 1-5, start the inspect → hypothesize → test → analyze cycle.

Your discoveries will persist in the global knowledge base, so future runs (even without --cold-start) will benefit from your research.\
"""

WORKFLOW_V3F = """\
## Workflow
1. **Inspect**: Use `list_packet_types` to survey the capture. Drill into specific packets with `inspect_packets`.
2. **Research (REQUIRED)**:
   a. **Online exploit search (REQUIRED)**: Use `web_search` to find exploit write-ups, vulnerability reports, and security advisories (e.g. `web_search(query="{search_example_1}")`, `web_search(query="{search_example_2}")`). Use `fetch_url` to read full content from promising results. Also search for confirmed crash patterns and CVEs specific to the target peripheral.
   b. Read at least 2 CVE write-ups or online advisories in full. Prioritize sources that describe specific attacks with exploit details (target field, mutation, root cause).
   c. For each CVE or advisory, extract and record (via `save_finding` with tag `web_sourced`):
      - The bug class / root cause pattern (e.g., unchecked length, missing enum validation, null deref on optional release)
      - Why the parser was vulnerable — what assumption was violated
      - Generalization potential — what other protocol fields or layers likely share the same weakness
      - The specific field+value — use these to attempt reproduction first, then generalize to adjacent fields
   d. After research, use `search_fields` / `get_field_info` to find ALL fields in the capture matching each bug class. Call `update_strategy` with a generalization matrix: [bug_class × candidate_fields × mutation_values], ranked by exploitability (pre-auth > post-auth, frequent packets > rare).
2.5. **Get a crash first (TOP PRIORITY)**: Your #1 goal is to achieve ANY crash, even if it reproduces a known vulnerability. A working crash proves your toolchain works and gives you a concrete foundation.
   - Take the most promising exploit details from your research (byte offset, value, filter) and write a C exploit. Try the exploit that looks most likely to work FIRST.
   - Test it and record results with `save_finding` (tag: `crash_reproduction`).
   - If it crashes: **SUCCESS** — you have a working crash. Now vary it: try adjacent offsets, different values at the same offset, and related fields to find NEW unique crashes.
   - If it doesn't crash: try adjusting the offset, value, or filter (the source may have different firmware/version). Try at least 2-3 variations before giving up on a candidate.
   - Work through your top 3-5 candidates from research. Do NOT skip to novel exploration until you have at least one confirmed crash or have exhausted all promising candidates.
   - Once you have a working crash, pivot to finding NEW crashes by generalizing from the working pattern.
3. **Hypothesize**: Based on protocol knowledge and research, identify fields likely to trigger Bluetooth stack bugs (boundary values, security-critical fields).
4. **Test**: Write a C exploit and run it. When you have multiple related hypotheses (e.g., sweeping values at an offset, testing adjacent bytes), batch them — plan all exploit code upfront. Set the `mutation_category` parameter.
5. **Analyze**: Read the `analysis` field in the result carefully:
   - Check `mutation_count`: if 0, your filter never matched — fix the filter before trying a new strategy.
   - Check `total_packets`: if < 30, the peripheral rejected the connection early — use a less aggressive mutation or target a later-stage packet.
   - Check `new_states`/`new_transitions`: new states are leads worth investigating with `diff_state_machines` or `view_state_machine`.
   - If crash: check `crash_category`. If `publicly_known_crash`, note the offset/value that caused it — consider trying a different value at that offset. If `non_publicly_known_crash` or `fully_novel_crash`, this is a WIN — analyze deeply with `analyze_crash_log`, `read_device_log`, and explore adjacent mutations.
   - If stuck (3+ tests with no crash and no new leads): use `web_search` or `fetch_url` to research the specific crash component, field, or error you're seeing. All tools remain available throughout — research is not limited to step 2.
6. **Record (MANDATORY)**: After each test, call `save_finding` AND `update_strategy` in the SAME response — do not wait for the next turn. Record what you tried, the crash_category result, and update your exhausted offset+value list in the strategy.
7. **Iterate**: Adjust strategy based on results. Explore related mutations near crashes. Move on from exhausted areas. Never repeat the same mutation technique on similar fields — diversify across the mutation taxonomy. You may use `web_search` and `fetch_url` at any point — not just during the initial research phase.
"""

RESEARCH_TEMPLATE = """\
## Discovery Mode — No Prior Crash Knowledge

You are starting with **zero prior knowledge** about {target_vendor} {friendly_protocol_name} vulnerabilities.
No known crash patterns are provided. You must discover vulnerabilities through your own analysis and research.

**Research tools available**: Use `web_search` for general web research and `fetch_url` to read full page content. Use `query_papers` and `read_paper` for the local paper collection. Save findings with `save_finding` (tag: `web_sourced` for online sources, `paper_insight` for papers).

**Research strategy** (you MUST research before your first test):
- Start with `web_search` for each layer and attack type
- Use `fetch_url` to read full CVE advisories and exploit write-ups — extract the actual bug mechanism, not just the CVE number
- Search the local paper collection for Bluetooth fuzzing and stack/controller exploitation papers, read the most relevant ones
- Your TOP PRIORITY is getting ANY crash, even a known one. When you find concrete exploit details (byte offsets, values, filters), immediately write a C exploit and test it. Do NOT skip to novel exploration until you have a working crash.
- Search for confirmed crashes and CVEs for the target peripheral. Prioritize sources with exact exploit details (offsets, values, filters) — these are your fastest path to a crash
- If a reproduction doesn't crash, try variations (adjust offset ±1-2 bytes, try different values, check filter matches) before moving on
- Once you have a confirmed crash, THEN generalize: use `search_fields` / `get_field_info` to find related fields and build a generalization matrix for novel crash discovery\
"""

RESEARCH_TEMPLATE_V3F = """\
## Discovery Mode — No Prior Crash Knowledge

You are starting with **zero prior knowledge** about {target_vendor} {friendly_protocol_name} vulnerabilities.
No known crash patterns are provided. You must discover vulnerabilities through your own analysis and research.

**Research tools available**: Use `web_search` for general web research and `fetch_url` to read full page content. Save findings with `save_finding` (tag: `web_sourced`).

**Research strategy** (you MUST research before your first test):
- Start with `web_search` for each layer and attack type
- Use `fetch_url` to read full CVE advisories and exploit write-ups — extract the actual bug mechanism, not just the CVE number
- Your TOP PRIORITY is getting ANY crash, even a known one. When you find concrete exploit details (byte offsets, values, filters), immediately write a C exploit and test it. Do NOT skip to novel exploration until you have a working crash.
- Search for confirmed crashes and CVEs for the target peripheral. Prioritize sources with exact exploit details (offsets, values, filters) — these are your fastest path to a crash
- If a reproduction doesn't crash, try variations (adjust offset ±1-2 bytes, try different values, check filter matches) before moving on
- Once you have a confirmed crash, THEN generalize: use `search_fields` / `get_field_info` to find related fields and build a generalization matrix for novel crash discovery\
"""

WDISSECTOR_API = """\
## WDissector C Plugin API Reference

Your exploit is a C shared library loaded by `bt_fuzzer`. Below is a **complete, compilable template**.

### Complete exploit template (copy-paste ready):
```c
#include <ModulesInclude.hpp>

// Filters
wd_filter_t f1;

const char *module_name() { return "ExploitName"; }

int setup(wd_modules_ctx_t *ctx) {
    ctx->config->fuzzing.global_timeout = false;
    f1 = wd_filter("btbrlmp.op == 40");

    // ── Bluetooth-specific configuration ──────────────────────────────────
    // USER-TUNABLE: set true to keep master role, false to allow role switch.
    ctx->config->bluetooth.disable_role_switch = false;

    // REQUIRED (must be true): bridges the HCI layer for packet interception.
    ctx->config->bluetooth.bridge_hci = true;

    // REQUIRED (must be true): intercepts TX packets so they can be modified.
    ctx->config->bluetooth.intercept_tx = true;

    // REQUIRED (must be true): enables low-level LMP sniffing.
    ctx->config->bluetooth.lmp_sniffing = true;

    // USER-TUNABLE: set true to enable RX bypass mode for flooding exploits.
    // When true, all received packets are bypassed — useful for high-rate
    // flooding attacks where you do not need to process the target's responses.
    ctx->config->bluetooth.rx_bypass = false;

    // REQUIRED (must be false): on-demand RX bypass must remain disabled.
    ctx->config->bluetooth.rx_bypass_on_demand = false;
    // ─────────────────────────────────────────────────────────────────────

    return 0;
}

int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx) {
    wd_register_filter(ctx->wd, f1);
    return 0;
}

int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx) {
    if (wd_read_filter(ctx->wd, f1)) {
        wd_log_y("Mutated!");
        pkt_buf[{offset}] = 0x67;
        return 1;
    }
    return 0;
}
```

### Key APIs:
- `wd_filter(const char *filter_str)` -> `wd_filter_t` -- Create a Wireshark display filter (e.g. `"btbrlmp.op == 40"`)
- `wd_register_filter(ctx->wd, filter)` -- Register filter for current packet (call in `tx_pre_dissection`)
- `wd_read_filter(ctx->wd, filter)` -> bool -- Check if current packet matches filter (call in `tx_post_dissection`)
- `wd_log_y(const char *msg)` -- Log message (yellow)
- `pkt_buf` -- Pointer to payload start. 
  * **CRITICAL - Offset Calculation:** Always call the `get_field_info` tool first to find the correct field offset (e.g. for `btbrlmp.fpage`) rather than attempting to manually parse raw packet hex dumps (which leads to off-by-one errors).
  * Note that the `byte_offset` returned by `get_field_info` is relative to the start of the H4 packet. Since `pkt_buf` in `tx_post_dissection` starts after the 7-byte H4/HCI header, you MUST calculate the index in `pkt_buf` as:
    `index_in_pkt_buf = byte_offset - 7`
    *Example:* If `get_field_info` for `btbrlmp.fpage` returns `byte_offset: 13`, you MUST use `pkt_buf[6]` (`13 - 7 = 6`) in your C++ code. Do NOT use `13` or any other value.
  * `get_field_info` refuses ASN.1 fields — for those, anchor by hex pattern via `get_packet_hex` + `inspect_packets`.
- Return 1 from `tx_post_dissection` to send mutated packet, 0 for unmodified.

### Config tuning guide:
| Field | Default | Tunable? | Notes |
|---|---|---|---|
| `disable_role_switch` | `false` | ✅ Yes | Set `true` to force master role and prevent role switching |
| `bridge_hci` | `true` | ❌ No | Must be `true` — required for HCI interception |
| `intercept_tx` | `true` | ❌ No | Must be `true` — required to hold and modify TX packets |
| `lmp_sniffing` | `true` | ❌ No | Must be `true` — required for low-level LMP visibility |
| `rx_bypass` | `false` | ✅ Yes | Set `true` for flooding exploits that skip RX processing |
| `rx_bypass_on_demand` | `false` | ❌ No | Must be `false` |

### Example: Flooding (send mutated every Nth packet)
```c
static uint counter = 0;
if (wd_read_filter(ctx->wd, f1)) {
    counter++;
    if (counter % 3 == 0) {  // Every 3rd matching packet
        // ... mutate ...
        return 1;
    }
}
```

### Exploit naming: Bluetooth exploits do not have any naming or prefix requirements.
"""
