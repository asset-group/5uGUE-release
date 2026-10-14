"""User custom instructions appended to the system prompt in full (non-versioned) mode.

Edit the string below to inject your own instructions into the agent's system prompt.
"""

USER_CUSTOM_INSTRUCTIONS_FIVEG = """
## Example Crash Exploit Pattern

The following illustrates the structure of a successful single-field mutation exploit targeting an RRC Setup message. Use this as a reference for how to structure your own exploits.

```c
#include "ModulesInclude.hpp"

wd_filter_t f1;

const char *module_name() { return "example_rrc_field_mutation"; }

int setup(wd_modules_ctx_t *ctx) {
    ctx->config->fuzzing.global_timeout = false;
    f1 = wd_filter("nr-rrc.rrcSetup_element");
    return 0;
}

int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx) {
    wd_register_filter(ctx->wd, f1);
    return 0;
}

int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx) {
    if (wd_read_filter(ctx->wd, f1)) {
        pkt_buf[63] = 0xFF;
        pkt_buf[64] = 0xFF;
        wd_log_y("Mutated target fields");
        return 1;
    }
    return 0;
}
```

Key pattern: target a specific ASN.1-encoded field within RRC Setup at a known offset with a value that produces a valid-but-incorrect interpretation. Multi-stage variants can combine a progression-enabling mutation (e.g., one that allows deep packet exchange) with a targeted field corruption in a later-stage message.
"""

USER_CUSTOM_INSTRUCTIONS_BT = """
## Bluetooth Custom Instructions: Offset Calculation and Tool Usage

1. **DO NOT calculate byte offsets manually.** LLMs are prone to off-by-one errors when manually parsing raw packet hex dumps.
2. **USE `get_field_info` to get the offset:** For any protocol field you wish to mutate, you MUST call the `get_field_info` tool first to retrieve the correct `byte_offset` (e.g. for `btbrlmp.fpage` or `btbrlmp.maxsp`).
3. **Calculate the fuzzer payload index correctly:**
   In your C++ exploit code (`pkt_buf[index]`), the index is calculated as:
   `index_in_pkt_buf = byte_offset - 7`
   Where `byte_offset` is the value returned by `get_field_info` (which is relative to the start of the H4 packet), and `7` is the offset of the fuzzer's payload start.
   *Example:* If `get_field_info` for `btbrlmp.fpage` returns `byte_offset: 13`, you MUST use `pkt_buf[6]` (`13 - 7 = 6`) in your C++ code. Do NOT use `13` or any other offset.
"""

# Keep legacy name for backward compatibility or direct imports
USER_CUSTOM_INSTRUCTIONS = USER_CUSTOM_INSTRUCTIONS_FIVEG

