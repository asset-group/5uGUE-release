import logging

import nest_asyncio

from upstream.utils.packet_cap import packet_dissection_reader
from upstream.utils.wd_utils import WDissectorTool

nest_asyncio.apply()

logger = logging.getLogger(__name__)


class State:
    def __init__(self, name: str) -> None:
        self.name = name
        self.next_states = {}

    def add_next_state(self, s: "State"):
        if s.name not in self.next_states:
            self.next_states[s.name] = s


class StateMachine:
    def __init__(self) -> None:
        self.states: dict[str, State] = {}

    def add_state(self, name: str) -> State:
        if name not in self.states:
            self.states[name] = State(name)
        return self.states[name]

    def add_transition(self, src: str, dst: str):
        src_state = self.add_state(src)
        dst_state = self.add_state(dst)
        src_state.add_next_state(dst_state)

    def add_transitions_from_state_seq(self, transitions: list[str]):
        for state in transitions:
            if state not in self.states:
                self.states[state] = State(state)
        for i in range(len(transitions) - 1):
            self.add_transition(transitions[i], transitions[i + 1])


def gen_sm(wd_tool: WDissectorTool, capture_path: str):
    sm = StateMachine()
    transitions = []
    buf = []

    for info, eh_pkt in packet_dissection_reader(
        capture_path,
        include_info=True,
        include_detailed_dissection=False,
        include_raw=True,
    ):
        pkt_comment = eh_pkt.options.get("opt_comment")
        if pkt_comment is not None:
            if "Fuzzed from" in pkt_comment or "Duplicated from" in pkt_comment:
                buf.pop(0)

        buf.append(eh_pkt)
        if len(buf) < 2:
            continue

        state = wd_tool.pkt_state(buf.pop(0).packet_data)
        transitions.append(state)
        sep_state = [
            "TX / LMP / LMP_detach",
            "TX / MAC-NR / RA-RNTI",
        ]
        if state in sep_state and len(transitions) > 1:
            sm.add_transitions_from_state_seq(transitions)
            transitions = []

    if len(transitions) > 1:
        sm.add_transitions_from_state_seq(transitions)

    return sm
