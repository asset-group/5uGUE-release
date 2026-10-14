import logging

from constants import (
    BT_WD_MODEL_CONFIG,
    BT_WD_SM_CONFIG,
    FIVEG_WD_MODEL_CONFIG,
    FIVEG_WD_SM_CONFIG,
    WIFI_WD_MODEL_CONFIG,
    WIFI_WD_SM_CONFIG,
)
from upstream.utils.misc import cached
from upstream.utils.types import ProtocolType
from wdissector import (
    WD_DIR_RX,
    WD_DIR_TX,
    WD_LOG_LEVEL_ERROR,
    Machine,
    WDPacketLabelGenerator,
    packet_read_field_bitmask,
    packet_read_field_bitmask_offset,
    packet_read_field_offset,
    packet_read_field_size,
    wd_field,
    wd_packet_dissect,
    wd_pkt_label,
    wd_read_field,
    wd_register_field,
    wd_set_log_level,
    wd_set_packet_direction,
)

logger = logging.getLogger(__name__)


class WDissectorTool:
    """WDissector protocol dissection tool."""

    def __init__(self, protocol: ProtocolType, decoding_offset: int) -> None:
        self.protocol: ProtocolType = protocol
        self.decoding_offset = decoding_offset

        if protocol == "bt":
            state_machine_config = BT_WD_SM_CONFIG
            model_config = BT_WD_MODEL_CONFIG
        elif protocol == "fiveg":
            state_machine_config = FIVEG_WD_SM_CONFIG
            model_config = FIVEG_WD_MODEL_CONFIG
        elif protocol == "wifi":
            state_machine_config = WIFI_WD_SM_CONFIG
            model_config = WIFI_WD_MODEL_CONFIG

        wd_set_log_level(WD_LOG_LEVEL_ERROR)
        self.StateMachine = Machine()
        if not self.StateMachine.init(state_machine_config):
            logger.error("Error initializing state machine")
            exit(1)
        self.wd = self.StateMachine.wd

        if not self.StateMachine.LoadModel(model_config):
            logger.error("Error loading state machine model")
            exit(1)

        self.PktLabelGen = WDPacketLabelGenerator()
        self.PktLabel = wd_pkt_label()
        if not self.PktLabelGen.init(state_machine_config, True):
            logger.error("Error initializing packet label generator")
            exit(1)

    def get_pkt_direction(self, pkt: bytes):
        direction = WD_DIR_TX
        try:
            if self.protocol == "bt":
                direction = WD_DIR_TX if pkt[3] == 0 else WD_DIR_RX
            elif self.protocol == "fiveg":
                direction = WD_DIR_TX if pkt[49] == 1 else WD_DIR_RX
        except Exception:
            pass
        return direction

    def pkt_state(self, pkt: bytes):
        """Get state of a packet."""
        direction = self.get_pkt_direction(pkt)
        if self.protocol == "fiveg":
            fiveg_field_offset = 48
        else:
            fiveg_field_offset = 0
        pkt = bytearray(pkt)[self.decoding_offset + fiveg_field_offset :]

        self.StateMachine.PrepareStateMapper(self.wd)
        wd_set_packet_direction(self.wd, direction)
        wd_packet_dissect(self.wd, pkt, len(pkt))
        self.StateMachine.RunStateMapper(self.wd, direction == WD_DIR_TX)

        return self.StateMachine.GetCurrentStateName()

    def label_pkt(self, pkt: bytes) -> str:
        """Get Wireshark filter label for a packet."""
        direction = self.get_pkt_direction(pkt)
        pkt = bytearray(pkt)[self.decoding_offset :]
        PktLabel = self.PktLabelGen.LabelPacket(direction, pkt, len(pkt))

        if PktLabel.label_status is True:
            return f"{PktLabel.pkt_field_name} == {PktLabel.pkt_field_value}"
        else:
            logger.warning(f"Cannot label packet {pkt.hex()}")
            return ""

    def field_offset_bitmask(
        self, pkt: bytes, field_name: str
    ) -> tuple[int, int, int, int]:
        """Get byte offset, bitmask, and size of a named field in a packet."""
        if self.protocol == "fiveg":
            fiveg_field_offset = 48
        else:
            fiveg_field_offset = 0
        direction = self.get_pkt_direction(pkt)

        target_wd_field = wd_field(field_name)
        if not target_wd_field:
            logger.error(f"Field not valid: {field_name}")
            raise Exception(f"Field not valid: {field_name}")

        wd_register_field(self.wd, target_wd_field)
        pkt = bytearray(pkt)[self.decoding_offset + fiveg_field_offset :]
        wd_set_packet_direction(self.wd, direction)
        wd_packet_dissect(self.wd, pkt, len(pkt))

        target_field = wd_read_field(self.wd, target_wd_field)
        if target_field:
            bitmask = packet_read_field_bitmask(target_field)
            field_size = packet_read_field_size(target_field)
            bitmask_offset = packet_read_field_bitmask_offset(bitmask)
            field_offset = packet_read_field_offset(target_field)
            if bitmask == 0:
                bitmask = 2 ** (field_size * 8) - 1
            return bitmask, bitmask_offset, field_offset, field_size
        else:
            logger.warning(
                f"wd_read_field: field '{field_name}' not present in dissected packet"
            )
            raise Exception(
                f"Field '{field_name}' not found in the dissected packet — it may not exist in this packet type/variant"
            )


@cached
def get_wd_tool(protocol: ProtocolType, decoding_offset: int):
    """Get a cached WDissectorTool instance."""
    return WDissectorTool(protocol, decoding_offset)
