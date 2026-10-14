import logging
import os
import struct
import subprocess
from io import BytesIO
from typing import Any, Generator, Literal, TypedDict, overload
from xml.etree.ElementTree import Element
import xml.etree.ElementTree as ET

import pyshark
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket
from pcapng.exceptions import TruncatedFile
from pyshark.packet.packet import Packet as PysharkPacket

from constants import EDITCAP_PATH, TSHARK_PATH, WDISSECTOR_PATH

logger = logging.getLogger(__name__)

PacketSummary = TypedDict(
    "PacketSummary",
    {
        "No.": str,
        "Time": str,
        "Source": str,
        "Destination": str,
        "Protocol": str,
        "Length": str,
        "Info": str,
    },
)


def pcap_pkt_reader(path: str):
    """Capture file reader using python-pcapng library."""
    with open(path, "rb") as f:
        scanner = FileScanner(f)
        pkt_index = 0
        try:
            for block in scanner:
                if not isinstance(block, EnhancedPacket):
                    continue
                pkt_index += 1
                yield block
        except TruncatedFile:
            logger.info(f"The capture file {path} is truncated.")
        except Exception:
            logger.error(
                f"Processing capture file: {path} at packet: {pkt_index}",
                exc_info=True,
            )


class PDMLPacketReader:
    """Read packet from PDML document."""

    def __init__(self, capture_path: str) -> None:
        self.capture_path = capture_path
        pdml = subprocess.check_output(
            [TSHARK_PATH, "-CWDissector", "-Tpdml", f"-r{self.capture_path}"],
            cwd=WDISSECTOR_PATH,
            stderr=subprocess.DEVNULL,
        )
        self.tree = ET.parse(BytesIO(pdml))

    def read_field(self, field: Element):
        res = {}
        if field.attrib.get("hide", None) == "yes":
            return res
        sub_fields = field.findall("./field")
        if len(sub_fields) == 0:
            key = field.attrib["name"]
            if key == "":
                key = field.attrib["show"]
            res[key] = field.attrib["showname"]
        else:
            key = field.attrib["name"]
            if key == "":
                key = field.attrib["show"]
            res[key] = {}
            for sub_field in sub_fields:
                for k, v in self.read_field(sub_field).items():
                    res[key][k] = v
        return res

    def read_proto(self, proto: Element):
        res = {}
        if proto.attrib.get("hide", None) == "yes":
            return res
        for tree in proto.findall("./"):
            if tree.tag == "field":
                for k, v in self.read_field(tree).items():
                    res[k] = v
            elif tree.tag == "proto":
                res[tree.attrib["name"]] = self.read_proto(tree)
        return res

    def read(self):
        for packet in self.tree.findall("./packet"):
            fields = {}
            for proto in packet.findall("./"):
                if proto.attrib["name"] == "geninfo":
                    for field in proto.findall("./field"):
                        if field.attrib["name"] == "num":
                            break
                else:
                    fields[proto.attrib["name"]] = self.read_proto(proto)
            yield fields


@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[True],
    include_detailed_dissection: Literal[False],
    include_raw: Literal[False],
) -> Generator[tuple[PacketSummary], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[False],
    include_detailed_dissection: Literal[True],
    include_raw: Literal[False],
) -> Generator[tuple[PysharkPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[False],
    include_detailed_dissection: Literal[False],
    include_raw: Literal[True],
) -> Generator[tuple[EnhancedPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[True],
    include_detailed_dissection: Literal[True],
    include_raw: Literal[False],
) -> Generator[tuple[PacketSummary, PysharkPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[False],
    include_detailed_dissection: Literal[True],
    include_raw: Literal[True],
) -> Generator[tuple[PysharkPacket, EnhancedPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[True],
    include_detailed_dissection: Literal[False],
    include_raw: Literal[True],
) -> Generator[tuple[PacketSummary, EnhancedPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[True],
    include_detailed_dissection: Literal[True],
    include_raw: Literal[True],
) -> Generator[tuple[PacketSummary, PysharkPacket, EnhancedPacket], Any, None]: ...
def packet_dissection_reader(
    capture_path: str,
    include_info: bool = True,
    include_detailed_dissection: bool = False,
    include_raw: bool = False,
):
    """Return packet dissection information generated by Wireshark."""
    tshark_params = {"-C": "WDissector"}
    readers = []
    capture_obj = None
    if include_info:
        capture_obj = pyshark.FileCapture(
            capture_path,
            tshark_path=TSHARK_PATH,
            only_summaries=True,
            keep_packets=False,
            use_json=False,
            custom_parameters=tshark_params,
        )
        info_fields_reader = (i._fields for i in capture_obj)
        readers.append(info_fields_reader)
    if include_detailed_dissection:
        pdml_reader = PDMLPacketReader(capture_path)
        readers.append(pdml_reader.read())
    if include_raw:
        pcap_reader = pcap_pkt_reader(capture_path)
        readers.append(pcap_reader)

    try:
        yield from zip(*readers)
    finally:
        if capture_obj is not None:
            # Kill tshark subprocess to prevent "Task exception was never retrieved" noise
            if (
                hasattr(capture_obj, "_current_tshark_process")
                and capture_obj._current_tshark_process
            ):
                try:
                    capture_obj._current_tshark_process.kill()
                    capture_obj._current_tshark_process.wait(timeout=5)
                except Exception:
                    pass
            try:
                capture_obj.close()
            except Exception:
                logger.debug("Error closing pyshark capture", exc_info=True)


def is_pcapng(capture_path: str) -> bool:
    with open(capture_path, "rb") as f:
        return f.read() == b"\x0a\x0d\x0d\x0a"


def is_pcap_truncated(capture_path: str) -> bool:
    PCAP_GLOBAL_HEADER_LEN = 24
    PCAP_PACKET_HEADER_LEN = 16
    with open(capture_path, "rb") as f:
        gh = f.read(PCAP_GLOBAL_HEADER_LEN)
        if len(gh) < PCAP_GLOBAL_HEADER_LEN:
            return True
        while True:
            ph = f.read(PCAP_PACKET_HEADER_LEN)
            if len(ph) == 0:
                return False
            if len(ph) < PCAP_PACKET_HEADER_LEN:
                return True
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("=IIII", ph)
            data = f.read(incl_len)
            if len(data) < incl_len:
                return True


def is_truncated_pcapng(capture_path: str) -> bool:
    with open(capture_path, "rb") as f:
        f.seek(-4, 2)
        last_len = struct.unpack("<I", f.read(4))[0]
        if last_len <= 12:
            return True
        if last_len > f.tell():
            return True
        f.seek(-last_len, 2)
        start_len = struct.unpack("<I", f.read(4))[0]
        return start_len != start_len


def is_truncated_capture(capture_path: str) -> bool:
    """Check if the capture file is truncated."""
    if is_pcapng(capture_path):
        return is_truncated_pcapng(capture_path)
    else:
        return is_pcap_truncated(capture_path)


def fix_truncated_pcap(capture_path: str):
    """Fix truncated captures in-place."""
    if not os.path.exists(capture_path):
        logger.error(f"File {capture_path} not found.")
        return
    capture_format = os.path.splitext(capture_path)[1].removeprefix(".")
    if capture_format not in ["pcap", "pcapng"]:
        logger.error(f"Unknown capture_format: {capture_format}")
    subprocess.run(
        f'{EDITCAP_PATH} -F {capture_format} "{capture_path}" "{capture_path}"',
        shell=True,
    )
