#!/usr/bin/env python3
"""
Simple program to parse Apples vendor -specific Bluetooth LE advertising data
and to print some information about it.

This program assumes that bluewalker[1] is used to listen for Bluetooth LE
Advertisement Datas.

Usage:
    First start this program: ./spy --unix /tmp/ble-socket
    Then on another terminal, start bluewalker to listen for BLE advertisements
    from devices sending apple -specific vendor data and dump that data as
    JSON to unix socket:

    sudo ./bluewalker -device hci0 -duration 120 -observer -filter-vendor 0x4c00 -json -unix /tmp/ble-socket

    Once bluewalker exits, spy will print out the decoded information.

[1] https://gitlab.com/jtaimisto/bluewalker
"""

import argparse
import json
import base64
import binascii
import struct
import socket
import os
import datetime


class TLV:
    """
    Instances of this class represent one TLV element.

    Attributes:
        type:        type field value (1 byte, unsigned)
        value:       Byte array containing the value data
        pkt_count:   Sequence number of the advertising packet this TLV was read
                    from
    """

    def __init__(self, t, v):
        """
        Create new instance of TLV with given type and value

        :param t: Type for this TLV
        :param v: value for this TLV
        """
        self.type = t
        self.value = v
        self.pkt_count = 0

    def value_type(self):
        """Get type of this TLV"""
        return self.type

    def value_data(self):
        """Get value of this TLV"""
        return self.value

    def value_length(self):
        """Get length of the value in bytes"""
        return len(self.value)

    def compare_to(self, tlv):
        """
        Compare this TLV to another.

        :param tlv: TLV to compare this TLV to.
        :return: true if both TLVs have same type, value length and value bytes
        """
        if self.type != tlv.type:
            return False
        if self.value_length() != tlv.value_length():
            return False
        if self.value != tlv.value:
            return False
        return True

    def print_value(self):
        """
        Print the contents of this TLVs value.

        Does some type -specific formating.

        :return: string containing the contents of value field.
        """
        if self.value_type() == 0x0C and self.value_length() > 2:
            output = []
            output.append("({}:02x}{:02x})".format(self.value[0], self.value[1]))
            output.append("{}".format(binascii.hexlify(bytearray(self.value[2:]))))
            return " ".join(output)
        else:
            return "{}".format(binascii.hexlify(bytearray(self.value)))

    def string(self):
        """Get string containing contents of this TLV"""
        return "t:0x{:02x} l:{} bytes v:[{}]".format(
            self.type, self.value_length(), self.print_value()
        )


class VData:
    """
    VData contains all data (TLVs) parsed from vendor -specific data of single
    advertising packet.

    Attributes:
        tlvs:       list of TLVs parsed
        pkt_num:    sequence number of the advertising packet received. Starts
                    from 0
        created:    timestamp when this VData was created (that is, when the
                    advertising data was received).
        duplicates: Number of times advertising data containing exactly same
                    TLVs was received after this vdata.
        delta:      Time difference from previous vdata
    """

    def __init__(self, pkt_num, tlvs):
        """
        Create new VData.

        :param pkt_num: Sequence number of the advertisement packet
        :param tlvs: TLVs parsed from the vendor -specific data
        """
        self.tlvs = tlvs
        self.pkt_num = pkt_num
        self.created = datetime.datetime.now()
        self.duplicates = 0
        self.delta = None
        for tlv in tlvs:
            tlv.pkt_count = pkt_num

    def compare_to(self, vdata):
        """
        Compare this VData to another.
        :param vdata: VData to compare this to
        :return: True if the Vdata contains same number TLVs with equal
                 contents
        """
        if len(self.tlvs) != len(vdata.tlvs):
            return False
        for i in range(len(self.tlvs)):
            if not self.tlvs[i].compare_to(vdata.tlvs[i]):
                return False
        return True

    def set_delta_from(self, vdata):
        """
        Set the delta time from given VData.
        :param vdata: vdata to calculate the time delta from
        """
        self.delta = self.created - vdata.created

    def string(self):
        """Get a string containing description of this vdata and its contents"""
        output = []
        indent = "\t "
        output.append("\t---[{}]".format(self.tlvs[0].pkt_count))
        if self.delta is not None:
            output[0] += " +{}s".format(self.delta.total_seconds())

        for tlv in self.tlvs:
            output.append("{}{}".format(indent, tlv.string()))

        output[-1] += "(@{})".format(self.created.isoformat())
        if self.duplicates > 0:
            output.append("\t--Repeated {} times".format(self.duplicates))

        return "\n".join(output)


class Device:
    """
    Device contains all data received from a single device

    The device is identified by its BD_ADDR and thus changing random address
    results in new device information.

    Attributes:
        address:        Bluetooth address of the device
        vdata:          (Different) data transmitted by the device
        last_vdata_idx: index of the last vdata received in vdata list
        counter:        number of times we have received advertising data from
                        this device
        last_update:    Timestamp of last time we have received anythig from
                        this device
        idents:         array of different 'ident' (or whatever it really is)
                        blobs we have seen being transmitted by this device.
    """

    def __init__(self, name: str):
        self.address = name
        self.vdata = []
        # Index of last Vdata received
        self.last_vdata_idx = -1
        self.counter = 0
        self.last_update = None
        self.idents = []

    def add_vdata(self, vdata):
        """
        Add new vdata sent by this device.

        If the vdata is different from previous vdata received, it is added
        to the list of data received. If it is same, just the duplicate counter
        on previous vdata is incremented.

        :param vdata: parsed vdata
        """

        self.last_update = vdata.created
        if self.last_vdata_idx != -1:
            # Drop TLV's which are identical to previous one
            prev = self.vdata[self.last_vdata_idx]
            if vdata.compare_to(prev):
                prev.duplicates += 1
                return
            vdata.set_delta_from(prev)

        self.vdata.append(vdata)
        for tlv in vdata.tlvs:
            if tlv.value_type() == 0x10 and tlv.value_length() > 0:
                ident = tlv.value_data()
                if ident not in self.idents:
                    self.idents.append(ident)

        self.last_vdata_idx += 1


def parse_vendor_data(data):
    """
    Parse the TLV structures from given vendor specific data.

    It is assumed that the company identifier is stripped from the start of
    data.

    :param data: Vendor specific data (sans the company identifier)
    :return: List of TLVs parsed from the data/
    """

    ret = []
    i = 0

    while i < len(data) - 1:
        typ = data[i]
        i = i + 1
        length = data[i]
        i = i + 1

        if i + length <= len(data):
            val = data[i : i + length]
            ret.append(TLV(typ, val))
            i = i + length
        else:
            break

    return ret


def get_uint16(buf):
    """Read one unsigned 16-bit little endian value from given buffer"""
    (val,) = struct.unpack("<H", buf)
    return val


def decode_data(data):
    """Base64 decode data from given string"""
    return base64.b64decode(data)


def parse_json_object(devices, data):
    """
    Read relevant data from JSON -encoded object.

    The data should contain JSON encoded device information as specified in
    https://gitlab.com/jtaimisto/bluewalker/

    The vendor specific Advertising Data is parsed (if the device information
    contains apple -specific data) and information parsed is added to the
    collected data for the device.

    :param devices: Map containig data received from different devices, keyed
                    by address.
    :param data: JSON encoded data received from bluewalker.
    """
    obj = json.loads(data)

    if "data" in obj:
        addr = obj["device"]["address"]
        datas = obj["data"]
        for elem in datas:
            decoded = decode_data(elem["data"])
            typ = elem["type"]
            if typ == 0xFF and len(decoded) > 2:
                vendor = get_uint16(decoded[0:2])
                if vendor == 0x004C:
                    dev = None
                    if addr in devices:
                        dev = devices[addr]
                    else:
                        dev = Device(addr)
                        devices[addr] = dev

                    values = parse_vendor_data(decoded[2:])
                    cnt = dev.counter
                    vdata = VData(cnt, values)
                    dev.add_vdata(vdata)
                    dev.counter = cnt + 1


def from_unix_socket(name):
    """
    Start listening on UNIX socket for bluewalker to connect and read data
    from the socket.

    :param name: name (path) of the unix socket to listen on.
    """

    if os.path.exists(name):
        try:
            os.remove(name)
        except OSError as err:
            print("Unable to remove existing socket {} : {}".format(name, err.strerror))
            return

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(name)
    print("Socket bound to {}".format(name))
    sock.listen(1)
    print("Waiting for connection")
    conn, client = sock.accept()
    print("Connection from {}".format(client))
    devices = {}
    with conn.makefile() as file:
        for line in file:
            parse_json_object(devices, line)

    conn.close()
    sock.close()

    for addr, dev in devices.items():
        print("{} (last update @{}) :".format(addr, dev.last_update.isoformat()))
        for vdata in dev.vdata:
            print(vdata.string())

    print("Idents:")
    for addr, dev in devices.items():
        if dev.idents:
            identstr = ",".join(
                ["{}".format(binascii.hexlify(bytearray(x))) for x in dev.idents]
            )
            print(
                "\t{} -> {} ({} - {})".format(
                    identstr,
                    addr,
                    dev.vdata[0].created.isoformat(),
                    dev.last_update.isoformat(),
                )
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--unix", default="")
    args = parser.parse_args()
    if args.unix != "":
        from_unix_socket(args.unix)
    else:
        print("use --unix <path> to specify the unix socket to listen on")
