# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: poed_ipc.proto
# Protobuf Python Version: 4.25.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0epoed_ipc.proto\x12\x07PoedIpc" \n\rPoecliRequest\x12\x0f\n\x07request\x18\x01 \x01(\t"\x1c\n\x0bPoecliReply\x12\r\n\x05reply\x18\x01 \x01(\t2F\n\x06PoeIpc\x12<\n\x0cHandlePoecli\x12\x16.PoedIpc.PoecliRequest\x1a\x14.PoedIpc.PoecliReplyb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "poed_ipc_pb2", _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals["_POECLIREQUEST"]._serialized_start = 27
    _globals["_POECLIREQUEST"]._serialized_end = 59
    _globals["_POECLIREPLY"]._serialized_start = 61
    _globals["_POECLIREPLY"]._serialized_end = 89
    _globals["_POEIPC"]._serialized_start = 91
    _globals["_POEIPC"]._serialized_end = 161
# @@protoc_insertion_point(module_scope)
