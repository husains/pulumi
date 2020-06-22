# Copyright 2016-2020, Pulumi Corporation.  All rights reserved.

import binascii
import os
from pulumi import export, input_type, Input, output_type, Output
from pulumi.dynamic import Resource, ResourceProvider, CreateResult

@input_type
class RandomSizeArgs:
    size: Input[float]
    def __init__(self, *, size: Input[float]):
        self.size = size

@output_type
class RandomSize:
    size: float

class RandomResourceProvider(ResourceProvider):
    def create(self, props):
        size = int(props["size"]["size"])
        val = binascii.b2a_hex(os.urandom(size)).decode("ascii")
        return CreateResult(val, { "val": val, "size": props["size"] })

class Random(Resource):
    val: Output[str]
    size: Output[RandomSize]
    def __init__(self, name, size: Input[RandomSizeArgs], opts = None):
        props = {
            "val": "",
            "size": size,
        }
        super().__init__(RandomResourceProvider(), name, props, opts)

r = Random("foo", RandomSizeArgs(size=15))

export("random_id", r.id)
export("random_val", r.val)
export("random_size", r.size.apply(lambda s: s.size))
