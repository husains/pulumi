# Copyright 2016-2018, Pulumi Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Support for serializing and deserializing properties going into or flowing
out of RPC calls.
"""
import sys
import asyncio
import functools
import inspect
import typing
from typing import List, Any, Callable, Dict, Optional, Tuple, Union, TYPE_CHECKING, cast, get_type_hints

from google.protobuf import struct_pb2
import six
from . import known_types, settings
from .. import log

if TYPE_CHECKING:
    from ..output import Inputs, Input, Output
    from ..resource import Resource, CustomResource
    from ..asset import FileAsset, RemoteAsset, StringAsset, FileArchive, RemoteArchive, AssetArchive

UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"
"""If a value is None, we serialize as UNKNOWN, which tells the engine that it may be computed later."""

_special_sig_key = "4dabf18193072939515e22adb298388d"
"""_special_sig_key is sometimes used to encode type identity inside of a map. See pkg/resource/properties.go."""

_special_asset_sig = "c44067f5952c0a294b673a41bacd8c17"
"""special_asset_sig is a randomly assigned hash used to identify assets in maps. See pkg/resource/asset.go."""

_special_archive_sig = "0def7320c3a5731c473e5ecbe6d01bc7"
"""special_archive_sig is a randomly assigned hash used to identify assets in maps. See pkg/resource/asset.go."""

_special_secret_sig = "1b47061264138c4ac30d75fd1eb44270"
"""special_secret_sig is a randomly assigned hash used to identify secrets in maps. See pkg/resource/properties.go"""

_INT_OR_FLOAT = six.integer_types + (float,)


def isLegalProtobufValue(value: Any) -> bool:
    """
    Returns True if the given value is a legal Protobuf value as per the source at
    https://github.com/protocolbuffers/protobuf/blob/master/python/google/protobuf/internal/well_known_types.py#L714-L732
    """
    return value is None or isinstance(value, (bool, six.string_types, _INT_OR_FLOAT, dict, list))


def _is_input_type(cls: type) -> bool:
    return hasattr(cls, "_pulumi_input_type")


def _is_output_type(cls: type) -> bool:
    return hasattr(cls, "_pulumi_output_type")


async def serialize_properties(inputs: 'Inputs',
                               property_deps: Dict[str, List['Resource']],
                               input_transformer: Optional[Callable[[str], str]] = None) -> struct_pb2.Struct:
    """
    Serializes an arbitrary Input bag into a Protobuf structure, keeping track of the list
    of dependent resources in the `deps` list. Serializing properties is inherently async
    because it awaits any futures that are contained transitively within the input bag.
    """
    struct = struct_pb2.Struct()
    for k, v in inputs.items():
        deps: List['Resource'] = []
        result = await serialize_property(v, deps, input_transformer)
        # We treat properties that serialize to None as if they don't exist.
        if result is not None:
            # While serializing to a pb struct, we must "translate" all key names to be what the
            # engine is going to expect. Resources provide the "transform" function for doing this.
            translated_name = k
            if input_transformer is not None:
                translated_name = input_transformer(k)
                log.debug(f"top-level input property translated: {k} -> {translated_name}")
            # pylint: disable=unsupported-assignment-operation
            struct[translated_name] = result
            property_deps[translated_name] = deps

    return struct


# pylint: disable=too-many-return-statements, too-many-branches
async def serialize_property(value: 'Input[Any]',
                             deps: List['Resource'],
                             input_transformer: Optional[Callable[[str], str]] = None) -> Any:
    """
    Serializes a single Input into a form suitable for remoting to the engine, awaiting
    any futures required to do so.
    """
    if isinstance(value, list):
        props = []
        for elem in value:
            props.append(await serialize_property(elem, deps, input_transformer))

        return props

    if known_types.is_unknown(value):
        return UNKNOWN

    if known_types.is_custom_resource(value):
        resource = cast('CustomResource', value)
        deps.append(resource)
        return await serialize_property(resource.id, deps, input_transformer)

    if known_types.is_asset(value):
        # Serializing an asset requires the use of a magical signature key, since otherwise it would
        # look like any old weakly typed object/map when received by the other side of the RPC
        # boundary.
        obj = {
            _special_sig_key: _special_asset_sig
        }

        if hasattr(value, "path"):
            file_asset = cast('FileAsset', value)
            obj["path"] = await serialize_property(file_asset.path, deps, input_transformer)
        elif hasattr(value, "text"):
            str_asset = cast('StringAsset', value)
            obj["text"] = await serialize_property(str_asset.text, deps, input_transformer)
        elif hasattr(value, "uri"):
            remote_asset = cast('RemoteAsset', value)
            obj["uri"] = await serialize_property(remote_asset.uri, deps, input_transformer)
        else:
            raise AssertionError(f"unknown asset type: {value}")

        return obj

    if known_types.is_archive(value):
        # Serializing an archive requires the use of a magical signature key, since otherwise it
        # would look like any old weakly typed object/map when received by the other side of the RPC
        # boundary.
        obj = {
            _special_sig_key: _special_archive_sig
        }

        if hasattr(value, "assets"):
            asset_archive = cast('AssetArchive', value)
            obj["assets"] = await serialize_property(asset_archive.assets, deps, input_transformer)
        elif hasattr(value, "path"):
            file_archive = cast('FileArchive', value)
            obj["path"] = await serialize_property(file_archive.path, deps, input_transformer)
        elif hasattr(value, "uri"):
            remote_archive = cast('RemoteArchive', value)
            obj["uri"] = await serialize_property(remote_archive.uri, deps, input_transformer)
        else:
            raise AssertionError(f"unknown archive type: {value}")

        return obj

    if inspect.isawaitable(value):
        # Coroutines and Futures are both awaitable. Coroutines need to be scheduled.
        # asyncio.ensure_future returns futures verbatim while converting coroutines into
        # futures by arranging for the execution on the event loop.
        #
        # The returned future can then be awaited to yield a value, which we'll continue
        # serializing.
        awaitable = cast('Any', value)
        future_return = await asyncio.ensure_future(awaitable)
        return await serialize_property(future_return, deps, input_transformer)

    if known_types.is_output(value):
        output = cast('Output', value)
        value_resources = await output.resources()
        deps.extend(value_resources)

        # When serializing an Output, we will either serialize it as its resolved value or the
        # "unknown value" sentinel. We will do the former for all outputs created directly by user
        # code (such outputs always resolve isKnown to true) and for any resource outputs that were
        # resolved with known values.
        is_known = await output._is_known
        is_secret = await output._is_secret
        value = await serialize_property(output.future(), deps, input_transformer)
        if not is_known:
            return UNKNOWN
        if is_secret and await settings.monitor_supports_secrets():
            # Serializing an output with a secret value requires the use of a magical signature key,
            # which the engine detects.
            return {
                _special_sig_key: _special_secret_sig,
                "value": value
            }
        return value

    transform_keys = True

    # If value is an input type, convert it to a dict via a call to its _to_dict() method,
    # and set transform_keys to False to prevent transforming the keys of the resulting dict
    # as the keys should already be the final names.
    value_cls = type(value)
    if _is_input_type(value_cls):
        to_dict = getattr(value_cls, "_to_dict", None)
        assert to_dict is not None
        assert callable(to_dict)
        value = to_dict(value)
        transform_keys = False

    if isinstance(value, dict):
        obj = {}
        for k, v in value.items():
            transformed_key = k
            if transform_keys and input_transformer is not None:
                transformed_key = input_transformer(k)
                log.debug(f"transforming input property: {k} -> {transformed_key}")
            obj[transformed_key] = await serialize_property(v, deps, input_transformer)

        return obj

    # Ensure that we have a value that Protobuf understands.
    if not isLegalProtobufValue(value):
        raise ValueError(f"unexpected input of type {type(value).__name__}")

    return value

# pylint: disable=too-many-return-statements
def deserialize_properties(props_struct: struct_pb2.Struct, keep_unknowns: Optional[bool] = None) -> Any:
    """
    Deserializes a protobuf `struct_pb2.Struct` into a Python dictionary containing normal
    Python types.
    """
    # Check out this link for details on what sort of types Protobuf is going to generate:
    # https://developers.google.com/protocol-buffers/docs/reference/python-generated
    #
    # We assume that we are deserializing properties that we got from a Resource RPC endpoint,
    # which has type `Struct` in our gRPC proto definition.
    if _special_sig_key in props_struct:
        from .. import FileAsset, StringAsset, RemoteAsset, AssetArchive, FileArchive, RemoteArchive  # pylint: disable=import-outside-toplevel
        if props_struct[_special_sig_key] == _special_asset_sig:
            # This is an asset. Re-hydrate this object into an Asset.
            if "path" in props_struct:
                return FileAsset(props_struct["path"])
            if "text" in props_struct:
                return StringAsset(props_struct["text"])
            if "uri" in props_struct:
                return RemoteAsset(props_struct["uri"])
            raise AssertionError("Invalid asset encountered when unmarshalling resource property")
        if props_struct[_special_sig_key] == _special_archive_sig:
            # This is an archive. Re-hydrate this object into an Archive.
            if "assets" in props_struct:
                return AssetArchive(deserialize_property(props_struct["assets"]))
            if "path" in props_struct:
                return FileArchive(props_struct["path"])
            if "uri" in props_struct:
                return RemoteArchive(props_struct["uri"])
            raise AssertionError("Invalid archive encountered when unmarshalling resource property")
        if props_struct[_special_sig_key] == _special_secret_sig:
            return {
                _special_sig_key: _special_secret_sig,
                "value": deserialize_property(props_struct["value"])
            }

        raise AssertionError("Unrecognized signature when unmarshalling resource property")

    # Struct is duck-typed like a dictionary, so we can iterate over it in the normal ways. Note
    # that if the struct had any secret properties, we push the secretness of the object up to us
    # since we can only set secret outputs on top level properties.
    output = {}
    for k, v in list(props_struct.items()):
        value = deserialize_property(v, keep_unknowns)
        # We treat values that deserialize to "None" as if they don't exist.
        if value is not None:
            output[k] = value

    return output

def is_rpc_secret(value: Any) -> bool:
    """
    Returns if a given python value is actually a wrapped secret
    """
    return isinstance(value, dict) and _special_sig_key in value and value[_special_sig_key] == _special_secret_sig

def unwrap_rpc_secret(value: Any) -> Any:
    """
    Given a value, if it is a wrapped secret value, return the underlying, otherwise return the value unmodified.
    """
    if is_rpc_secret(value):
        return value["value"]

    return value

def deserialize_property(value: Any, keep_unknowns: Optional[bool] = None) -> Any:
    """
    Deserializes a single protobuf value (either `Struct` or `ListValue`) into idiomatic
    Python values.
    """
    from ..output import Unknown  # pylint: disable=import-outside-toplevel
    if value == UNKNOWN:
        return Unknown() if settings.is_dry_run() or keep_unknowns else None

    # ListValues are projected to lists
    if isinstance(value, struct_pb2.ListValue):
        # values has no __iter__ defined but this works.
        values = [deserialize_property(v, keep_unknowns) for v in value] # type: ignore
        # If there are any secret values in the list, push the secretness "up" a level by returning
        # an array that is marked as a secret with raw values inside.
        if any(is_rpc_secret(v) for v in values):
            return {
                _special_sig_key: _special_secret_sig,
                "value": [unwrap_rpc_secret(v) for v in values]
            }

        return values

    # Structs are projected to dictionaries
    if isinstance(value, struct_pb2.Struct):
        props = deserialize_properties(value, keep_unknowns)
        # If there are any secret values in the dictionary, push the secretness "up" a level by returning
        # a dictionary that is marked as a secret with raw values inside. Note: thje isinstance check here is
        # important, since deserialize_properties will return either a dictionary or a concret type (in the case of
        # assets).
        if isinstance(props, dict) and any(is_rpc_secret(v) for v in props.values()):
            return {
                _special_sig_key: _special_secret_sig,
                "value": {k: unwrap_rpc_secret(v) for k, v in props.items()}
            }

        return props

    # Everything else is identity projected.
    return value


Resolver = Callable[[Any, bool, bool, Optional[Exception]], None]
"""
A Resolver is a function that takes four arguments:
    1. A value, which represents the "resolved" value of a particular output (from the engine)
    2. A boolean "is_known", which represents whether or not this value is known to have a particular value at this
       point in time (not always true for previews), and
    3. A boolean "is_secret", which represents whether or not this value is contains secret data, and
    4. An exception, which (if provided) is an exception that occured when attempting to create the resource to whom
       this resolver belongs.

If argument 4 is not none, this output is considered to be abnormally resolved and attempts to await its future will
result in the exception being re-thrown.
"""


def transfer_properties(res: 'Resource', props: 'Inputs') -> Dict[str, Resolver]:
    from .. import Output  # pylint: disable=import-outside-toplevel
    resolvers: Dict[str, Resolver] = {}
    for name in props.keys():
        if name in ["id", "urn"]:
            # these properties are handled specially elsewhere.
            continue

        resolve_value: 'asyncio.Future' = asyncio.Future()
        resolve_is_known: 'asyncio.Future' = asyncio.Future()
        resolve_is_secret: 'asyncio.Future' = asyncio.Future()

        def do_resolve(value_fut: 'asyncio.Future',
                       known_fut: 'asyncio.Future[bool]',
                       secret_fut: 'asyncio.Future[bool]',
                       value: Any,
                       is_known: bool,
                       is_secret: bool,
                       failed: Optional[Exception]):
            # Was an exception provided? If so, this is an abnormal (exceptional) resolution. Resolve the futures
            # using set_exception so that any attempts to wait for their resolution will also fail.
            if failed is not None:
                value_fut.set_exception(failed)
                known_fut.set_exception(failed)
                secret_fut.set_exception(failed)
            else:
                value_fut.set_result(value)
                known_fut.set_result(is_known)
                secret_fut.set_result(is_secret)

        # Important to note here is that the resolver's future is assigned to the resource object using the
        # name before translation. When properties are returned from the engine, we must first translate the name
        # using res.translate_output_property and then use *that* name to index into the resolvers table.
        log.debug(f"adding resolver {name}")
        resolvers[name] = functools.partial(do_resolve, resolve_value, resolve_is_known, resolve_is_secret)
        res.__setattr__(name, Output({res}, resolve_value, resolve_is_known, resolve_is_secret))

    return resolvers


# Use the built-in `get_origin` and `get_args` functions on Python 3.8+,
# otherwise fallback to downlevel implementations.
if sys.version_info[:2] >= (3, 8):
    _get_origin = typing.get_origin
    _get_args = typing.get_args
elif sys.version_info[:2] >= (3, 7):
    def _get_origin(tp):
        if isinstance(tp, typing._GenericAlias):
            return tp.__origin__
        return None

    def _get_args(tp):
        if isinstance(tp, typing._GenericAlias):
            return tp.__args__
        return ()
else:
    def _get_origin(tp):
        if hasattr(tp, "__origin__"):
            return tp.__origin__
        return None

    def _get_args(tp):
        if hasattr(tp, "__args__"):
            return tp.__args__
        return ()


def _is_union_type(tp):
    if sys.version_info[:2] >= (3, 7):
        return (tp is Union or
                isinstance(tp, typing._GenericAlias) and tp.__origin__ is Union)
    return type(tp) is typing._Union # pylint: disable=unidiomatic-typecheck, no-member


def _is_optional_type(tp):
    if tp is type(None):
        return True
    if _is_union_type(tp):
        return any(_is_optional_type(tt) for tt in _get_args(tp))
    return False


def _output_types(cls: type) -> Dict[str, type]:
    """
    Returns a dictionary of property names to types, for a given Resource or output type,
    based on class's variable annotations.

    This is used after deserializing outputs, to know if an output type needs to be
    instantiated and used instead of a raw dict.
    """
    # pylint: disable=import-outside-toplevel
    from .. import Output, Input, Resource
    from ..output import _get_properties

    def unwrap(val: type) -> type:
        origin = _get_origin(val)

        # If it is an Output[T], extract the T arg.
        if origin is Output:
            args = _get_args(val)
            assert len(args) == 1
            val = args[0]

        # If it is Optional[T], it is Union[T, None], extract the first arg T.
        if _is_optional_type(val):
            args = _get_args(val)
            assert len(args) == 2
            assert args[1] is type(None)
            val = args[0]

        return val

    if _is_output_type(cls):
        props = getattr(cls, "_pulumi_properties", None)
    elif issubclass(cls, Resource):
        props = _get_properties(cls)
    else:
        return {}

    # Get hints via typing.get_type_hints(), which handles forward references.
    # Pass Output and Input as locals, to ensure they are available.
    cls_hints = get_type_hints(cls, localns={"Output": Output, "Input": Input}) # type: ignore

    return {
        prop.name: unwrap(cls_hints[name])
        for name, prop in props.items()
    }


def translate_output_properties(res: 'Resource', output: Any, typ: Optional[type] = None) -> Any:
    """
    Recursively rewrite keys of objects returned by the engine to conform with a naming
    convention specified by the resource's implementation of `translate_output_property`.

    Additionally, if output is a `dict` and `typ` is an output type, instantiate the output type,
    passing the dict as an argument to the output type's __init__() method.

    If output is a `dict`, every key is translated using `translate_output_property` while every value is transformed
    by recursing.

    If output is a `list`, every value is recursively transformed.

    If output is a primitive (i.e. not a dict or list), the value is returned without modification.
    """

    # If typ is optional, unwrap it.
    if typ and _is_optional_type(typ):
        args = _get_args(typ)
        assert len(args) == 2
        assert args[1] is type(None)
        typ = args[0]

    if isinstance(output, dict):
        # Function called to lookup a type for a given key.
        # The default always returns None.
        get_type: Callable[[str], Optional[type]] = lambda k: None

        if typ and _is_output_type(typ):
            # If typ is an output type, get its types, so we can pass
            # the type along for each property.
            types = _output_types(typ)
            get_type = lambda k: types.get(k) # pylint: disable=unnecessary-lambda
        elif typ:
            # If typ is a dict, get the type for its values, to pass
            # along for each key.
            origin = _get_origin(typ)
            if origin is dict or typing.Dict:
                args = _get_args(typ)
                if len(args) == 2 and args[0] is str:
                    get_type = lambda k: args[1]
        translated = {
            res.translate_output_property(k):
                translate_output_properties(res, v, get_type(k))
            for k, v in output.items()
        }
        # If typ is an output type, instantiate it, passing the translated dict as an
        # arg to the output type's __init__() method, otherwise, return the translated
        # dict.
        return typ(translated) if typ and _is_output_type(typ) else translated

    if isinstance(output, list):
        element_type: Optional[type] = None
        if typ:
            # If typ is a list, get the type for its values, to pass
            # along for each item.
            origin = _get_origin(typ)
            if origin is list or typing.List:
                args = _get_args(typ)
                if len(args) == 1:
                    element_type = args[0]
        return [translate_output_properties(res, v, element_type) for v in output]

    return output


def contains_unknowns(val: Any) -> bool:
    def impl(val: Any, stack: List[Any]) -> bool:
        if known_types.is_unknown(val):
            return True

        if not any([x is val for x in stack]):
            stack.append(val)
            if isinstance(val, dict):
                return any([impl(x, stack) for x in val.values()])
            if isinstance(val, list):
                return any([impl(x, stack) for x in val])
        return False

    return impl(val, [])


async def resolve_outputs(res: 'Resource',
                          serialized_props: struct_pb2.Struct,
                          outputs: struct_pb2.Struct,
                          resolvers: Dict[str, Resolver]):

    # Produce a combined set of property states, starting with inputs and then applying
    # outputs.  If the same property exists in the inputs and outputs states, the output wins.
    all_properties = {}
    # Get the resource's output types, so we can convert dicts from the engine into actual
    # instantiated output types as needed.
    types = _output_types(type(res))
    for key, value in deserialize_properties(outputs).items():
        # Outputs coming from the provider are NOT translated. Do so here.
        translated_key = res.translate_output_property(key)
        translated_value = translate_output_properties(res, value, types.get(key))
        log.debug(f"incoming output property translated: {key} -> {translated_key}")
        log.debug(f"incoming output value translated: {value} -> {translated_value}")
        all_properties[translated_key] = translated_value

    if not settings.is_dry_run() or settings.is_legacy_apply_enabled():
        for key, value in list(serialized_props.items()):
            translated_key = res.translate_output_property(key)
            if translated_key not in all_properties:
                # input prop the engine didn't give us a final value for.Just use the value passed into the resource by
                # the user.
                all_properties[translated_key] = translate_output_properties(res, deserialize_property(value), types.get(key))

    for key, value in all_properties.items():
        # Skip "id" and "urn", since we handle those specially.
        if key in ["id", "urn"]:
            continue

        # Otherwise, unmarshal the value, and store it on the resource object.
        log.debug(f"looking for resolver using translated name {key}")
        resolve = resolvers.get(key)
        if resolve is None:
            # engine returned a property that was not in our initial property-map.  This can happen
            # for outputs that were registered through direct calls to 'registerOutputs'. We do
            # *not* want to do anything with these returned properties.  First, the component
            # resources that were calling 'registerOutputs' will have already assigned these fields
            # directly on them themselves.  Second, if we were to try to assign here we would have
            # an incredibly bad race condition for two reasons:
            #
            #  1. This call to 'resolveProperties' happens asynchronously at some point far after
            #     the resource was constructed.  So the user will have been able to observe the
            #     initial value up until we get to this point.
            #
            #  2. The component resource will have often assigned a value of some arbitrary type
            #     (say, a 'string').  If we overwrite this with an `Output<string>` we'll be changing
            #     the type at some non-deterministic point in the future.
            continue

        # Secrets are passed back as object with our special signiture key set to _special_secret_sig, in this case
        # we have to unwrap the object to get the actual underlying value.
        is_secret = False
        if isinstance(value, dict) and _special_sig_key in value and value[_special_sig_key] == _special_secret_sig:
            is_secret = True
            value = value["value"]

        # If either we are performing a real deployment, or this is a stable property value, we
        # can propagate its final value.  Otherwise, it must be undefined, since we don't know
        # if it's final.
        if not settings.is_dry_run():
            # normal 'pulumi up'.  resolve the output with the value we got back
            # from the engine.  That output can always run its .apply calls.
            resolve(value, True, is_secret, None)
        else:
            # We're previewing. If the engine was able to give us a reasonable value back,
            # then use it. Otherwise, inform the Output that the value isn't known.
            resolve(value, value is not None, is_secret, None)

    # `allProps` may not have contained a value for every resolver: for example, optional outputs may not be present.
    # We will resolve all of these values as `None`, and will mark the value as known if we are not running a
    # preview.
    for key, resolve in resolvers.items():
        if key not in all_properties:
            resolve(None, not settings.is_dry_run(), False, None)


def resolve_outputs_due_to_exception(resolvers: Dict[str, Resolver], exn: Exception):
    """
    Resolves all outputs with resolvers exceptionally, using the given exception as the reason why the resolver has
    failed to resolve.

    :param resolvers: Resolvers associated with a resource's outputs.
    :param exn: The exception that occured when trying (and failing) to create this resource.
    """
    for key, resolve in resolvers.items():
        log.debug(f"sending exception to resolver for {key}")
        resolve(None, False, False, exn)
