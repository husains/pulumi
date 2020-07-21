# Copyright 2016-2020, Pulumi Corporation.
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

import unittest
from typing import Dict, List, Optional

from pulumi.runtime import rpc
from pulumi.output import Output, output_type, output_property


camel_case_to_snake_case = {
    "firstArg": "first_arg",
    "secondArg": "second_arg",
}


class FakeCustomResource:
    """
    Fake CustomResource class that duck-types to the real CustomResource.
    This class is substituted for the real CustomResource for the below test.
    """
    def __init__(self, id):
        self.id = id

    def translate_output_property(self, prop: str) -> str:
        return camel_case_to_snake_case.get(prop) or prop


@output_type
class Foo(dict):
    first_arg: str = output_property("firstArg")
    second_arg: float = output_property("secondArg")

    def _translate_property(self, prop: str) -> str:
        return camel_case_to_snake_case.get(prop) or prop


@output_type
class Bar(dict):
    third_arg: Foo = output_property("thirdArg")
    third_optional_arg: Optional[Foo] = output_property("thirdOptionalArg")

    fourth_arg: Dict[str, Foo] = output_property("fourthArg")
    fourth_optional_arg: Dict[str, Optional[Foo]] = output_property("fourthOptionalArg")

    fifth_arg: List[Foo] = output_property("fifthArg")
    fifth_optional_arg: List[Optional[Foo]] = output_property("fifthOptionalArg")

    sixth_arg: Dict[str, List[Foo]] = output_property("sixthArg")
    sixth_optional_arg: Dict[str, Optional[List[Foo]]] = output_property("sixthOptionalArg")
    sixth_optional_optional_arg: Dict[str, Optional[List[Optional[Foo]]]] = output_property("sixthOptionalOptionalArg")

    seventh_arg: List[Dict[str, Foo]] = output_property("seventhArg")
    seventh_optional_arg: List[Optional[Dict[str, Foo]]] = output_property("seventhOptionalArg")
    seventh_optional_optional_arg: List[Optional[Dict[str, Optional[Foo]]]] = output_property("seventhOptionalOptionalArg")

    eighth_arg: List[Dict[str, List[Foo]]] = output_property("eighthArg")
    eighth_optional_arg: List[Optional[Dict[str, List[Foo]]]] = output_property("eighthOptionalArg")
    eighth_optional_optional_arg: List[Optional[Dict[str, Optional[List[Foo]]]]] = output_property("eighthOptionalOptionalArg")
    eighth_optional_optional_optional_arg: List[Optional[Dict[str, Optional[List[Optional[Foo]]]]]] = output_property("eighthOptionalOptionalOptionalArg")

    def _translate_property(self, prop: str) -> str:
        return camel_case_to_snake_case.get(prop) or prop


class TranslateOutputPropertiesTests(unittest.TestCase):
    def test_translate(self):
        res = FakeCustomResource("fake")
        output = {
            "firstArg": "hello",
            "secondArg": 42,
        }
        result = rpc.translate_output_properties(res, output, Foo) # type: ignore
        self.assertIsInstance(result, Foo)
        self.assertEqual(result.first_arg, "hello")
        self.assertEqual(result["first_arg"], "hello")
        self.assertEqual(result.second_arg, 42)
        self.assertEqual(result["second_arg"], 42)

    def test_nested_types(self):
        def assertFoo(val, first_arg, second_arg):
            self.assertIsInstance(val, Foo)
            self.assertEqual(val.first_arg, first_arg)
            self.assertEqual(val["first_arg"], first_arg)
            self.assertEqual(val.second_arg, second_arg)
            self.assertEqual(val["second_arg"], second_arg)

        res = FakeCustomResource("fake")
        output = {
            "thirdArg": {
                "firstArg": "hello",
                "secondArg": 42,
            },
            "thirdOptionalArg": {
                "firstArg": "hello-opt",
                "secondArg": 142,
            },
            "fourthArg": {
                "foo": {
                    "firstArg": "hi",
                    "secondArg": 41,
                },
            },
            "fourthOptionalArg": {
                "foo": {
                    "firstArg": "hi-opt",
                    "secondArg": 141,
                },
            },
            "fifthArg": [{
                "firstArg": "bye",
                "secondArg": 40,
            }],
            "fifthOptionalArg": [{
                "firstArg": "bye-opt",
                "secondArg": 140,
            }],
            "sixthArg": {
                "bar": [{
                    "firstArg": "goodbye",
                    "secondArg": 39,
                }],
            },
            "sixthOptionalArg": {
                "bar": [{
                    "firstArg": "goodbye-opt",
                    "secondArg": 139,
                }],
            },
            "sixthOptionalOptionalArg": {
                "bar": [{
                    "firstArg": "goodbye-opt-opt",
                    "secondArg": 1139,
                }],
            },
            "seventhArg": [{
                "baz": {
                    "firstArg": "adios",
                    "secondArg": 38,
                },
            }],
            "seventhOptionalArg": [{
                "baz": {
                    "firstArg": "adios-opt",
                    "secondArg": 138,
                },
            }],
            "seventhOptionalOptionalArg": [{
                "baz": {
                    "firstArg": "adios-opt-opt",
                    "secondArg": 1138,
                },
            }],
            "eighthArg": [{
                "blah": [{
                    "firstArg": "farewell",
                    "secondArg": 37,
                }],
            }],
            "eighthOptionalArg": [{
                "blah": [{
                    "firstArg": "farewell-opt",
                    "secondArg": 137,
                }],
            }],
            "eighthOptionalOptionalArg": [{
                "blah": [{
                    "firstArg": "farewell-opt-opt",
                    "secondArg": 1137,
                }],
            }],
            "eighthOptionalOptionalOptionalArg": [{
                "blah": [{
                    "firstArg": "farewell-opt-opt-opt",
                    "secondArg": 11137,
                }],
            }],
        }
        result = rpc.translate_output_properties(res, output, Bar) # type: ignore
        self.assertIsInstance(result, Bar)

        self.assertIs(result.third_arg, result["thirdArg"])
        assertFoo(result.third_arg, "hello", 42)
        self.assertIs(result.third_optional_arg, result["thirdOptionalArg"])
        assertFoo(result.third_optional_arg, "hello-opt", 142)

        self.assertIs(result.fourth_arg, result["fourthArg"])
        assertFoo(result.fourth_arg["foo"], "hi", 41)
        self.assertIs(result.fourth_optional_arg, result["fourthOptionalArg"])
        assertFoo(result.fourth_optional_arg["foo"], "hi-opt", 141)

        self.assertIs(result.fifth_arg, result["fifthArg"])
        assertFoo(result.fifth_arg[0], "bye", 40)
        self.assertIs(result.fifth_optional_arg, result["fifthOptionalArg"])
        assertFoo(result.fifth_optional_arg[0], "bye-opt", 140)

        self.assertIs(result.sixth_arg, result["sixthArg"])
        assertFoo(result.sixth_arg["bar"][0], "goodbye", 39)
        self.assertIs(result.sixth_optional_arg, result["sixthOptionalArg"])
        assertFoo(result.sixth_optional_arg["bar"][0], "goodbye-opt", 139)
        self.assertIs(result.sixth_optional_optional_arg, result["sixthOptionalOptionalArg"])
        assertFoo(result.sixth_optional_optional_arg["bar"][0], "goodbye-opt-opt", 1139)

        self.assertIs(result.seventh_arg, result["seventhArg"])
        assertFoo(result.seventh_arg[0]["baz"], "adios", 38)
        self.assertIs(result.seventh_optional_arg, result["seventhOptionalArg"])
        assertFoo(result.seventh_optional_arg[0]["baz"], "adios-opt", 138)
        self.assertIs(result.seventh_optional_optional_arg, result["seventhOptionalOptionalArg"])
        assertFoo(result.seventh_optional_optional_arg[0]["baz"], "adios-opt-opt", 1138)

        self.assertIs(result.eighth_arg, result["eighthArg"])
        assertFoo(result.eighth_arg[0]["blah"][0], "farewell", 37)
        self.assertIs(result.eighth_optional_arg, result["eighthOptionalArg"])
        assertFoo(result.eighth_optional_arg[0]["blah"][0], "farewell-opt", 137)
        self.assertIs(result.eighth_optional_optional_arg, result["eighthOptionalOptionalArg"])
        assertFoo(result.eighth_optional_optional_arg[0]["blah"][0], "farewell-opt-opt", 1137)
        self.assertIs(result.eighth_optional_optional_optional_arg, result["eighthOptionalOptionalOptionalArg"])
        assertFoo(result.eighth_optional_optional_optional_arg[0]["blah"][0], "farewell-opt-opt-opt", 11137)