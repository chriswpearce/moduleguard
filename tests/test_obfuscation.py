"""Scope-aware source obfuscation behavior."""

import inspect
import re

from moduleguard.obfuscation import obfuscate_source


def _execute(source):
    namespace = {"__name__": "sample"}
    exec(compile(source, "sample.py", "exec"), namespace)
    return namespace


def test_comments_and_internal_locals_are_obfuscated_but_public_api_is_stable():
    source = '''
"""Confidential module description."""
# confidential pricing explanation
MODULE_TOTAL = 0

class PriceCalculator:
    """Confidential class description."""
    def calculate(self, base):
        """Confidential method description."""
        internal_multiplier = 2  # private implementation note
        return base * internal_multiplier

def calculate_price(base, tax=0.2):
    """Confidential function description."""
    global MODULE_TOTAL
    internal_subtotal = base * (1 + tax)
    MODULE_TOTAL = internal_subtotal

    captured_adjustment = 3
    def apply_adjustment(value):
        nonlocal captured_adjustment
        captured_adjustment += 1
        nested_result = value + captured_adjustment
        return nested_result

    selected_values = [item * internal_subtotal for item in range(3) if item]
    try:
        import math as internal_math
        final_result = apply_adjustment(selected_values[-1]) + internal_math.floor(0.9)
    except ArithmeticError as internal_error:
        final_result = len(str(internal_error))
    return final_result
'''
    obfuscated = obfuscate_source(source, "pricing_rules.py")
    original = _execute(source)
    protected = _execute(obfuscated)

    assert "#" not in obfuscated
    assert "Confidential" not in obfuscated
    for internal_name in (
        "internal_multiplier",
        "internal_subtotal",
        "captured_adjustment",
        "selected_values",
        "internal_math",
        "internal_error",
        "final_result",
        "nested_result",
        "item",
        "base",
        "self",
    ):
        assert internal_name not in obfuscated
    assert "tax" in obfuscated
    assert re.search(r"\b[Il]{49}\b", obfuscated)

    assert "calculate_price" in protected
    assert "PriceCalculator" in protected
    assert protected.get("__doc__") is None
    assert protected["PriceCalculator"].__doc__ is None
    assert protected["calculate_price"].__doc__ is None
    assert str(inspect.signature(protected["calculate_price"])) != str(
        inspect.signature(original["calculate_price"])
    )
    assert protected["calculate_price"](10, tax=0.1) == original["calculate_price"](
        10, tax=0.1
    )
    assert protected["MODULE_TOTAL"] == original["MODULE_TOTAL"]
    assert protected["PriceCalculator"]().calculate(4) == 8


def test_locals_reflection_disables_renaming_for_that_scope():
    source = '''
def public_function(value):
    reflected_local = value + 1
    return sorted(locals()), reflected_local
'''
    obfuscated = obfuscate_source(source)
    namespace = _execute(obfuscated)

    assert "reflected_local" in obfuscated
    names, result = namespace["public_function"](4)
    assert names == ["reflected_local", "value"]
    assert result == 5


def test_obfuscation_is_deterministic_for_the_same_source():
    source = "def public(value):\n    internal_value = value + 1\n    return internal_value\n"
    assert obfuscate_source(source) == obfuscate_source(source)


def test_keyword_only_parameter_name_is_preserved():
    source = '''
def public_function(positional_value, *, named_value=2):
    return positional_value * named_value
'''
    obfuscated = obfuscate_source(source)
    namespace = _execute(obfuscated)

    assert "positional_value" not in obfuscated
    assert "named_value" in obfuscated
    assert namespace["public_function"](3, named_value=4) == 12


def test_defaulted_parameter_name_is_preserved_for_keyword_calls():
    source = '''
def public_function(required_value, optional_value=2):
    return required_value * optional_value
'''
    obfuscated = obfuscate_source(source)
    namespace = _execute(obfuscated)

    assert "required_value" not in obfuscated
    assert "optional_value" in obfuscated
    assert namespace["public_function"](3, optional_value=4) == 12


def test_dotted_import_and_enclosing_class_lookup_keep_their_behavior():
    source = '''
def public():
    import xml.etree
    outer_value = 7
    class InternalClass:
        before_assignment = outer_value
    return xml.etree.__name__, InternalClass.before_assignment
'''
    original = _execute(source)
    protected = _execute(obfuscate_source(source))
    assert protected["public"]() == original["public"]()