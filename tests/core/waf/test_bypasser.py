from src.core.attack.waf_mutator import MutationType
from src.core.waf.bypasser import WAFBypasser


def test_build_bypass_headers_rotates_by_attempt():
    bypasser = WAFBypasser()

    h1 = bypasser.build_bypass_headers("cloudflare", attempt=0)
    h2 = bypasser.build_bypass_headers("cloudflare", attempt=1)

    assert isinstance(h1, dict)
    assert isinstance(h2, dict)
    assert h1 != h2


def test_choose_mutation_types_for_known_waf():
    bypasser = WAFBypasser()
    types = bypasser.choose_mutation_types("aws_waf")

    assert MutationType.ENCODE in types
    assert len(types) >= 3


def test_choose_mutation_types_generic_fallback():
    bypasser = WAFBypasser()
    types = bypasser.choose_mutation_types(None)

    assert MutationType.ENCODE in types
    assert MutationType.CASE in types

