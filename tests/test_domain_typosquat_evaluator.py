"""Unit tests for domain typosquatting evaluator."""

from cti_core.processors.domain_typosquat_evaluator import DomainTyposquatEvaluator, levenshtein_distance


def test_levenshtein_distance():
    assert levenshtein_distance("kitten", "sitting") == 3
    assert levenshtein_distance("apple", "apple") == 0
    assert levenshtein_distance("paypal", "paypaal") == 1


def test_typosquat_evaluation():
    # 1 edit from paypal
    is_squat, penalty, brand = DomainTyposquatEvaluator.evaluate("paypaal.com")
    assert is_squat is True
    assert penalty == 35.0
    assert brand == "paypal"

    # 1 edit from microsoft
    is_squat, penalty, brand = DomainTyposquatEvaluator.evaluate("microsft.net")
    assert is_squat is True
    assert penalty == 35.0
    assert brand == "microsoft"

    # Legitimate / Unrelated
    is_squat, penalty, brand = DomainTyposquatEvaluator.evaluate("cyberdefense-blog.io")
    assert is_squat is False
    assert penalty == 0.0
    assert brand is None
