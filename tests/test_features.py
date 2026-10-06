from features import extract_features


def test_ip_host_is_flagged():
    feats = extract_features("http://203.0.113.10/login")
    assert feats["is_ip"] == 1
    assert feats["is_https"] == 0


def test_brand_in_subdomain():
    feats = extract_features("http://paypal.com.secure-login.com/verify")
    assert feats["brand_in_subdomain"] == 1

def test_no_brand_in_subdomain():
    feats = extract_features("http://paypal.com/verify")
    assert feats["brand_in_subdomain"] == 0

def test_real_brand_domain_is_not_subdomain_trick():
    feats = extract_features("https://www.paypal.com/signin")
    assert feats["brand_in_subdomain"] == 0
    assert feats["is_https"] == 1

def test_punycode():
    feats = extract_features("https://xn--pypal-4ve.com/account")
    assert feats["has_punycode"] == 1

def test_no_punycode():
    feats = extract_features("https://pypal-4ve.com/account")
    assert feats["has_punycode"] == 0