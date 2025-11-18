from utils.http import contains_reflected_payload, has_csrf_token

def test_xss_reflection():
    payload = "<svg/onload=alert(1)>"
    html = f"<html><body>resultado: {payload}</body></html>"
    assert contains_reflected_payload(html, payload)

def test_csrf_token_detection():
    inputs = [{"name":"authenticity_token"}, {"name":"email"}]
    assert has_csrf_token(inputs)
