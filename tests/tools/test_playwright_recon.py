from src.tools.custom.playwright_recon import PlaywrightCrawler


def test_score_post_login_route_prefers_stateful_paths():
    crawler = PlaywrightCrawler()
    high_value = crawler._score_post_login_route("https://app.example.com/account/settings")
    low_value = crawler._score_post_login_route("https://app.example.com/static/js/app.js")
    assert high_value > 0
    assert low_value <= 0


def test_score_post_login_route_penalizes_logout_paths():
    crawler = PlaywrightCrawler()
    assert crawler._score_post_login_route("https://app.example.com/logout") <= 0
    assert crawler._score_post_login_route("https://app.example.com/signout") <= 0


def test_score_post_login_route_prioritizes_security_area():
    crawler = PlaywrightCrawler()
    security = crawler._score_post_login_route("https://app.example.com/account/security")
    generic = crawler._score_post_login_route("https://app.example.com/help")
    assert security > generic
