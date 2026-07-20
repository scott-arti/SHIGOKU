import pytest
from aiohttp import web

from src.core.preflight.auth_probe import AuthProbe
from src.core.preflight.models import AuthClassification


@pytest.mark.asyncio
async def test_relative_redirect_login_page_is_classified_as_login_page():
    async def root(_request):
        raise web.HTTPFound("login.php")

    async def login(_request):
        return web.Response(
            text=(
                "<html><title>Login</title>"
                "<form><input type='password' name='password'></form></html>"
            ),
            content_type="text/html",
        )

    app = web.Application()
    app.router.add_get("/", root)
    app.router.add_get("/login.php", login)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 4291)
    await site.start()

    try:
        probe = AuthProbe()
        result = await probe._do_probe(
            "http://127.0.0.1:4291/",
            cookies={},
            bearer_token="",
            auth_headers={},
            auth_required=False,
        )
    finally:
        await runner.cleanup()

    assert result.classification == AuthClassification.LOGIN_PAGE
    assert result.status_code == 200
    assert result.probed_url.endswith("/login.php")
    assert result.redirect_chain[0]["location"] == "login.php"


@pytest.mark.asyncio
async def test_authenticated_page_beats_generic_challenge_words():
    async def home(_request):
        return web.Response(
            text=(
                "<html><title>Welcome :: DVWA</title>"
                "<body>"
                "<a href='logout.php'>Logout</a>"
                "<p>Welcome admin</p>"
                "<li>Insecure CAPTCHA</li>"
                "<p>More difficult challenges are available in other projects.</p>"
                "</body></html>"
            ),
            content_type="text/html",
        )

    app = web.Application()
    app.router.add_get("/", home)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 4292)
    await site.start()

    try:
        probe = AuthProbe()
        result = await probe._do_probe(
            "http://127.0.0.1:4292/",
            cookies={},
            bearer_token="",
            auth_headers={},
            auth_required=False,
        )
    finally:
        await runner.cleanup()

    assert result.classification == AuthClassification.AUTHENTICATED
    assert result.has_challenge is True
    assert "logout" in result.body_markers
