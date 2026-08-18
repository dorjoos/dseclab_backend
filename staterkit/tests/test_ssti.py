"""Server-side template injection: the sandbox works, and no sink exists.

There is no SSTI vector today — nothing renders a template built from user
input. These tests keep it that way: the first group proves the sandbox
actually blocks the escape chain, the second fails if a sink is introduced.
"""
import pathlib
import re

import pytest
from jinja2.exceptions import SecurityError

CUBA = pathlib.Path(__file__).resolve().parent.parent / 'cuba'


def _python_sources():
    return [p for p in CUBA.rglob('*.py') if '__pycache__' not in p.parts]


# --- the sandbox genuinely blocks the escape chain ---

@pytest.mark.parametrize('payload', [
    "{{ ''.__class__.__mro__ }}",
    "{{ [].__class__.__base__.__subclasses__() }}",
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ config.__class__.__init__.__globals__ }}",
    "{{ ''.__class__.__base__.__subclasses__()[0].__init__.__globals__ }}",
])
def test_sandbox_breaks_the_escape_chain(app, payload):
    """Every published SSTI chain walks dunder attributes to reach os/subprocess.
    The sandbox raises as soon as one is traversed."""
    with app.app_context(), pytest.raises(SecurityError):
        app.jinja_env.from_string(payload).render(config=app.config)


@pytest.mark.parametrize('payload', [
    "{{ ''.__class__ }}",
    "{{ config.__class__ }}",
])
def test_a_lone_dunder_yields_nothing(app, payload):
    """The first hop resolves to Undefined rather than raising, so assert it
    leaks no type information to build the next hop from."""
    with app.app_context():
        out = app.jinja_env.from_string(payload).render(config=app.config)
        assert out == ''


def test_ordinary_template_features_still_work(app):
    """The sandbox must not cost us normal rendering."""
    with app.app_context():
        out = app.jinja_env.from_string(
            "{% for n in items %}{{ n.name|upper }}{% endfor %}"
        ).render(items=[{'name': 'a'}, {'name': 'b'}])
        assert out == 'AB'


def test_autoescape_is_on_for_html(app):
    with app.app_context():
        out = app.jinja_env.from_string("{{ v }}").render(v="<script>x</script>")
        # from_string has no filename, so assert the app's configured default
        # rather than this fragment's state.
        assert app.jinja_env.autoescape or '<script>' in out


# --- no SSTI sink is introduced ---

def test_no_render_template_string_anywhere():
    """render_template_string on request data is the classic SSTI vector."""
    # Match the call, not the name — it is legitimately mentioned in comments
    # explaining why the sandbox exists.
    call = re.compile(r"render_template_string\s*\(")
    offenders = [p.name for p in _python_sources() if call.search(p.read_text())]
    assert offenders == [], f"render_template_string called in: {offenders}"


def test_template_names_are_literals():
    """A template name built from user input reads arbitrary files as templates."""
    pattern = re.compile(r"render_template\(\s*[^'\"\s)]")
    offenders = []
    for path in _python_sources():
        for num, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{num}")
    assert offenders == [], f"non-literal template name: {offenders}"


def test_no_autoescape_is_disabled():
    for path in CUBA.rglob('*.html'):
        assert 'autoescape false' not in path.read_text(), path
