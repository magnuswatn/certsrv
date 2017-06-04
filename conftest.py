import pytest

def pytest_addoption(parser):
    parser.addoption("--adcs", action="store", default='localhost',
                     help="Active Directory Certificates Services server to use")
    parser.addoption("--username", action="store", help="Username for auth",
                     default="user")
    parser.addoption("--password", action="store", help="Password for auth",
                     default="password")
    parser.addoption("--template", action="store", help="Template to use",
                     default="WebServer")
    parser.addoption("--manual-template", action="store", help="Template with manual approval",
                     default="WebServer_Manual")

@pytest.fixture
def opt_adcs(request):
    return request.config.getoption("--adcs")

@pytest.fixture
def opt_username(request):
    return request.config.getoption("--username")

@pytest.fixture
def opt_password(request):
    return request.config.getoption("--password")

@pytest.fixture
def opt_template(request):
    return request.config.getoption("--template")

@pytest.fixture
def opt_mantemplate(request):
    return request.config.getoption("--manual-template")

