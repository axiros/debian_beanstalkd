import pytest
import random
import beanstalkc


@pytest.fixture(scope="session")
def con(request):
    _con = beanstalkc.Connection()
    tube = "test-%d" % random.randint(0, 2**32-1)

    _con.watch(tube)
    _con.ignore('default')
    _con.use(tube)

    def unwatch():
        _con.ignore(tube)

    request.addfinalizer(unwatch)
    return _con

def test_tubes(con):
    assert 'default' in con.tubes()

def test_job(con):
    assert con.peek_ready() is None
    body = "test job"
    con.put(body)
    job = con.reserve()
    job_body = job.body
    job.delete()
    assert job_body == body
