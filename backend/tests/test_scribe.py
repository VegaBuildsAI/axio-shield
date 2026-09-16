import pytest

from app.agents.scribe import Scribe
from app.store import Store


@pytest.fixture
def scribe(tmp_path):
    store = Store(str(tmp_path / "audit.db"))
    return Scribe(store)


async def test_chain_grows_and_verifies(scribe):
    await scribe.write(agent="SENTINEL", action="scored", subject_id="e1", payload={"score": 0.9})
    await scribe.write(agent="ORACLE", action="classified", subject_id="i1", payload={"owasp": "ASI02"})
    records = scribe.export()
    assert [r["seq"] for r in records] == [1, 2]
    assert records[1]["prev_hash"] == records[0]["hash"]
    ok, broken = scribe.verify_chain()
    assert ok is True and broken is None


async def test_tamper_breaks_chain(scribe):
    await scribe.write(agent="SENTINEL", action="scored", subject_id="e1", payload={"score": 0.9})
    await scribe.write(agent="ORACLE", action="classified", subject_id="i1", payload={"owasp": "ASI02"})
    # Manipular directamente la fila 1 en SQLite (simula alteración del log)
    scribe.store._conn.execute("UPDATE audit SET payload=? WHERE seq=1", ('{"score": 0.0}',))
    scribe.store._conn.commit()
    ok, broken = scribe.verify_chain()
    assert ok is False
    assert broken == 1
