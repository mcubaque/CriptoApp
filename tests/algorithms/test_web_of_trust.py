from app.algorithms.pki import web_of_trust


def test_direct_trust_path():
    result = web_of_trust.evaluate_trust("Ana->Beto", "Ana", "Beto")
    assert result.output == "Ana → Beto"


def test_transitive_trust_path():
    result = web_of_trust.evaluate_trust("Ana->Beto, Beto->Carla, Carla->Dario", "Ana", "Dario")
    assert result.output == "Ana → Beto → Carla → Dario"


def test_no_path_found():
    result = web_of_trust.evaluate_trust("Ana->Beto, Xavier->Yolanda", "Ana", "Yolanda")
    assert result.output == "Sin camino de confianza"
    assert result.steps[-1].ok is False


def test_unparseable_edges_rejected():
    result = web_of_trust.evaluate_trust("esto no tiene el formato correcto", "Ana", "Beto")
    assert result.ok is False
