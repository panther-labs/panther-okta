from panther_config import testing
from panther_okta.rules.improbable_access import geo_improbable_access_filter


class TestGIAFilters(testing.PantherPythonFilterTestCase):
    def test_geo_improbable_access_filter_valid(self) -> None:
        f = geo_improbable_access_filter()
        self.assertFilterIsValid(f)
