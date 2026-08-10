import unittest
from argus.core.mission import Mission
from argus.intelligence.models import APIEndpoint
from argus.intelligence.business import BusinessObjectAnalyzer

class TestBusinessObjectAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = BusinessObjectAnalyzer()
        self.mission = Mission(target="example.com")

    def test_empty_input(self):
        self.analyzer.analyze(self.mission)
        self.assertEqual(len(self.mission.business_objects), 0)

    def test_grouping_endpoints(self):
        self.mission.api_intelligence = [
            APIEndpoint(method="GET", path="/users", resource="users", operation="READ", business_object="User"),
            APIEndpoint(method="POST", path="/users", resource="users", operation="CREATE", business_object="User"),
        ]
        
        self.analyzer.analyze(self.mission)
        
        self.assertEqual(len(self.mission.business_objects), 1)
        bo = self.mission.business_objects[0]
        self.assertEqual(bo.name, "User")
        self.assertEqual(len(bo.endpoints), 2)

    def test_crud_detection(self):
        self.mission.api_intelligence = [
            APIEndpoint(method="GET", path="/users", resource="users", operation="READ", business_object="User"),
            APIEndpoint(method="POST", path="/users", resource="users", operation="CREATE", business_object="User"),
            APIEndpoint(method="PUT", path="/users/1", resource="users", operation="UPDATE", business_object="User"),
            APIEndpoint(method="DELETE", path="/users/1", resource="users", operation="DELETE", business_object="User"),
        ]
        
        self.analyzer.analyze(self.mission)
        
        bo = self.mission.business_objects[0]
        self.assertEqual(bo.operations, {"READ", "CREATE", "UPDATE", "DELETE"})

    def test_multiple_resources(self):
        self.mission.api_intelligence = [
            APIEndpoint(method="GET", path="/users", resource="users", operation="READ", business_object="User"),
            APIEndpoint(method="POST", path="/organizations", resource="organizations", operation="CREATE", business_object="Organization"),
        ]
        
        self.analyzer.analyze(self.mission)
        
        self.assertEqual(len(self.mission.business_objects), 2)
        
        names = {bo.name for bo in self.mission.business_objects}
        self.assertEqual(names, {"User", "Organization"})

if __name__ == "__main__":
    unittest.main()
