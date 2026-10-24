"""
Health tests for ForgeEntropy.
Built by Mourad.Soltani
"""
import unittest
from forgeentropy.cli import calculate_entropy, generate_secret, audit_secret

class TestForgeEntropy(unittest.TestCase):
    def test_entropy_empty(self):
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_entropy_simple(self):
        ent = calculate_entropy("aaaa")
        self.assertLess(ent, 1.0)  # low entropy

    def test_generate_length(self):
        s = generate_secret(16, "alnum")
        self.assertEqual(len(s), 16)
        self.assertTrue(all(c.isalnum() for c in s))

    def test_audit_policy(self):
        weak = "password123"
        result = audit_secret(weak, min_entropy=50)
        self.assertFalse(result["meets_policy"])

        strong = generate_secret(32)
        result = audit_secret(strong, min_entropy=100)
        self.assertTrue(result["meets_policy"])
        self.assertGreater(result["entropy_bits"], 100)

    def test_crack_time(self):
        from forgeentropy.cli import estimate_crack_time
        self.assertIsInstance(estimate_crack_time(10), str)

if __name__ == "__main__":
    unittest.main()
