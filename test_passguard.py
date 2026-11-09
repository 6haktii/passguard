"""Unit tests for PassGuard. Run with:  python -m unittest -v"""

import hashlib
import string
import unittest

import passguard


class TestStrength(unittest.TestCase):

    def test_common_password_is_very_weak(self):
        result = passguard.analyze_password("password123")
        self.assertEqual(result["score"], 0)

    def test_strong_password_scores_high(self):
        result = passguard.analyze_password("T7#vLm!q9Zr@w2Kp")
        self.assertGreaterEqual(result["score"], 3)

    def test_short_password_is_capped(self):
        result = passguard.analyze_password("Xy#9")
        self.assertLessEqual(result["score"], 1)

    def test_empty_password_has_zero_entropy(self):
        self.assertEqual(passguard.calculate_entropy(""), 0.0)

    def test_sequence_detection(self):
        self.assertTrue(passguard.has_sequence("xx123yy"))
        self.assertTrue(passguard.has_sequence("zcbaz"))
        self.assertFalse(passguard.has_sequence("a1b2c3"))

    def test_repeat_detection(self):
        self.assertTrue(passguard.has_repeats("heyyyy"))
        self.assertFalse(passguard.has_repeats("hello"))

    def test_year_detection(self):
        self.assertTrue(passguard.has_year("Bhakti@2006"))
        self.assertFalse(passguard.has_year("Tiger#77xq"))

    def test_keyboard_pattern_detection(self):
        self.assertTrue(passguard.has_keyboard_pattern("myqwerpass"))
        self.assertTrue(passguard.has_keyboard_pattern("fdsa99"))
        self.assertFalse(passguard.has_keyboard_pattern("T7#vLm!q9Zr"))


class TestBreachCheckParsing(unittest.TestCase):

    def test_suffix_found_in_response(self):
        sha1 = hashlib.sha1(b"password").hexdigest().upper()
        suffix = sha1[5:]
        fake_body = f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:10434004\r\n"
        self.assertEqual(passguard.count_in_range_response(fake_body, suffix), 10434004)

    def test_suffix_not_found(self):
        fake_body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
        self.assertEqual(passguard.count_in_range_response(fake_body, "ABCDEF"), 0)


class TestGenerator(unittest.TestCase):

    def test_length(self):
        self.assertEqual(len(passguard.generate_password(20)), 20)

    def test_contains_every_character_type(self):
        pwd = passguard.generate_password(12)
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))
        self.assertTrue(any(c in string.punctuation for c in pwd))

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            passguard.generate_password(5)

    def test_passwords_are_different(self):
        self.assertNotEqual(passguard.generate_password(), passguard.generate_password())


if __name__ == "__main__":
    unittest.main()
