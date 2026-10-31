import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
XSS_ROOT = os.path.join(ROOT, 'xssdetector')
for path in (ROOT, XSS_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from xssdetector.utils.char_sequence import VOCAB_SIZE, encode_texts
from xssdetector.utils.preprocess import (
    classify_injection_context,
    decode_recursive,
    generalize_tokens,
    preprocess_for_sequence_model,
    preprocess_input,
)


class PreprocessTest(unittest.TestCase):
    def test_recursive_url_decoding(self):
        encoded = '%253Cscript%253Ealert(1)%253C/script%253E'
        decoded = decode_recursive(encoded)
        self.assertIn('<script>', decoded.lower())
        self.assertNotIn('%3c', decoded.lower())

    def test_html_entity_decoding(self):
        decoded = decode_recursive('&lt;img src=x onerror=alert(1)&gt;')
        self.assertIn('<img', decoded.lower())

    def test_generalize_replaces_url_numbers_and_strings(self):
        raw = 'Visit https://evil.example/a?x=99 and alert("cookie")'
        generalized = generalize_tokens(raw)
        self.assertIn('http://website', generalized)
        self.assertNotIn('evil.example', generalized)
        self.assertIn('param_string', generalized)
        self.assertNotIn('cookie', generalized)
        self.assertIn('alert(param_string)', generalized)

    def test_sequence_preprocess_decodes_then_generalizes(self):
        encoded = '%3Cscript%3Ealert(12)%3C/script%3E'
        processed = preprocess_for_sequence_model(encoded)
        self.assertIn('<script>', processed)
        self.assertIn('alert(0)', processed)

    def test_injection_context_labels(self):
        self.assertEqual(classify_injection_context('<div>hello</div>'), 'html_body')
        self.assertEqual(classify_injection_context('<img src=x onerror=alert(1)>'), 'attribute')
        self.assertEqual(classify_injection_context('javascript:alert(1)'), 'uri')
        self.assertEqual(classify_injection_context('eval(document.cookie)'), 'js')

    def test_preprocess_input_exposes_new_fields(self):
        result = preprocess_input('%3Cscript%3Ealert("x")%3C/script%3E')
        self.assertTrue(result['was_decoded'])
        self.assertIn('<script>', result['decoded'])
        self.assertIn('param_string', result['generalized'])
        self.assertIn(result['injection_context'], {'html_body', 'attribute', 'js', 'uri'})

    def test_char_encoding_shape_and_vocab(self):
        matrix = encode_texts(['<script>', 'abc'], max_len=8)
        self.assertEqual(matrix.shape, (2, 8))
        self.assertTrue((matrix >= 0).all())
        self.assertTrue((matrix < VOCAB_SIZE).all())
        self.assertEqual(int(matrix[1, 3]), 0)


if __name__ == '__main__':
    unittest.main()
