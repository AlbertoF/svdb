import unittest

from id.cpe import CPEID


class CPETestCase(unittest.TestCase):
    
    def test_cpe_creation(self):
        _str = ('a', 'microsoft', 'ie', '8.0.7600.16385')
        self.assertTrue(isinstance(CPEID(*_str), CPEID))
        
    def test_cpe_creation_fail(self):
        _str = ('a', '!microsoft', 'ie', '8.0.7600.16385')
        self.assertRaises(ValueError, CPEID, *_str)
        
    def test_cpe_creation_from_string(self):
        _str = "cpe:/a:microsoft:ie:8.0.7600.16385"
        self.assertTrue(isinstance(CPEID.from_string(_str), CPEID))
        
    def test_cpe_creation_from_string_fail(self):
        _str = "cpe:/a:microsoft!:ie:8.0.7600.16385"
        self.assertRaises(ValueError, CPEID.from_string, _str)
    
    def test_cpe_equal_param(self):
        cpe_str = ('a', 'microsoft', 'ie', '8.0.7600.16385','32','1','0')
        cpe = CPEID(*cpe_str)
        self.assertEqual(cpe.get_type_info(), 'a')
        self.assertEqual(cpe.get_vendor_info(), 'microsoft')
        self.assertEqual(cpe.get_product_info(), 'ie')
        self.assertEqual(cpe.get_version_info(), '8.0.7600.16385')
        self.assertEqual(cpe.get_update_info(), '32')
        self.assertEqual(cpe.get_edition_info(), '1')
        self.assertEqual(cpe.get_language_info(), '0')
        
    def test_cpe_equal_param_from_string(self):
        cpe_str = "cpe:/a:microsoft:ie:8.0.7600.16385:32:1:0"              
        cpe = CPEID.from_string(cpe_str)
        self.assertEqual(cpe.get_type_info(), 'a')
        self.assertEqual(cpe.get_vendor_info(), 'microsoft')
        self.assertEqual(cpe.get_product_info(), 'ie')
        self.assertEqual(cpe.get_version_info(), '8.0.7600.16385')
        self.assertEqual(cpe.get_update_info(), '32')
        self.assertEqual(cpe.get_edition_info(), '1')
        self.assertEqual(cpe.get_language_info(), '0')
        self.assertEqual(str(cpe), cpe_str)

    def test_cpe_equal(self):
        cpe_param = ('a', 'microsoft', 'ie', '8.0.7600.16385')
        cpe_str = "cpe:/" + ":".join(cpe_param)
        cpe1 = CPEID.from_string(cpe_str)
        cpe2 = CPEID(*cpe_param)
        self.assertEqual(cpe1, cpe2)
        
    def test_cpe_base_equal(self):
        cpe_str = ('a', 'microsoft', 'ie', '8.0.7600.16385','32','1','0')
        cpe = CPEID(*cpe_str)
        self.assertEqual(cpe.get_base(), "cpe:/a:microsoft:ie")
        
    def test_cpe_base_equal_from_string(self):
        cpe_str = "cpe:/a:microsoft:ie:8.0.7600.16385:124124:wqe:ewqewq"
        cpe = CPEID.from_string(cpe_str)
        self.assertEqual(cpe.get_base(), "cpe:/a:microsoft:ie")
        
    def test_cpe_metod_of_equality(self):
        cpe_str = "cpe:/a:microsoft:ie"
        self.assertTrue(CPEID.from_string(cpe_str)==CPEID.from_string(cpe_str))
        
    def test_cpe_creation_true(self):
        cpe_str = "cpe:/a:microsoft:ie:8.0.7600.16385"
        self.assertTrue(CPEID.correct_cpe_str(cpe_str))
        cpe_str = "cpe:/a:microsoft-:ie:8.0.7600.16385"
        self.assertTrue(CPEID.correct_cpe_str(cpe_str))
        cpe_str = "cpe:/a:---microsoft---:ie:8.0.7600.16385"
        self.assertTrue(CPEID.correct_cpe_str(cpe_str))
        cpe_str = "cpe:/a:~microsoft-:ie~:8.0.7600.16385"
        self.assertTrue(CPEID.correct_cpe_str(cpe_str))
        cpe_str = "cpe:/a:microsoft.~-%:ie%:8.0.7600.16385"
        self.assertTrue(CPEID.correct_cpe_str(cpe_str))
        
    def test_cpe_creation_failture(self):
        cpe_str = "CE:/a:microsoft:ie:8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/A:microsoft:ie:8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/a::ie:8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/a:microsoft::8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/aa:microsoft::8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:a:microsoft::8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe//a:microsoft::8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/a::ie:8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/a-:microsoft:ie:ie"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/:microsoft:ie:ie"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/a:microsoft!:ie:ie"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID.from_string, cpe_str)
        cpe_str = 32
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))
        self.assertRaises(TypeError, CPEID.from_string, cpe_str)
        cpe_str = CPEID
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))
        self.assertRaises(TypeError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/a:microsoft:","ie"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))
        self.assertRaises(TypeError, CPEID.from_string, cpe_str)
        cpe_str = "cpe:/a:microsoft:ie",":ie"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))
        self.assertRaises(TypeError, CPEID.from_string, *cpe_str)


if __name__ == "__main__":
    unittest.main()