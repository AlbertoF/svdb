import unittest

from id.cve import CVEID


class CVETestCase(unittest.TestCase):
    def test_cve_creation(self):
        _str = "cve", "2011", "0346"
        self.assertTrue(isinstance(CVEID(*_str), CVEID))
        
    def test_cve_creation_fail(self):
        _str = ('cve', '!microsoft', 'ie')
        self.assertRaises(ValueError, CVEID, *_str)
        
    def test_cve_creation_from_string(self):
        _str = "cve-2010-0111"
        self.assertTrue(isinstance(CVEID.from_string(_str), CVEID))
       
    def test_cve_creation_from_string_fail(self):
        _str = "cve-!2010-0111"
        self.assertRaises(ValueError, CVEID.from_string, _str)
    
    def test_cve_equal_param(self):
        cve_str = ('cve', '2011', '0001')
        cve = CVEID(*cve_str)
        self.assertEqual(cve.get_type(), 'cve')
        self.assertEqual(cve.get_year(), 2011)
        self.assertEqual(cve.get_num(), 1)
        self.assertEqual(cve.is_candidate(), False)
        
    def test_cve_equal_param_from_string(self):
        cve_str = "cve-2009-2123"              
        cve = CVEID.from_string(cve_str)
        self.assertEqual(cve.get_type(), 'cve')
        self.assertEqual(cve.get_year(), 2009)
        self.assertEqual(cve.get_num(), 2123)
        self.assertEqual(str(cve), cve_str)
        self.assertEqual(str(cve), cve.cve_str)

    def test_cve_equal(self):
        cve_param = ('cve', '2008', '123')
        cve_str = "-".join(cve_param)
        cve1 = CVEID.from_string(cve_str)
        cve2 = CVEID(*cve_param)
        self.assertEqual(cve1, cve2)
        self.assertEqual(str(cve1), str(cve2))
        self.assertEqual(cve1.cve_str, cve2.cve_str)
        
    def test_cve_metod_of_equality(self):
        cve_str = "cve-2003-999"
        self.assertTrue(CVEID.from_string(cve_str)==CVEID.from_string(cve_str))
        
    def test_cve_creation_true(self):
        cve_str = "cve-2007-92291"
        self.assertTrue(CVEID.correct_cve_str(cve_str))
        cve_str = "can-2007-1"
        self.assertTrue(CVEID.correct_cve_str(cve_str))
        cve_str = "can-2011-0"
        self.assertTrue(CVEID.correct_cve_str(cve_str))
        cve_str = "cve-2001-0"
        self.assertTrue(CVEID.correct_cve_str(cve_str))
        cve_str = "cve-2006-5"
        self.assertTrue(CVEID.correct_cve_str(cve_str))
        
    def test_cve_creation_failt(self):
        cve_str = "cv-2001-11"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve-16385"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve-200-102"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve2001-21"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cv2001-121"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve-000-1"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve/5"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve:7600-16385"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve-1-1"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve-2020.201"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = "cve:2010:121"
        self.assertFalse(CVEID.correct_cve_str(cve_str))   
        self.assertRaises(ValueError, CVEID.from_string, cve_str)
        cve_str = 32
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(TypeError, CVEID.from_string, cve_str)
        cve_str = CVEID
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(TypeError, CVEID.from_string, cve_str)
        cve_str = "cve-2011","32"
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(TypeError, CVEID.from_string, cve_str)
        cve_str = "cve-2011-20","12"
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(TypeError, CVEID.from_string, *cve_str)



    def test_cve_with_ignore_case(self):
        cve_str = "CVE-2011-0346"
        self.assertTrue(CVEID.correct_cve_str(cve_str, ignore_case=True))                
        self.assertTrue(CVEID.correct_cve_str("CAN-2011-0346", ignore_case=True)) 
        self.assertFalse(CVEID.correct_cve_str("xCVE-2011-0346", ignore_case=True)) 
        self.assertFalse(CVEID.correct_cve_str("xCAN-2011-0346", ignore_case=True)) 
        self.assertFalse(CVEID.correct_cve_str("CVE-2011-0346x", ignore_case=True)) 
        self.assertFalse(CVEID.correct_cve_str("CAN-2011-0346x", ignore_case=True))         
    
    def test_cve_candidate(self):
        cve_str = "can-2011-0346"
        cve = CVEID.from_string(cve_str)
        self.assertEqual(cve.get_year(), 2011)
        self.assertEqual(cve.is_candidate(), True)
        self.assertEqual(str(cve), cve_str)
        self.assertEqual(cve, CVEID.from_string(cve_str))
        self.assertNotEqual(cve, CVEID("cve","2010","0346"))

if __name__ == "__main__":
    unittest.main()