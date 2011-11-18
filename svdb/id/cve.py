#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Staff for working with CVE Identifiers. See http://cve.mitre.org."""

import re


class CVEID(object):
    """
    CVEID class.
    CVE Identifiers (also called "CVE names," "CVE numbers," "CVE-IDs," and "CVEs") 
    are unique, common identifiers for publicly known information security vulnerabilities.
    See http://cve.mitre.org.
    """
    
    pattern = r'^cve-[\d]{4}-[\d]+$|can-[\d]{4}-[\d]+$'
    
    @classmethod
    def correct_cve_str(cls, cve_str, ignore_case=False):
        if isinstance(cve_str, (str, unicode)):
            if ignore_case:
                if re.match(cls.pattern, cve_str, re.I) is not None:
                    return True
            else:
                if re.match(cls.pattern, cve_str) is not None:
                    return True
        else:
            return False
    
    @classmethod
    def from_string(self, cve_str):
        """
        This create the CVEID object from the string describes cve
        """
        if not isinstance(cve_str, (str, unicode)):
            raise TypeError("parameter 'cve_str' must be a string")
        if not CVEID.correct_cve_str(cve_str, ignore_case=True):
            raise ValueError("CPE string is incorrect")
        return CVEID(cve_str[:3].lower(), cve_str[4:8], cve_str[9:])
    
    def __init__(self, cve_type, year, num):
        if not isinstance(cve_type, (str, unicode)):
            raise TypeError("parameter 'cve_type' must be a string")
        self._type = cve_type.lower()
        if not isinstance(year, str):
            raise TypeError("parameter 'year' must be a string")
        if year.isdigit():
            self._year = year
        else:
            raise ValueError("parameter 'year' have incorrect value")
        if not isinstance(num, str):
            raise TypeError("parameter 'year' must be a string")
        if year.isdigit():
            self._num = num
        else:
            raise ValueError("parameter 'year' have incorrect value")
    
    def __str__(self):
        return "-".join([self._type, self._year, self._num])
    
    def __eq__(self, other):
        if not isinstance(other, CVEID):
            raise ValueError
        return str(self) == str(other)

    def get_type(self):
        """
        @return: value of the cve type.
        Mast be string value
        """
        return self._type
    
    def get_year(self):
        """
        @return: value of the cve year.
        Mast be integer value
        """
        return int(self._year)
    
    def get_num(self):
        """
        @return: value of the cve number.
        Mast be integer value
        """
        return int(self._num)
    
    def is_candidate(self):
        """
        @return: True if cve id has candidate status. False otherwise.
        """
        return (self._type == 'can')
    
    cve_str = property(__str__)