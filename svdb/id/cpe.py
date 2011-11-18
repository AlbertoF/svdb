#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Staff for working with CPE identifiers. See http://cpe.mitre.org."""

import re

class CPEID(object):
    """
    CPE identifier (name) class.
    CPE is a structured naming scheme for information technology systems, platforms, and packages.
    See http://cpe.mitre.org.
    """
    
    pattern = r'^cpe:/(?P<platform_type>[hoa]):(?P<vendor>[\w\.\-~%]+):(?P<product>[\w\.\-~%]+):?(?P<version>[\w\.\-~%]*):?(?P<update>[\w\.\-~%]*):?(?P<edition>[\w\.\-~%]*):?(?P<language>[\w\.\-~%]*)$'
    list_of_attributes = 'platform_type','vendor', 'product', 'version', 'update', 'edition', 'language'
    @classmethod
    def correct_cpe_str(cls, cpe_str, ignore_case=False):
        """
        Function only to check validly CPEID string
        Return True if CPEID is valid, or False in another thing
        """
        if isinstance(cpe_str, (str, unicode)):
            if ignore_case:
                if re.match(cls.pattern, cpe_str, re.I) is not None:
                    return True
            else:
                if re.match(cls.pattern, cpe_str) is not None:
                    return True
        else:
            return False
            
    @classmethod
    def from_string(self, cpe_str):
        """
        @param cpe_str: CPE string 
        @return cpe_str: CPEID object
        """
        if not isinstance(cpe_str, (str, unicode)):
            raise TypeError("parameter 'cpe_str' must be a string")
        return CPEID(*(cpe_str[5:].split(':')))
        
    def __init__(self, platform_type, vendor, product, version='', update='', edition='', language = ''):
        """ Modify different parameters into string with full CPE identifier
        @param platform_type: string with type of service the particular platform type.
            Correct values:
            'h' - hardware type
            'o' - operation system type
            'a' - application type
        @param vendor: string with the supplier or vendor of the platform type.
        @param product: string with the product name of the platform type.
        @param version: string with the product name of the platform type.
        @param update: string with the version of the platform type.
        @param edition: string with the update or service pack information.
        @param language: This clear.
        """
        #Dictionary with all parameters of CPE, also include empty
        cpe_dict = {}
        
        for key in self.list_of_attributes:
            item = locals()[key]
            if not isinstance(item, (str, unicode)):
                raise TypeError("parameter '%s' must be a string" % str(key))
            #If first 3 arguments are empty
            elif item == '' and str(key) in self.list_of_attributes[:3]:
                raise ValueError("The parameter '%s' must not be empty" % str(key))
            #If arguments contain wrong symbols
            elif re.match(r'^[a-z0-9_\.\-~%]+$', item) is None and item != '':
                raise ValueError("parameter '%s' = '%s' contains undecleared symbols" % (str(key), item))
            cpe_dict[key] = item.lower()
        #If first parameter is invalid
        if re.match(r'^[aoh]$', cpe_dict['platform_type']) is None:
            raise ValueError("First parameter must be 'a' or 'o' or 'h'")
        self._cpe_dict = cpe_dict
        
    def __str__(self):
        return self._get_string()
    
    def __eq__(self, other):
        if not isinstance(other, CPEID):
            raise ValueError
        return self._get_string().lower() == other._get_string().lower()
    
    def get_base(self):
        """
        @return: CPE string with base cpe info: type, vendor, product.
        """
        return "cpe:/" + ":".join(self._cpe_dict[elem] for elem in self.list_of_attributes[:3]).rstrip(":")
        
    def _get_string(self):
        """
        @return: assert CPE string
        """
        return "cpe:/" + ":".join(self._cpe_dict[elem] for elem in self.list_of_attributes).rstrip(":")
    
    def get_type_info(self):
        """
        @return: string with type of service the particular platform type.
        Correct values:
            'h' - hardware type
            'o' - operation system type
            'a' - application type
        """
        return self._cpe_dict['platform_type']
        
    def get_vendor_info(self):
        """
        @return: string with the supplier or vendor of the platform type.
        """
        return self._cpe_dict['vendor']
        
    def get_product_info(self):
        """
        @return: string with the product name of the platform type.
        """
        return self._cpe_dict['product']      
        
    def get_version_info(self):
        """
        @return: string with the version of the platform type.
        """
        return self._cpe_dict['version']      
        
    def get_update_info(self):
        """
        @return: string with the update or service pack information.
        """
        return self._cpe_dict['update']   
    
    def get_edition_info(self):
        """
        @return: string with the edition of the platform type.
        """
        return self._cpe_dict['edition']     
        
    def get_language_info(self):
        """
        @return: string with the language associated with the specific platform.
        
        This component should be represented by a valid language tag as defined by IETF 
        RFC 4646 entitled Tags for Identifying Languages.
        """
        return self._cpe_dict['language']

    def generalize(self, cpe):
        """
        @param cpe: CPEID object.
        @return: True if self object cpe generalize param cpe otherwise False.
        """
        if not isinstance(cpe, CPEID):
            return False
        return cpe._get_string().upper().startswith(self._get_string().upper()) and \
            len(self._get_string()) < len(cpe._get_string())
    #This give our spe_str
    cpe_str = property(_get_string)
            
if __name__ == "__main__":
    _str = ('a', 'microsoft', 'ie', '8.0.7600.16385')
    print isinstance(CPEID(*_str), CPEID)
    cp = CPEID(*_str)
    print (cp.cpe_str)

