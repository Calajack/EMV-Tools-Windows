# EMV-Tools-Windows
We're building a clean Windows-native implementation of EMV payment card processing tools from scratch, 
using the original emv-tools-master as a reference blueprint only. 
We are now building our own version of the files! 
We are building with modulus store facility (if the executable parses the certificate, but does not have the modulus on file
it will store it to memory for future refrence).

*Technical Specifications:                          
-Crypto Backend: OpenSSL 3.0+ (via vcpkg)          
-Smart Cards: Windows PC/SC (winscard.h)            
-Build System: MSBuild + CMake                      
-Language: C++17 with Win32 API

*Key Dependencies:
 -OpenSSL (crypto/rsa/evp)
 -Winsock2 for TCP/IP
 -Windows Smart Card API

**Reference Points:
*Original emv-tools functions we're reimplementing:
-Certificate parsing
-Cryptographic operations
-Smart card communication
-TLV processing

*Key differences from original:
-No libgcrypt/nettle dependencies
-Windows-native I/O
-C++ classes instead of C structs
-RAII resource management

FILE STRUCTURE: 
EMV-Tools-Windows/
├── include/         ----------UNIVERSAL HEADERS
│   ├── emv/
│   │   ├── emv_tags.h
│   │   ├── emv_defs.h
│   │   ├── emv_commands.h
│   │   ├── tlv.h
│   │   └── dol.h
│   ├── crypto/
│   │   ├── emv_pk.h
│   │   └── emv_pki_priv.h
│   └── scard/
│       └── scard_common.h
│       └── apdu.h
├── libcore/      
│    ├── x64----------------------------CONTAINS 3D OBJECTS, TLOG'S AND RECIPE
│    ├── libcore.vcxproj
│    ├── libcore.vcxproj.filters
│    └── libcore.vcxproj.user
├── libcrypto/
│    ├── x64----------------------------CONTAINS 3D OBJECTS, TLOG'S AND RECIPE
│    ├── libcrypto.vcxproj
│    ├── libcrypto.vcxproj.filters
│    └── libcrypto.vcxproj.user
├── libscard/
│    ├── x64----------------------------CONTAINS 3D OBJECTS, TLOG'S AND RECIPE
│    ├── libscard.vcxproj
│    ├── libscard.vcxproj.filters
│    └── libscard.vcxproj.user
│
├── libraries/
     ├── libcore
     │    ├──  All .c & .h files for libcore
     ├── libcrypto
     │    ├──  All .c & .h files for libcrypto
     └── libscard
          └──  All .c & .h files for libscard

