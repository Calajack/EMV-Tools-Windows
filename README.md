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

