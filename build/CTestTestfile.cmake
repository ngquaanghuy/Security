# CMake generated Testfile for 
# Source directory: /home/ngquanghuy/Security
# Build directory: /home/ngquanghuy/Security/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(Encoders "/home/ngquanghuy/Security/build/test_encoders")
set_tests_properties(Encoders PROPERTIES  _BACKTRACE_TRIPLES "/home/ngquanghuy/Security/CMakeLists.txt;40;add_test;/home/ngquanghuy/Security/CMakeLists.txt;0;")
add_test(ChaCha20 "/home/ngquanghuy/Security/build/test_chacha20")
set_tests_properties(ChaCha20 PROPERTIES  _BACKTRACE_TRIPLES "/home/ngquanghuy/Security/CMakeLists.txt;54;add_test;/home/ngquanghuy/Security/CMakeLists.txt;0;")
add_test(ChaCha20Poly1305 "/home/ngquanghuy/Security/build/test_chacha20poly1305")
set_tests_properties(ChaCha20Poly1305 PROPERTIES  _BACKTRACE_TRIPLES "/home/ngquanghuy/Security/CMakeLists.txt;69;add_test;/home/ngquanghuy/Security/CMakeLists.txt;0;")
