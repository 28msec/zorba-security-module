# Copyright 2006-2010 The FLWOR Foundation.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

MESSAGE(STATUS "")
MESSAGE(STATUS "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
MESSAGE(STATUS "Configuring external module <security>")
MESSAGE(STATUS "-------------------------------------------------------------")
MESSAGE(STATUS "")

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT (zorba_security_module)
ENABLE_TESTING ()
INCLUDE (CTest)

FIND_PACKAGE (Zorba REQUIRED HINTS "${ZORBA_BUILD_DIR}")
INCLUDE ("${Zorba_USE_FILE}")

FIND_PACKAGE(OpenSSL) 
IF (NOT OPENSSL_FOUND)

  MESSAGE(WARNING "Could not find the OpenSSL library and development headers")
  MESSAGE(WARNING "Not building security modules")
  SET_PROPERTY (GLOBAL PROPERTY ZORBA_PROJECT_UNAVAILABLE 1)
  
  MESSAGE(STATUS "")
  MESSAGE(STATUS "-------------------------------------------------------------")  
  MESSAGE(STATUS "Configuration FAILED for external module <security>")

ELSE (NOT OPENSSL_FOUND)

  INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
  
  ADD_TEST_DIRECTORY("${PROJECT_SOURCE_DIR}/test")
  ADD_SUBDIRECTORY("src")
  
  MESSAGE(STATUS "")
  MESSAGE(STATUS "-------------------------------------------------------------")
  MESSAGE(STATUS "Configuration SUCCEEDED for external module <security>")

ENDIF (NOT OPENSSL_FOUND)

DONE_DECLARING_ZORBA_URIS()

MESSAGE(STATUS "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
