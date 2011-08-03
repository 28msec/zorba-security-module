xquery version "3.0";

(:
 : Copyright 2006-2009 The FLWOR Foundation.
 :
 : Licensed under the Apache License, Version 2.0 (the "License");
 : you may not use this file except in compliance with the License.
 : You may obtain a copy of the License at
 :
 : http://www.apache.org/licenses/LICENSE-2.0
 :
 : Unless required by applicable law or agreed to in writing, software
 : distributed under the License is distributed on an "AS IS" BASIS,
 : WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 : See the License for the specific language governing permissions and
 : limitations under the License.
:)

(:~
 : This module provides access to functions that perform different hash operations.
 :
 : @author Gabriel Petrovay, Markus Pilman
 : @project cryptography
 :)
module namespace hash = "http://www.zorba-xquery.com/modules/cryptography/hash";

declare namespace ver = "http://www.zorba-xquery.com/options/versioning";
declare option ver:module-version "1.0";

(:~
 : Computes the MD5 hash of the string provided as parameter.
 :
 : @param $value The string to hash.
 : @return The MD5 hash of the provided string.
 :)
declare function hash:md5($value as xs:string) as xs:string
{
  hash:hash-impl($value, "md5")
};

(:~
 : Computes the SHA1 hash of the string provided as parameter.
 :
 : @param $value The string to hash.
 : @return The SHA1 hash of the provided string.
 :)
declare function hash:sha1($value as xs:string) as xs:string
{
  hash:hash-impl($value, "sha1")
};

(:~
 : This function is only used internally and should not be called directly by the
 : user.
 :
 : @param $value The string to be hashed.
 : @param $alg The algorithm to use for this hashing operation. Currently only
 :        "md5" and "sha1" algorithms are available.
 : @return The hash of the provided string. If <code>$alg</code> is not a valid
 :         algorithm name, the MD5 hash will be returned.
 :)
declare %private function hash:hash-impl($value as xs:string, $alg as xs:string) as xs:string external;
