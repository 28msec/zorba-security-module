import module namespace hash = "http://www.zorba-xquery.com/modules/cryptography/hash";
import module namespace f = "http://expath.org/ns/file";

xs:hexBinary(hash:hash-binary(f:read-binary(resolve-uri("ls")), "sha256"))
