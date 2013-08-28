import module namespace hash = "http://zorba.io/modules/hash";
import module namespace f = "http://expath.org/ns/file";

xs:hexBinary(hash:hash-binary(f:read-binary(resolve-uri("ls")), "sha256"))
