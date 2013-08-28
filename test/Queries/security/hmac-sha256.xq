import module namespace hash = "http://zorba.io/modules/hmac";
import module namespace f = "http://expath.org/ns/file";

hash:compute-binary(xs:base64Binary("Zm9vCg=="), "bar", "sha256"),
xs:hexBinary(hash:compute-binary(f:read-binary(resolve-uri("ls")), "bar", "sha256"))
