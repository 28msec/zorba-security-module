import module namespace f = "http://expath.org/ns/file";
import module namespace hash = "http://zorba.io/modules/hash";

variable $f := f:read-binary(resolve-uri("ls"));

variable $h := hash:sha1-binary($f);

starts-with(<a attr="{$h || $f}"/>/@attr, "CT6WCSr3")
