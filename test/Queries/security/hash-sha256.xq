(: Values compared to php -r 'echo base64_encode(sha1($string, true));' :)
import module namespace hash = "http://www.zorba-xquery.com/modules/cryptography/hash";

hash:hash("abc", "sha256"),
hash:hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "sha256"),
hash:hash-binary(xs:base64Binary("Zm9vCg=="), "sha256")
