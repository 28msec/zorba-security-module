(: Values compared to php -r 'echo base64_encode(sha1($string, true));' :)
import module namespace hash = "http://zorba.io/modules/hash";

xs:hexBinary(hash:md5("abc")),
hash:md5("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
