(: Values compared to php -r 'echo base64_encode(sha1($string, true));' :)
import module namespace hash = "http://zorba.io/modules/hash";

hash:sha1("abc"),
hash:sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
