# JWEDecoder
decode data with jwe



# command for build pairKey:
./openssl ecparam -genkey -name secp521r1 -noout -out C:/private/private-key-pair.pem 

./openssl ec -in C:/private/private-key-pair.pem -pubout -out C:/private/public-key.pem
