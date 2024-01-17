from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes 
from base64 import b64encode
from base64 import b64decode
#from secret import FLAG

def encode(message):
    return hex(bytes_to_long(b64encode(message)))


def decode(message):
    message = int(message, 16)
    msglen = message.bit_length()
    message = long_to_bytes(message, msglen).decode()
    return b64decode(message).decode()

def main():
    #encoded_flag = encode(FLAG)
    #with open("output.txt", "w") as f:
    #    f.write(encoded_flag)

    hash = "0x53465243657a51784d56383361444e664d32356a4d475178626a6c664e44497a5832677a4d6a4e664e7a42664e5463306558303d"
    hash = decode(hash)
    print(hash)

if __name__ == "__main__":
    main()
