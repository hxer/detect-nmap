


def str_to_hex_str(input_string: str, encoding: str = 'utf-8'):
    # 使用UTF-8编码将字符串转换为字节对象
    bytes_object = input_string.encode(encoding)

    # 将每个字节转换为十六进制字符串（无前缀），并用列表推导式连接
    hex_string = ''.join([f'{byte:02x}' for byte in bytes_object])
    return hex_string

def decimal_to_hex_string(number: int):
    hex_string = hex(number & 0xffffffff)[2:]
    return hex_string.zfill(8)


# header_data='{"code":25,"extFields":{"AccessKey":"rocketmq2","Signature":"+zdRdUuaziSQkHUUqdrtwg1F8jk="},"flag":0,"language":"JAVA","opaque":0,"serializeTypeCurrentRPC":"JSON","version":433}'
header_data = '{"code":28,"extFields":{},"flag":0,"language":"JAVA","opaque":0,"serializeTypeCurrentRPC":"JSON","version":433}'
body_data = ''

header_length = len(header_data)
print(header_length)

data_length = 4 + header_length + len(body_data)
print(data_length)

request_data = decimal_to_hex_string(data_length) + decimal_to_hex_string(header_length) + \
    str_to_hex_str(header_data) + str_to_hex_str(body_data)

print(request_data)