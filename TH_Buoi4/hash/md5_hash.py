def left_rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def md5(message):
    # Khởi tạo các biến ban đầu
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    # Tiền xử lý chuỗi văn bản
    original_length = len(message) * 8  # Độ dài tính bằng bit
    message += b'\x80'  # Thêm bit 1 (0x80)
    while len(message) % 64 != 56:  # Đệm bằng 0 cho đến khi còn 56 byte
        message += b'\x00'
    message += original_length.to_bytes(8, 'little')  # Thêm độ dài gốc

    # Chia chuỗi thành các block 512-bit
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        words = [int.from_bytes(block[j:j+4], 'little') for j in range(0, 64, 4)]
        
        # Lưu giá trị ban đầu của a, b, c, d
        a0, b0, c0, d0 = a, b, c, d

        # Vòng lặp chính của thuật toán MD5
        for j in range(64):
            if j < 16:
                f = (b & c) | ((~b) & d)
                g = j
                s = [7, 12, 17, 22][j % 4]
            elif j < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * j + 1) % 16
                s = [5, 9, 14, 20][j % 4]
            elif j < 48:
                f = b ^ c ^ d
                g = (3 * j + 5) % 16
                s = [4, 11, 16, 23][j % 4]
            else:
                f = c ^ (b | (~d))
                g = (7 * j) % 16
                s = [6, 10, 15, 21][j % 4]
            
            # Cập nhật giá trị
            temp = d
            d = c
            c = b
            b = b + left_rotate((a + f + 0x5A827999 + words[g]) & 0xFFFFFFFF, s)
            a = temp

        # Cộng dồn giá trị
        a = (a + a0) & 0xFFFFFFFF
        b = (b + b0) & 0xFFFFFFFF
        c = (c + c0) & 0xFFFFFFFF
        d = (d + d0) & 0xFFFFFFFF

    # Định dạng kết quả cuối cùng
    return '{:08x}{:08x}{:08x}{:08x}'.format(
        a & 0xFFFFFFFF, b & 0xFFFFFFFF, c & 0xFFFFFFFF, d & 0xFFFFFFFF
    )

# Nhập chuỗi và tính mã băm
input_string = input("Nhập chuỗi cần băm: ")
md5_hash = md5(input_string.encode('utf-8'))
print("Mã băm MD5 của chuỗi '{}' là: {}".format(input_string, md5_hash))