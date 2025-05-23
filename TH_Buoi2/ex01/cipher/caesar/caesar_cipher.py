from cipher.caesar import ALPHABET

class CaesarCipher:
    def __init__(self):
        self.alphabet = ALPHABET

    def encrypt_text(self, text: str, key: int) -> str:
        alphabet_len = len(self.alphabet)
        text = text.upper()
        encrypted_text = []
        for letter in text:
            letter_index = self.alphabet.index(letter)
            out_index = (letter_index + key) % alphabet_len
            out_letter = self.alphabet[out_index]
            encrypted_text.append(out_letter)
        return "".join(encrypted_text)

    def decrypt_text(self, text: str, key: int) -> str:
        alphabet_len = len(self.alphabet)
        text = text.upper()
        decrypted_text = []
        for letter in text:
            letter_index = self.alphabet.index(letter)
            out_index = (letter_index - key) % alphabet_len
            out_letter = self.alphabet[out_index]
            decrypted_text.append(out_letter)
        return "".join(decrypted_text)