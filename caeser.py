import sys
import re


def remove_foreign_chars(text):
    """Removes non-letter and non-digit characters from the input string."""
    return re.sub(r'[^a-zA-Z0-9 ]', '', text)


def caesar_cipher(decode, text, shift, mod, charset, foreign_chars):
    """Applies the Caesar cipher to the input text."""
    if decode == "decode":
        shift = -shift

    if foreign_chars == "1":
        text = remove_foreign_chars(text)

    charset = charset.lower()
    result = ""

    for char in text:
        index = charset.find(char.lower())
        if index != -1:
            new_index = (index + shift) % mod
            if new_index < 0:
                new_index += mod
            result += charset[new_index] if char.islower() else charset[new_index].upper()
        else:
            result += char

    return result


def main():
    """Main function to handle user input and process the cipher."""
    print("Caesar Cipher Encoder/Decoder")

    mode = input("Enter mode (encode/decode): ")
    text = input("Enter text: ")
    shift = int(input("Enter shift value: "))
    mod = int(input("Enter modulo value: "))
    charset = input("Enter alphabet set: ")
    letter_case = int(input("Choose case (1: Maintain, 2: Lower, 3: Upper): "))
    foreign_chars = input("Remove foreign characters? (1: Yes, 2: No): ")

    result = caesar_cipher(mode, text, shift, mod, charset, foreign_chars)

    if letter_case == 2:
        result = result.lower()
    elif letter_case == 3:
        result = result.upper()

    print("\nResult:")
    print(result)


if __name__ == "__main__":
    main()
