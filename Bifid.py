# Note
"""
    HillCypher implements a custom encryption and decryption algorithm using a predefined 6x6 matrix of symbols.

    The matrix coordinates are used to map symbols to their respective positions, facilitating the encryption
    and decryption processes.

    The class maintains dictionaries for symbol-to-coordinate and coordinate-to-symbol
    mappings, and uses lists to store row and column values during encryption and decryption.

"""


class Bifid:
    def __init__(self):
        self.symbols_to_xy = {}
        self.xy_to_symbols = {}
        self.row_values = []
        self.column_values = []

        # Converting the keys into symbolToXY and xyToSymbol dictionaries to get rid of resource-consuming repeated
        # iterations for element searching
        keys = [
            ["A", "Ă", "Â", "B", "C", "D"],
            ["E", "F", "G", "H", "I", "Î"],
            ["J", "K", "L", "M", "N", "O"],
            ["P", "Q", "R", "S", "Ș", "T"],
            ["Ț", "U", "V", "W", "X", "Y"],
            ["Z", ".", ",", ";", "-", " "],
        ]

        for i in range(len(keys)):
            for j in range(len(keys[i])):
                symbol = keys[i][j]
                xy = f"{i}{j}"
                self.xy_to_symbols[xy] = symbol
                self.symbols_to_xy[symbol] = xy

    def set_row_column_values(self, unencrypted=None, encrypted=None):
        if unencrypted:
            for i, c in enumerate(unencrypted):
                notation = self.symbols_to_xy.get(c)
                self.column_values.append(int(notation) % 10)
                self.row_values.append(int(notation) // 10)

        if encrypted:
            for i, c in enumerate(encrypted):
                notation = self.symbols_to_xy.get(c)
                if i < len(encrypted) // 2:
                    self.row_values.append(int(notation) // 10)
                    self.row_values.append(int(notation) % 10)
                else:
                    self.column_values.append(int(notation) // 10)
                    self.column_values.append(int(notation) % 10)

    def encrypt(self, message):
        # Adding a trailing space in case the text has odd length, which would affect the last row/column element
        if len(message) % 2 == 1:
            message += " "

        self.row_values.clear()
        self.column_values.clear()
        self.set_row_column_values(unencrypted=message)

        encrypted = []
        for i in range(0, len(self.row_values), 2):
            xy = f"{self.row_values[i]}{self.row_values[i + 1]}"
            encrypted.append(self.xy_to_symbols[xy])

        for i in range(0, len(self.column_values), 2):
            xy = f"{self.column_values[i]}{self.column_values[i + 1]}"
            encrypted.append(self.xy_to_symbols[xy])

        return ''.join(encrypted)

    def decrypt(self, encrypted):
        decrypted = []

        self.row_values.clear()
        self.column_values.clear()
        self.set_row_column_values(encrypted=encrypted)

        if self.row_values[-1] == 5 and self.column_values[-1] == 5:
            for i in range(len(self.row_values) - 1):
                xy = f"{self.row_values[i]}{self.column_values[i]}"
                decrypted.append(self.xy_to_symbols[xy])
        else:
            for i in range(len(self.row_values)):
                xy = f"{self.row_values[i]}{self.column_values[i]}"
                decrypted.append(self.xy_to_symbols[xy])

        return ''.join(decrypted)

