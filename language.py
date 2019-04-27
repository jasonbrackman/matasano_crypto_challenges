#
# Purpose: Obtain the letter frequency from an input text
#          - currently set to an English text, but no reason why it couldn't be setup for other languages.
#
# Created: Dec. 29th, 2016
import os
import string
import collections


class Language:
    """The book passed in dictates the language used.  The default book is in English."""

    def __init__(self, book=None):
        if not book:
            current_dir = os.path.split(__file__)[0]
            book = os.path.join(current_dir, "data_language/english.txt")

        self.text = self.read_book(book)
        self.letter_frequency = self.letter_frequency_()

    def read_book(self, book):
        with open(book, "rt") as handle:
            text = handle.read()
        return text

    def letter_frequency_(self):
        text = self.text.lower()
        count = collections.Counter(
            letter for letter in text if letter in string.ascii_lowercase
        )
        totals = sum(count.values())
        frequency = {k: v / totals for k, v in count.items()}
        keys = reversed(
            sorted(
                frequency, key=lambda x: frequency[x] if frequency[x] is not None else 0
            )
        )

        return {key: frequency[key] for key in keys}

    def common_words(self, number=50, min_length=4):
        """
        Example:
        Obtain most common words through an examination of open source document.
        :param min_length:
        :param text:
        :param number:
        :return:
        """

        words = self.text.split()
        counter = collections.Counter(words)
        most_common = [
            key for (key, value) in counter.most_common(number) if len(key) > min_length
        ]
        return most_common

    def score_text(self, text: bytes) -> float:
        scores = []

        for letter in text.decode("utf-8"):

            if letter in self.letter_frequency:
                scores.append(self.letter_frequency[letter])
            else:
                if letter in string.printable:
                    scores.append(0)
                else:
                    scores = [0]

        return sum(scores)

    def part_of_language(self, decrypted: bytes, number=100, min_length=3):
        english_words = self.common_words(number=number, min_length=min_length)
        return (
            True
            if any(word in decrypted.decode("utf-8") for word in english_words)
            else False
        )
