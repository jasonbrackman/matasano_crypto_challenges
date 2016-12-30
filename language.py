#
# Purpose: Obtain the letter frequency from an input text
#          - currently set to an English text, but no reason why it couldn't be setup for other languages.
#
# Created: Dec. 29th, 2016

import collections


def letter_frequency(text='zen10.txt'):
    with open(text, 'rt') as handle:
        text = handle.read()
        count = collections.Counter(text)

        totals = sum(count.values())

        frequency = {k: v/totals for k, v in count.items()}

        keys = reversed(sorted(frequency, key=lambda x: frequency[x] if frequency[x] is not None else 0))
        letter_frequency = {key: frequency[key] for key in keys}

        return letter_frequency


def common_words(text='zen10.txt', number=50):
    """
    Example:
    Obtain most common words through an examination of open source document.
    :param text:
    :param number:
    :return:
    """
    with open(text, 'rt') as handle:
        words = handle.read().split()
        counter = collections.Counter(words)
        most_common = [key for (key, value) in counter.most_common(number)]
        return most_common
