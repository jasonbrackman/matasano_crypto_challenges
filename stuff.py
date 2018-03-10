import binascii

import cryptopals

message = b""""I honour your circumspection. A fortnight's acquaintance is certainly
very little. One cannot know what a man really is by the end of a
fortnight. But if _we_ do not venture, somebody else will; and after
all, Mrs. Long and her nieces must stand their chance; and therefore, as
she will think it an act of kindness, if you decline the office, I will
take it on myself."

The girls stared at their father. Mrs. Bennet said only, "Nonsense,
nonsense!"

"What can be the meaning of that emphatic exclamation?" cried he. "Do
you consider the forms of introduction, and the stress that is laid on
them, as nonsense? I cannot quite agree with you _there_. What say you,
Mary? for you are a young lady of deep reflection I know, and read great
books, and make extracts."

Mary wished to say something very sensible, but knew not how.

"While Mary is adjusting her ideas," he continued, "let us return to Mr.
Bingley."

"I am sick of Mr. Bingley," cried his wife.

"I am sorry to hear _that_; but why did not you tell me so before? If I
had known as much this morning, I certainly would not have called on
him. It is very unlucky; but as I have actually paid the visit, we
cannot escape the acquaintance now."

The astonishment of the ladies was just what he wished; that of Mrs.
Bennet perhaps surpassing the rest; though when the first tumult of joy
was over, she began to declare that it was what she had expected all the
while.

"How good it was in you, my dear Mr. Bennet! But I knew I should
persuade you at last. I was sure you loved your girls too well to
neglect such an acquaintance. Well, how pleased I am! and it is such a
good joke, too, that you should have gone this morning, and never said
a word about it till now."

"Now, Kitty, you may cough as much as you chuse," said Mr. Bennet; and,
as he spoke, he left the room, fatigued with the raptures of his wife.

"What an excellent father you have, girls," said she, when the door was
shut. "I do not know how you will ever make him amends for his kindness;
or me either, for that matter. At our time of life, it is not so
pleasant I can tell you, to be making new acquaintance every day; but
for your sakes, we would do any thing. Lydia, my love, though you _are_
the youngest, I dare say Mr. Bingley will dance with you at the next
ball."

"Oh!" said Lydia stoutly, "I am not afraid; for though I _am_ the
youngest, I'm the tallest."

The rest of the evening was spent in conjecturing how soon he would
return Mr. Bennet's visit, and determining when they should ask him to
dinner.
"""
key = b'jason_'

x = cryptopals.encrypt_xor(message, key=key)
z = cryptopals.break_repeating_key_xor(binascii.unhexlify(x))

print("Original Message Length:", len(message))
print("Original Password:", key)
print(" Cracked Password:", z)
# print(cryptopals.decrypt_xor(x, key=z, hexlify=True))
