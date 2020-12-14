import random
import re
import string
import uuid


def have_spl_character(text):
    string_check = re.compile('[@_!#$%^&*()<>?/\\|}{~:]')
    return string_check.search(text) is not None


def generate_uuid():
    return str(uuid.uuid4())


def random_string():
    """Generate a random string with the combination of lowercase and uppercase letters """
    string_length = random.randint(10, 15)
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(string_length))
