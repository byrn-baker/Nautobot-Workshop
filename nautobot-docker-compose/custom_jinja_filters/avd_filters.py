from django_jinja import library
from pyavd.j2filters import encrypt as avd_encrypt

@library.filter(name="arista.avd.encrypt")
def encrypt(value, *args, **kwargs):
    return avd_encrypt(value, **kwargs)
