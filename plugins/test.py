# coding=utf-8
__author__ = 'Andoni Diaz <andoni94@gmail.com>'

"""
    Plugin template for development
"""

class Main:

    def __init__(self):
        pass

    __title__ = "PluginTest"
    __description__ = "Un plugin de prueba"
    __menu_entry__ = "Test de plugin vacío"
    __version__ = "1.0"
    __menu_color__ = chr(27) + "[0;92m"

    def main(self):
        print "Hola"