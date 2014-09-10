# coding=utf-8

"""
    Main module of the framework
"""
import inspect

__author__ = 'Andoni Diaz <andoni94@gmail.com>'
__version__ = "0.0.1a"

from titles import LeviathanTitles
import random
import sys, imp, re
from os import listdir
from os.path import isfile, join


class Leviathan:
    def __init__(self):
        pass

    def main():
        plugin_list = []
        module_list = []
        print LeviathanTitles.titles[random.randint(0, (len(LeviathanTitles.titles) - 1))]
        print "Welcome to Leviathan v.%s" % __version__
        print "[*] Loading all modules..."
        # Cargamos los ficheros en el directorio de plugins con una lista de comprensión
        plugins_files = []
        for f in listdir("plugins/"):
            if isfile(join("plugins/", f)):
                if f.endswith(".py"):
                    plugins_files.append(f)

        for file in plugins_files:
            # Regularizamos los nombres para poder importar el código mediante introspección
            name = re.findall("(.*).py$", file)
            if '__init__' not in name[0]:
                plugin_list.append(name[0])

        for plugin in plugin_list:
            module = imp.load_source(plugin, "./plugins/" + plugin + ".py")
            # module = __import__("plugins."+plugin, fromlist=['Main'])
            module_list.append(module)
            print dir(module.Main)
            clase = module.Main()
            print clase.__title__

    if __name__ == "__main__": main()
