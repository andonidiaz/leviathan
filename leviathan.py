# coding=utf-8

"""
    Main module of the framework
"""
import inspect

__author__ = 'Andoni Diaz <andoni94@gmail.com>'
__version__ = "0.0.1a"

from titles import LeviathanTitles
import imp, re, random
from os import listdir
from os.path import isfile, join


class Leviathan(object):

    def buildMenu(list):
        i = 0
        for plugin in list:
            elemento = plugin.Main()
            print "[" + str(i) + "] - " + elemento.__title__ + ": " + elemento.__menu_entry__
            i += 1

    def mainLoop(list):
        element = input("[+] Insert the plugin that you will load")

    if __name__ == "__main__":
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
            buildMenu(module_list)
