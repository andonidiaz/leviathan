# coding=utf-8

"""
    Main module of the framework
"""

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
            print "  "+str(i)+" -> " + elemento.__menu_color__ + elemento.__title__ + chr(27)+"[0m" + ": " + elemento.__menu_entry__
            i += 1

    def mainLoop(list):
        while True:
            element = input(chr(27)+"[0;92m"+"[+]"+chr(27)+"[0m"+" Insert the plugin that you will load: ")
            objeto = list[int(element)].Main()
            objeto.main()

    if __name__ == "__main__":
        plugin_list = []
        module_list = []
        print LeviathanTitles.titles[random.randint(0, (len(LeviathanTitles.titles) - 1))]
        print chr(27)+"[0;91m"+"Welcome to Leviathan v.%s" % __version__ + chr(27)+"[0m"
        print chr(27)+"[1;91m"+"Developed by Marc Ruiz and Andoni Diaz.\n"
        print chr(27)+"[0;91m"+"[*]"+chr(27)+"[0m"+" Loading all modules..."
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
        print chr(27)+"[0;92m"+"[*]"+chr(27)+"[0m"+" All modules loaded without problems."

        buildMenu(module_list)
        mainLoop(module_list)