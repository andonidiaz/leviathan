__author__ = 'Andoni Diaz <andoni94@gmail.com>'

"""
Framework artifact that allows to introspect the inner code and make an re-usable-dynamic api
combining the functions of the plugins developed by the community. 
"""

import inspect

class Framework()
	#Vector api with all the callable functions
	global apiVector

	"""
	Getting all callable methods with the decorator APIcallable
	"""
	def registerCallableMethods(plugin)
		sourcelines = inspect.getsourcelines(cls)[0]
    		for i,line in enumerate(sourcelines):
        		line = line.strip()
        		if line.split('(')[0].strip() == '@APIcallable':
            			nextLine = sourcelines[i+1]
            			name = nextLine.split('def')[1].split('(')[0].strip()
				if not(registerFunctionApi(plugin, name)):
					print "Function name " + name + " is duplicated. Please remove it or remove the API decorator."
            			yield(name)
	
	"""
	Registering plugin into the framework and saving all inner functions
	"""
	def registerFunctionApi(object, name)
		if apiVector[name] is None:
			apiVector[name] = object
			return True
		else:
			return False

	"""
	Call dynamically from the API in order to de-serialize all the functions included
	"""
	def callFromApi(funcName, *params)	
		if not(apiVector[funcName] is None):
			return getattr(plugin,funcName)(params)
		else:
			print "Function called as " + funcName + " doesn't exist."
			return None
