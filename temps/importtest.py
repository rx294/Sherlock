from importlib import import_module


mod = import_module('testclass')
met = getattr(mod, 'Complex')
t= met(4.0, -4.5)

print t.__module__
print dir(t)