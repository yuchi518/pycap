from distutils.core import setup, Extension

setup(name="pycap",
      version="0.1",
      ext_modules = [Extension('pycap', ['pycap.c'], libraries=['pcap'])])