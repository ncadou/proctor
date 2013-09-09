# encoding: utf-8

import os

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import proctor


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='proctor',
      version=proctor.__version__,
      author=proctor.__author__,
      author_email=proctor.__email__,
      maintainer=proctor.__maintainer__,
      maintainer_email=proctor.__email__,
      url=proctor.__url__,
      long_description=read('README.md'),
      packages=find_packages(),
      include_package_data=True,
      install_requires=['desub', 'pymiproxy', 'SocksiPy-branch'],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Plugins',
          'Intended Audience :: Developers',
          'Natural Language :: English',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.7',
          'Topic :: Documentation',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: Internet :: WWW/HTTP'],
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'proctor = proctor.scripts:main']})
