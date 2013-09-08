# encoding: utf-8

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages


setup(name='proctor',
      version='0.0.1',
      author='Brasseurs Numériques',
      author_email='ncadou@ajah.ca',
      url='http://ajah.ca',
      packages=find_packages(),
      include_package_data=True,
      install_requires=['desub', 'pymiproxy', 'SocksiPy-branch'],
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'proctor = proctor.scripts:main']})
