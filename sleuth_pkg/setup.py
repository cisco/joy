from setuptools import setup, find_packages

setup(name='sleuth',
      version='0.1',
      description='Iteration and inspection over dictionary objects',
      url='https://github.com/cisco/joy.git',
      author='David McGrew, Philip Perricone',
      author_email='mcgrew@cisco.com, phperric@cisco.com',
      license='BSD-3',
      packages=find_packages(),
      package_data={'sleuth': ['*.json']},
      zip_safe=True)