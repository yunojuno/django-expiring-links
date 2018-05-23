# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages

README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name="django-request-token",
    version="0.8",
    packages=find_packages(),
    install_requires=[
        'Django>=1.11',
        'PyJWT>=1.4',
        'sqlparse>=0.2',
        'psycopg2>=2.7',
        'jsonfield>=2.0.2'
    ],
    include_package_data=True,
    description='JWT-backed Django app for managing querystring tokens.',
    license='MIT',
    long_description=README,
    url='https://github.com/yunojuno/django-request-token',
    author='YunoJuno',
    author_email='code@yunojuno.com',
    maintainer='YunoJuno',
    maintainer_email='code@yunojuno.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
