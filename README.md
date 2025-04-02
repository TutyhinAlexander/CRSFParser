# CRSFParser

CRSF packets parser

## Description

Can parse CRSF bytes stream and write output to log. Also can create CRSF packets by input data.

## Installation

### Linux

1. If no `git` installed, install it:

	```bash
	$ sudo apt install git
	```	

1. Make sure you have cmake installed. If no - install it:

	```bash
	$ sudo apt-get -y install cmake
	```	

1. Create and enter directory for project to install into

	```bash
	$ mkdir CRSFParser
	$ cd CRSFParser
	```	

1. Clone project onto your current directory

	```bash
	$ git clone https://github.com/TutyhinAlexander/CRSFParser.git .
	```	

1. Create a new build directory and change into it:

	```bash
	$ mkdir build
	$ cd build
	```	

1. Run cmake on the parent directory to generate makefile:

	```bash
	$ cmake ..
	```

1. Run make on the generated makefile to generate the static CRSFParser libCRSFParser.a:

	```bash
	$ make
	```

1. To install the headers on your system:

	```bash
	$ sudo make install
	```	

## Dependencies
	
	Project uses `LinuxLogger` so you need to install it first:
	
	https://github.com/TutyhinAlexander/LinuxLogger
	

## Using This Project As A CMake Dependency

Add folowwing to your main `CMakeLists.txt`:

```cmake
find_package(CRSFParser REQUIRED)
...
...
target_link_libraries(<your_target_project> CRSFAnalyser::CRSFParser)
```


## Using & Examples

See `CRSFParserTest.cpp` for example of using CRSFParser library


On a Linux system you should be able to compile this example with:

```bash
g++ CRSFParserTest.cpp -o CRSFParserTest -lLogger -lCRSFParser
```	

