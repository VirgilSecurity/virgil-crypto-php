# Virgil Security Сryptographic PHP Library - Documentation

Common library description can be found [here](https://github.com/VirgilSecurity/virgil).

## Build prerequisite

1. [CMake](http://www.cmake.org/).
1. [Git](http://git-scm.com/).
1. [Python](http://python.org/).
1. [Python YAML](http://pyyaml.org/).
1. C/C++ compiler:
    [gcc](https://gcc.gnu.org/),
    [clang](http://clang.llvm.org/),
    [MinGW](http://www.mingw.org/),
    [Microsoft Visual Studio](http://www.visualstudio.com/), or other.

## Build

1. Open terminal.
2. Clone project. ``` git clone https://github.com/VirgilSecurity/virgil.git ```
4. Navigate to the project's folder.
5. ``` cd virgil_lib ```
6. Create folder for the build purposes. ``` mkdir build ```
7. Navigate to the "build" folder. ``` cd build ```
8. Configure cmake. Note, replace "../install" path, if you want install library in different location.
 ``` cmake -DPLATFORM_NAME=PHP -DCMAKE_INSTALL_PREFIX=../install .. ```
10. Build library. ``` make ```
11. Install library. ``` make install ```
12. Add to your php.ini ```extension=path/to/your/virgil_crypto_php.so```, replace ``"path/to/your/virgil_crypto_php.so"`` to your path where virgil_php.so extension is located

## Installation

Use [Composer](http://getcomposer.org) to install this library.

Into your `composer.json` file, just include this library with adding:

```
"virgil/crypto": "1.2.0"
```

Then, run `composer update` and enjoy.