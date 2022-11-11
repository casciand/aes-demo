# Installation

1. cmake: https://cmake.org/download/
2. .NET: https://dotnet.microsoft.com/en-us/download

If on Windows:

3. Visual Studio Community: https://visualstudio.microsoft.com/vs/community/

# Build

Run the following commands from the project root:

## C#

```commandline
cd csharp
dotnet build
```

## C++

If on Linux or MacOS:

```commandline
cd cpp/lib/cryptopp
make
```

```commandline
cd cpp
mkdir build && cd build
cmake .
make
```

If on Windows:

Open the project in Visual Studio. If it complains about an outdated toolset, change to the newer toolset in properties. Build project lib and build project DLL. Copy DLL to the folder where `cpp.exe` is located, most likely `cpp\build\Debug`.

```commandline
cd cpp\build
cmake --build .
```

# Run

## C++

Start the server by running the executable in the `cpp\build\Debug` directory (or wherever the executable resides).

```commandline
.\cpp.exe
```

## C#

Start the client by running the following command in the `csharp` directory.

```commandline
dotnet run
```

After the connection establishes, send encrypted messages to the server from the prompt.
