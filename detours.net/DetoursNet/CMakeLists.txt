# Minimum CMake required
cmake_minimum_required(VERSION 3.11)

set(DETOURSNET_SRC
	src/DetoursNet.cs
	src/DetoursNetLoader.cs
)

add_library(DetoursNet SHARED ${DETOURSNET_SRC})
set_target_properties(DetoursNet PROPERTIES DOTNET_SDK "Microsoft.NET.Sdk")