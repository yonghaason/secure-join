cmake_minimum_required(VERSION 3.31.3)
set(CMAKE_MODULE_PATH "/home/lab614/psu/usenix2025/unbalanced_ePSU/MCRG/cmake;/home/lab614/psu/usenix2025/unbalanced_ePSU/vcpkg/installed/x64-linux/share/seal;/home/lab614/psu/usenix2025/unbalanced_ePSU/vcpkg/installed/x64-linux/share/kuku")
project(CheckASM ASM)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/result.cmake"
  "set(CMAKE_ASM_COMPILER \"${CMAKE_ASM_COMPILER}\")\n"
  
  )