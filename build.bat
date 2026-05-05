cmake -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
@echo off
echo .
echo done!
pause