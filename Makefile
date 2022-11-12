clear:
	rm -rf build

release:
	mkdir -p build && cmake --no-warn-unused-cli -DCMAKE_BUILD_TYPE:STRING=Release -H./ -B./build -G Ninja
	cmake --build ./build --config Release --target all -j $(shell nproc)

debug:
	mkdir -p build && cmake --no-warn-unused-cli -DCMAKE_BUILD_TYPE:STRING=Debug -H./ -B./build -G Ninja
	cmake --build ./build --config Release --target all -j $(shell nproc)

all:
	make clear
	make release
