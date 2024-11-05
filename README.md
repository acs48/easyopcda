# easyopcda

An OPC DA 3.0 compatible client. https://github.com/acs48/easyopcda

## Install
Copy the project folder to your build tree.
Add easyopcda to your CMakeLists.txt project addint the following directives:
- add_subdirectory(easyopcda-v0.2.x)
- ...
- target_link_libraries(your_target PRIVATE easyopcda_lib)

Requires MSVC compiler. Requires C++17. Requires x86 (32bit) build. As such, executable requires MSVC redists.

## Use

easyopcda is still under development and valid for prototyping, troubleshooting and testing OPC DA connections.
Latest tag support reading (both synchronous and asynchronous). It does not support writing yet.

The three main classes of the project:
- OPCInit: to initialize / uninitialize DCOMs
- OPCClient: handling connection to OPC server
- OPCGroup: handling tag groups, read and write operations.

User can get results of read operations through the std::function<void(std::wstring groupName, opcTagResult)> ASyncCallback passed as argument of OPCInit constructor.

Project makes use of spdlog (https://github.com/gabime/spdlog) for logging. spdlog is licensed under MIT license (https://github.com/gabime/spdlog/blob/v1.x/LICENSE)

Log can be redirected both to default spdlog (e.g. what set by user) and/or to std::string in each class instance (may be necessary when used as a remote process). 

## Example

See example.cpp source file for basic example. Requires Matrikon OPC Server for simulation, which can be downloaded for free at www.matrikon.com upon registration with a valid business mail.

## License

easyopcda is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public License for more details.

Use of this source code is governed by a GNU General Public License v3.0 License that can be found in the LICENSE file.
