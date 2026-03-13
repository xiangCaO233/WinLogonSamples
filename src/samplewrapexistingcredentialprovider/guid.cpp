/**
 * @file guid.cpp
 * @brief 实例化 GUID。
 *
 * @details 在 C++ 中，包含定义 GUID 的头文件通常只产生外部引用。
 * 通过在包含 guid.h 之前包含 <initguid.h>，编译器会实际为这些 GUID 分配内存空间。
 * 这通常在项目中只做一次。
 */

#include <initguid.h>  // 必须在 guid.h 之前，用于初始化内存中的 GUID
#include "guid.h"      // 包含刚才定义的 CLSID_CSample