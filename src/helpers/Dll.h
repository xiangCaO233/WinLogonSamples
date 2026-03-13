/**
 * @file Dll.h
 * @brief DLL 全局定义与生命周期管理声明。
 *
 * 本文件定义了 DLL 的实例句柄以及用于控制 DLL 卸载时机的引用计数函数。
 */

#pragma once

/**
 * @brief 全局 DLL 实例句柄。
 * @details 存储本 DLL 被加载到进程空间时的基地址，常用于加载资源（如位图、字符串）。
 */
extern HINSTANCE g_hinst;

/**
 * @brief 方便使用的宏，指向当前 DLL 的实例句柄。
 */
#define HINST_THISDLL g_hinst

/**
 * @brief 增加 DLL 的全局引用计数。
 * @details 当创建一个 COM 对象或锁定服务器时调用，防止 DLL 在对象尚在使用时被系统卸载。
 */
void DllAddRef();

/**
 * @brief 减少 DLL 的全局引用计数。
 * @details 当 COM 对象被销毁或服务器解锁时调用。
 */
void DllRelease();