#pragma once

// 1. 先包含 windows.h，但告诉它不要定义状态码
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

// 2. 接着包含真正需要的 ntstatus.h
#include <ntstatus.h>

// 3. 包含其他 LSA 相关头文件
#include <Lmcons.h>
#include <sspi.h>
#include <NTSecAPI.h>
#include <ntsecpkg.h>


// PrepareToken.hpp
NTSTATUS UserNameToToken(__in LSA_UNICODE_STRING*         AccountName,
                         __in LUID*                       LogonId,  // 新增参数
                         __out LSA_TOKEN_INFORMATION_V1** Token, __out PNTSTATUS SubStatus);