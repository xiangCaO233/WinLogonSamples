/**
 * @file common.h
 * @brief 定义凭据提供程序的 UI 字段布局和静态数据。
 *
 * @details 此文件描述了在包装好的凭据磁贴（Tile）上附加哪些控件，以及如何显示它们。
 */

#pragma once
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <intsafe.h>
#include <security.h>

/** @brief 定义最大 ULONG 值，常用于无效索引。 */
#define MAX_ULONG ((ULONG)(-1))

/**
 * @enum SAMPLE_FIELD_ID
 * @brief 控件的索引 ID。
 * @details 每个在登录界面显示的控件（文本、组合框等）都必须有一个唯一的 ID。
 */
enum SAMPLE_FIELD_ID
{
    SFI_I_WORK_IN_STATIC  = 0,  ///< 静态文本标签："I work in"
    SFI_DATABASE_COMBOBOX = 1,  ///< 下拉组合框：选择数据库/部门
    SFI_NUM_FIELDS        = 2,  ///< 字段总数计数器。添加新字段时需将其保持在最后。
};

/**
 * @struct FIELD_STATE_PAIR
 * @brief 定义控件的状态。
 * @details 包含控件的显示时机（cpfs）和交互状态（cpfis）。
 */
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE             cpfs;  ///< 显示状态（隐藏、选中时显示、始终显示等）
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;  ///< 交互状态（无、获取焦点等）
};

/**
 * @var s_rgFieldStatePairs
 * @brief UI 字段状态配置表。
 * @details 这里的顺序必须与 SAMPLE_FIELD_ID 中的顺序完全对应。
 */
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] = {
    // SFI_I_WORK_IN_STATIC: 仅在磁贴被选中（Selected）时显示，不可交互
    {CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},

    // SFI_DATABASE_COMBOBOX: 仅在磁贴被选中时显示，用户可以点击选择
    {CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},
};

/**
 * @var s_rgCredProvFieldDescriptors
 * @brief 控件描述符数组。
 * @details 定义了每个控件的类型和名称。Windows 通过这个表来构建 UI。
 */
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] = {
    {
        SFI_I_WORK_IN_STATIC,           // 字段 ID
        CPFT_SMALL_TEXT,                // 控件类型：小文本域
        const_cast<LPWSTR>(L"IWorkIn")  // 控件的内部程序名（非显示文本）
    },
    {
        SFI_DATABASE_COMBOBOX,           // 字段 ID
        CPFT_COMBOBOX,                   // 控件类型：组合框（下拉列表）
        const_cast<LPWSTR>(L"Database")  // 控件的内部程序名
    },
};

/**
 * @var s_rgDatabases
 * @brief 下拉框的内容数据。
 * @details 这是一个静态模拟数据库，用户在组合框中看到并选择这些选项。
 */
static const PWSTR s_rgDatabases[] = {
    const_cast<PWSTR>(L"Operations"),       // 运营部
    const_cast<PWSTR>(L"Human Resources"),  // 人力资源部
    const_cast<PWSTR>(L"Sales"),            // 销售部
    const_cast<PWSTR>(L"Finance"),          // 财务部
};