/**
 * @file guid.h
 * @brief 定义组件的唯一标识符 (CLSID)。
 *
 * @details GUID (全局唯一标识符) 是 COM 组件的灵魂。Windows 通过这个 128 位的数字
 * 在注册表中查找并加载你的 DLL。
 */

// {ACFC407B-266C-4085-8DAE-F3E276336E4B}
// 意义：这个 ID 必须通过工具（如 guidgen.exe）生成，确保全球唯一。
// 系统通过这个 ID 识别这就是“示例凭据提供程序”。
DEFINE_GUID(CLSID_CSample, 0xacfc407b, 0x266c, 0x4085, 0x8d, 0xae, 0xf3, 0xe2, 0x76, 0x33, 0x6e,
            0x4b);