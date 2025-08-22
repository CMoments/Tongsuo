/*
这段代码（`sdf_ext.c`）主要是做SDF标准接口的**通用辅助实现**，而不是专门适配某个特定厂商。具体说明如下：

### 1. 打印与格式化相关函数
如 `SDF_PrintDeviceInfo`、`SDF_PrintRSAPublicKey`、`SDF_PrintECCCipher` 等，都是用来把 SDF 标准结构体（如 `DEVICEINFO`、`RSArefPublicKey`、`ECCCipher` 等）以人类可读的方式输出，便于调试和日志记录。

### 2. 标准结构体的内存管理
如 `SDF_NewECCCipher`、`SDF_FreeECCCipher`，用于分配和释放 SDF 标准结构体（如 `ECCCipher`）的内存，保证主流程和适配层都能安全使用这些结构体。
- 注意：`SDF_NewECCCipher` 里有一行 `if (len < sizeof(SANSEC_ECCCipher)) { len = sizeof(SANSEC_ECCCipher); }`，这说明它会为 Sansec（上证通）厂商的 ECCCipher 结构体分配足够空间，但本质上还是以标准结构体为主。

### 3. 错误码解释
`SDF_GetErrorReason` 用于将 SDF 错误码转换为字符串，方便日志和调试。

### 4. 算法能力表
`sdf_cipher_caps`、`sdf_digest_caps`、`sdf_pkey_caps` 是标准算法ID与名称的映射表，用于打印设备能力。

### 5. 不是特定厂商适配
- 这些代码没有直接做 Sansec 或其他厂商的专用适配（如算法ID转换、结构体字段转换等）。
- 但它为适配层和主流程提供了“通用工具”，比如分配结构体时兼容了 Sansec 的结构体长度，这样适配层可以安全地做结构体转换。

**总结**：  
本文件是SDF标准接口的通用实现和工具集，服务于主流程和所有厂商适配层。它不是专门为某个厂商做适配，但为适配层提供了必要的基础能力（如内存分配、打印、错误解释等）。
*/