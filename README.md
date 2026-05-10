# ThickyStore-GO

参考 TrickyStoreOSS 思路，用 Go 实现接管 Keystore 关键路径的原理性验证。

## 注意事项

- **deleteKeyPair**：暂未实现删除缓存中的 key。
- **Socket**：未做随机化，易被检测；当前仅作原理探究。
- **公钥**：由私钥推导公钥的部分目前为随机占位；主要原因无EC算法私钥（几块钱能买到的基本都假的 只有证书链是真的）
