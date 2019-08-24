## 第一次尝试使用WebSocket
## 需要注意客户端到服务器(C2S)与服务器到客户端(S2C)的帧格式：
### C2S
- Fin
- Reserved
- Opcode
- Mask:**True**
- Payload length
- **masking-key**
- **masked payload**

### S2C
- Fin
- Reserved
- Opcode
- Mask:**False**
- Payload length
- **payload**