## 第一次尝试使用WebSocket
## 需要注意客户端到服务器(C2S)与服务器到客户端(S2C)的帧格式：
### C2S
- Fin
- Reserved
- Opcode
- Mask:<font color=red>True</font>
- Payload length
- <font color=Red>masking-key</font>
- <font color=red>masked payload</font>

### S2C
- Fin
- Reserved
- Opcode
- Mask:<font color=red>False</font>
- Payload length
- <font color=red>payload</font>