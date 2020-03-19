import asyncio
import websockets
import pandas as pd
import random
import json


# 用户列表
UserList = pd.DataFrame(columns = ('obj_ws', 'IP', 'NickName'))

async def SetNickName(websocket, NewNick, IsDefault = False):
    '''
    设置用户昵称并传回客户端
    websocket:  客户端ws
    NewNick:    设置的用户昵称
    IsDefault:  使用已预置的随机昵称
    '''
    if len(NewNick) == 0:
        ret = {'Type':'SetNickErr', 'Data':'昵称不能为空！'}
    elif len(NewNick) > 20:
        ret = {'Type':'SetNickErr', 'Data':'昵称过长！'}
    elif NewNick in UserList['NickName'].values and websocket not in UserList.loc[UserList.NickName == NewNick, 'obj_ws'].values:
        ret = {'Type':'SetNickErr', 'Data':'昵称重复！'}
    elif IsDefault == False:
        await SendRoomSystemMsg(UserList.loc[UserList.obj_ws == websocket, 'NickName'].iloc[0] + ' 更改昵称为：' + NewNick)
        UserList.loc[UserList.obj_ws == websocket, 'NickName'] = NewNick
        ret = {'Type':'SetNickOK', 'Data':NewNick}
    else:
        ret = {'Type':'SetNickDefault', 'Data':NewNick}
    await websocket.send(json.dumps(ret))

async def SendSystemMsg(websocket, Message):
    '''
    向客户端发送系统消息
    websocket:  客户端ws
    Message:    消息文本
    '''
    ret = {'Type':'SysMsg', 'Data':Message}
    await websocket.send(json.dumps(ret))

async def SendRoomSystemMsg(Message):
    '''
    向房间内所有客户端发送房间系统消息
    Message:    消息文本
    '''
    ret = {'Type':'RoomSysMsg', 'Data':Message}
    for index, row in UserList.iterrows():
        await row['obj_ws'].send(json.dumps(ret))

async def SendRoomMsg(websocket, Message):
    '''
    向房间内所有客户端发送房间内聊天消息
    websocket:  客户端ws
    Message:    消息文本
    '''
    if Message:
        ret = {'Type':'RoomMsg', 'NickName':UserList.loc[UserList.obj_ws == websocket, 'NickName'].iloc[0], 'Data':Message}
        for index, row in UserList.iterrows():
            await row['obj_ws'].send(json.dumps(ret))

# 生成一个新的不重复的昵称
def NewNickName():
    str_head = 'Anonymous'
    str_NickName = str_head + str(random.randint(0,10000))
    while str_NickName in UserList['NickName'].values:
        str_NickName = str_head + str(random.randint(0,10000))
    return str_NickName

# 处理客户端消息
async def handler(websocket):
    try:
        while True:
            recv_text = await websocket.recv()
            data = json.loads(recv_text)
            if data['Type'] == 'SetNickName':
                await SetNickName(websocket, data['Data'])
            elif data['Type'] == 'RoomMsg':
                await SendRoomMsg(websocket, data['Data'])
    except websockets.exceptions.ConnectionClosed as e:
        LeftNickName = UserList.loc[UserList.obj_ws == websocket, 'NickName'].iloc[0]
        UserList.drop(index = UserList[UserList.obj_ws == websocket].index.tolist(), inplace = True)
        await SendRoomSystemMsg(LeftNickName + ' 离开')

# 新客户端连接
async def NewClient(websocket, path):
    global UserList
    NewNick = NewNickName()
    UserList = UserList.append({'obj_ws':websocket, 'IP':websocket.remote_address[0], 'NickName':NewNick, 'RoomID':-1}, ignore_index=True)
    await SendRoomSystemMsg('欢迎 ' + NewNick)
    await SetNickName(websocket, NewNick, True)
    await handler(websocket)

# 启动websocket服务器
start_server = websockets.serve(NewClient, '127.0.0.1', 666)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
