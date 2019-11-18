#
#
#            Nim's Runtime Library
#        (c) Copyright 2012 Dominik Picheta
#
#    See the file "copying.txt", included in this
#    distribution, for details about the copyright.
#

## 该模块实现了 SMTP 客户端协议 RFC 5321,
## 可以用于向任意的 SMTP 服务器发送邮件.
##
## 该模块也实现了发送格式化消息的协议
## 即 RFC 2822.
##
## 发送邮件的例子:
##
##
## .. code-block:: Nim
##   var msg = createMessage("Hello from Nim's SMTP",
##                           "Hello!.\n Is this awesome or what?",
##                           @["foo@gmail.com"])
##   let smtpConn = newSmtp(useSsl = true, debug=true)
##   smtpConn.connect("smtp.gmail.com", Port 465)
##   smtpConn.auth("username", "password")
##   smtpConn.sendmail("username@gmail.com", @["foo@gmail.com"], $msg)
##
##
## 使用 startTls 的例子:
##
##
## .. code-block:: Nim
##   var msg = createMessage("Hello from Nim's SMTP",
##                           "Hello!.\n Is this awesome or what?",
##                           @["foo@gmail.com"])
##   let smtpConn = newSmtp(debug=true)
##   smtpConn.connect("smtp.mailtrap.io", Port 2525)
##   smtpConn.startTls()
##   smtpConn.auth("username", "password")
##   smtpConn.sendmail("username@gmail.com", @["foo@gmail.com"], $msg)
##
##
## 该模块需要安装 OpenSSL 来获取 SSL 支持。如果你想
## 开启 SSL, 编译命令添加 ``-d:ssl``。

import net, strutils, strtabs, base64, os
import asyncnet, asyncdispatch

export Port

type
  Message* = object
    msgTo: seq[string]
    msgCc: seq[string]
    msgSubject: string
    msgOtherHeaders: StringTableRef
    msgBody: string

  ReplyError* = object of IOError

  SmtpBase[SocketType] = ref object
    sock: SocketType
    debug: bool

  Smtp* = SmtpBase[Socket]
  AsyncSmtp* = SmtpBase[AsyncSocket]

proc debugSend(smtp: Smtp | AsyncSmtp, cmd: string) {.multisync.} =
  if smtp.debug:
    echo("C:" & cmd)
  await smtp.sock.send(cmd)

proc debugRecv(smtp: Smtp | AsyncSmtp): Future[TaintedString] {.multisync.} =
  result = await smtp.sock.recvLine()
  if smtp.debug:
    echo("S:" & result.string)

proc quitExcpt(smtp: Smtp, msg: string) =
  smtp.debugSend("QUIT")
  raise newException(ReplyError, msg)

const compiledWithSsl = defined(ssl)

when not defined(ssl):
  type PSSLContext = ref object
  let defaultSSLContext: PSSLContext = nil
else:
  var defaultSSLContext {.threadvar.}: SSLContext

  proc getSSLContext(): SSLContext =
    if defaultSSLContext == nil:
      defaultSSLContext = newContext(verifyMode = CVerifyNone)
    result = defaultSSLContext

proc createMessage*(mSubject, mBody: string, mTo, mCc: seq[string],
                otherHeaders: openarray[tuple[name, value: string]]): Message =
  ## 创建一个新的 MIME 兼容的 Message 对象。
  result.msgTo = mTo
  result.msgCc = mCc
  result.msgSubject = mSubject
  result.msgBody = mBody
  result.msgOtherHeaders = newStringTable()
  for n, v in items(otherHeaders):
    result.msgOtherHeaders[n] = v

proc createMessage*(mSubject, mBody: string, mTo,
                    mCc: seq[string] = @[]): Message =
  ## 以上函数的替代版本。
  result.msgTo = mTo
  result.msgCc = mCc
  result.msgSubject = mSubject
  result.msgBody = mBody
  result.msgOtherHeaders = newStringTable()

proc `$`*(msg: Message): string =
  ## ``Message`` 对象的字符串表示。
  result = ""
  if msg.msgTo.len() > 0:
    result = "TO: " & msg.msgTo.join(", ") & "\c\L"
  if msg.msgCc.len() > 0:
    result.add("CC: " & msg.msgCc.join(", ") & "\c\L")
  # TODO: Folding? i.e when a line is too long, shorten it...
  result.add("Subject: " & msg.msgSubject & "\c\L")
  for key, value in pairs(msg.msgOtherHeaders):
    result.add(key & ": " & value & "\c\L")

  result.add("\c\L")
  result.add(msg.msgBody)

proc newSmtp*(useSsl = false, debug = false,
              sslContext: SSLContext = nil): Smtp =
  ## 创建一个新的 ``Smtp`` 对象。
  new result
  result.debug = debug
  result.sock = newSocket()
  if useSsl:
    when compiledWithSsl:
      if sslContext == nil:
        getSSLContext().wrapSocket(result.sock)
      else:
        sslContext.wrapSocket(result.sock)
    else:
      {.error: "SMTP module compiled without SSL support".}

proc newAsyncSmtp*(useSsl = false, debug = false,
                   sslContext: SSLContext = nil): AsyncSmtp =
  ## 创建一个新的 ``AsyncSmtp`` 对象。
  new result
  result.debug = debug

  result.sock = newAsyncSocket()
  if useSsl:
    when compiledWithSsl:
      if sslContext == nil:
        getSSLContext().wrapSocket(result.sock)
      else:
        sslContext.wrapSocket(result.sock)
    else:
      {.error: "SMTP module compiled without SSL support".}

proc quitExcpt(smtp: AsyncSmtp, msg: string): Future[void] =
  var retFuture = newFuture[void]()
  var sendFut = smtp.debugSend("QUIT")
  sendFut.callback =
    proc () =
      retFuture.fail(newException(ReplyError, msg))
  return retFuture

proc checkReply(smtp: Smtp | AsyncSmtp, reply: string) {.multisync.} =
  var line = await smtp.debugRecv()
  if not line.startswith(reply):
    await quitExcpt(smtp, "Expected " & reply & " reply, got: " & line)

proc connect*(smtp: Smtp | AsyncSmtp,
              address: string, port: Port) {.multisync.} =
  ## 建立与 SMTP 服务器的连接。
  ## 可能因为 ReplyError 或者 socket error 导致连接失败。
  await smtp.sock.connect(address, port)

  await smtp.checkReply("220")
  await smtp.debugSend("HELO " & address & "\c\L")
  await smtp.checkReply("250")

proc startTls*(smtp: Smtp | AsyncSmtp, sslContext: SSLContext = nil) {.multisync.} =
  ## 为 SMTP 连接开启 TLS (Transport Layer Security) 模式。
  ## 可能因为 ReplyError 导致连接失败。
  await smtp.debugSend("STARTTLS\c\L")
  await smtp.checkReply("220")
  when compiledWithSsl:
    if sslContext == nil:
      getSSLContext().wrapConnectedSocket(smtp.sock, handshakeAsClient)
    else:
      sslContext.wrapConnectedSocket(smtp.sock, handshakeAsClient)
  else:
    {.error: "SMTP module compiled without SSL support".}

proc auth*(smtp: Smtp | AsyncSmtp, username, password: string) {.multisync.} =
  ## 向服务器发送 AUTH 命令，
  ## 使用 `username` 和 `password` 登录。
  ## 可能因为 ReplyError 导致连接失败。

  await smtp.debugSend("AUTH LOGIN\c\L")
  await smtp.checkReply("334") # TODO: Check whether it's asking for the "Username:"
                               # i.e "334 VXNlcm5hbWU6"
  await smtp.debugSend(encode(username) & "\c\L")
  await smtp.checkReply("334") # TODO: Same as above, only "Password:" (I think?)

  await smtp.debugSend(encode(password) & "\c\L")
  await smtp.checkReply("235") # Check whether the authentication was successful.

proc sendMail*(smtp: Smtp | AsyncSmtp, fromAddr: string,
               toAddrs: seq[string], msg: string) {.multisync.} =
  ## 发送 来自 ``fromAddr`` 的 ``msg``  到目标地址 ``toAddrs``.
  ## 可以使用 ``createMessage`` 创建格式化的 Messages 对象，
  ## 然后再将 Message 对象转换为字符串。

  await smtp.debugSend("MAIL FROM:<" & fromAddr & ">\c\L")
  await smtp.checkReply("250")
  for address in items(toAddrs):
    await smtp.debugSend("RCPT TO:<" & address & ">\c\L")
    await smtp.checkReply("250")

  # Send the message
  await smtp.debugSend("DATA " & "\c\L")
  await smtp.checkReply("354")
  await smtp.sock.send(msg & "\c\L")
  await smtp.debugSend(".\c\L")
  await smtp.checkReply("250")

proc close*(smtp: Smtp | AsyncSmtp) {.multisync.} =
  # 断开与 SMTP 服务器的连接并关闭 socket。
  await smtp.debugSend("QUIT\c\L")
  smtp.sock.close()

when not defined(testing) and isMainModule:
  # 为了测试一个真实的 SMTP 服务，创建 smtp.ini 文件，即
  # username = ""
  # password = ""
  # smtphost = "smtp.gmail.com"
  # port = 465
  # use_tls = true
  # sender = ""
  # recipient = ""

  import parsecfg

  proc `[]`(c: Config, key: string): string = c.getSectionValue("", key)

  let
    conf = loadConfig("smtp.ini")
    msg = createMessage("Hello from Nim's SMTP!",
      "Hello!\n Is this awesome or what?", @[conf["recipient"]])

  assert conf["smtphost"] != ""

  proc async_test() {.async.} =
    let client = newAsyncSmtp(
      conf["use_tls"].parseBool,
      debug = true
    )
    await client.connect(conf["smtphost"], conf["port"].parseInt.Port)
    await client.auth(conf["username"], conf["password"])
    await client.sendMail(conf["sender"], @[conf["recipient"]], $msg)
    await client.close()
    echo "async email sent"

  proc sync_test() =
    var smtpConn = newSmtp(
      conf["use_tls"].parseBool,
      debug = true
    )
    smtpConn.connect(conf["smtphost"], conf["port"].parseInt.Port)
    smtpConn.auth(conf["username"], conf["password"])
    smtpConn.sendMail(conf["sender"], @[conf["recipient"]], $msg)
    smtpConn.close()
    echo "sync email sent"

  waitFor async_test()
  sync_test()
