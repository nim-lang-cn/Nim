#
#
#            Nim's Runtime Library
#        (c) Copyright 2015 Dominik Picheta
#
#    See the file "copying.txt", included in this
#    distribution, for details about the copyright.
#


## 此模块实现RFC 3986指定的URI解析。
##
## 统一资源标识符(URI)提供了一种简单且可扩展的资源标识方法。URI可以进一步分类为定位程序、名称或两者。术语“统一资源定位器”(URL)指uri的子集。
##
## 基本用法
## ===========
##
## 拼接URIs
## -------------
## .. code-block::
##    import uri
##    let host = parseUri("https://nim-lang.org")
##    let blog = "/blog.html"
##    let bloguri = host / blog
##    assert $host == "https://nim-lang.org"
##    assert $bloguri == "https://nim-lang.org/blog.html"
##
## URI访问项目
## ---------------
## .. code-block::
##    import uri
##    let res = parseUri("sftp://127.0.0.1:4343")
##    if isAbsolute(res):
##      assert res.port == "4343"
##    else:
##      echo "Wrong format"

import strutils, parseutils
type
  Url* = distinct string

  Uri* = object
    scheme*, username*, password*: string
    hostname*, port*, path*, query*, anchor*: string
    opaque*: bool

proc encodeUrl*(s: string, usePlus = true): string =
  ## 这个模块按照 RFC3986 编码规范解析 URI
  ##
  ##
  ## ## 作为一个特殊的规则，当 ``usePlus``的值为真时，
  ## 空格被编码为``'+'``而不是 ``'%20'``。
  ##
  ## **See also:**
  ## * ``decodeUrl proc<#decodeUrl,string>``_
  runnableExamples:
    assert encodeUrl("https://nim-lang.org") == "https%3A%2F%2Fnim-lang.org"
    assert encodeUrl("https://nim-lang.org/this is a test") == "https%3A%2F%2Fnim-lang.org%2Fthis+is+a+test"
    assert encodeUrl("https://nim-lang.org/this is a test", false) == "https%3A%2F%2Fnim-lang.org%2Fthis%20is%20a%20test"
  result = newStringOfCap(s.len + s.len shr 2) # assume 12% non-alnum-chars
  let fromSpace = if usePlus: "+" else: "%20"
  for c in s:
    case c
    # https://tools.ietf.org/html/rfc3986#section-2.3
    of 'a'..'z', 'A'..'Z', '0'..'9', '-', '.', '_', '~': add(result, c)
    of ' ': add(result, fromSpace)
    else:
      add(result, '%')
      add(result, toHex(ord(c), 2))

proc decodeUrl*(s: string, decodePlus = true): string =
  ## 根据 RFC3986 对 URL 进行解码。
  ##
  ## 这意味着任何``'%xx'``(其中``xx``表示十六进制)被转换为序号为 ``xx``的字符，
  ## 其他所有的字符都被保留了下来。
  ##
  ## 作为一个特殊的规则，当``decodePlus``的值为真时，`` + `` `字符被转换为空格。
  ##
  ## **See also:**
  ## * `encodeUrl proc<#encodeUrl,string>`_
  runnableExamples:
    assert decodeUrl("https%3A%2F%2Fnim-lang.org") == "https://nim-lang.org"
    assert decodeUrl("https%3A%2F%2Fnim-lang.org%2Fthis+is+a+test") == "https://nim-lang.org/this is a test"
    assert decodeUrl("https%3A%2F%2Fnim-lang.org%2Fthis%20is%20a%20test",
        false) == "https://nim-lang.org/this is a test"
  proc handleHexChar(c: char, x: var int) {.inline.} =
    case c
    of '0'..'9': x = (x shl 4) or (ord(c) - ord('0'))
    of 'a'..'f': x = (x shl 4) or (ord(c) - ord('a') + 10)
    of 'A'..'F': x = (x shl 4) or (ord(c) - ord('A') + 10)
    else: assert(false)

  result = newString(s.len)
  var i = 0
  var j = 0
  while i < s.len:
    case s[i]
    of '%':
      var x = 0
      handleHexChar(s[i+1], x)
      handleHexChar(s[i+2], x)
      inc(i, 2)
      result[j] = chr(x)
    of '+':
      if decodePlus:
        result[j] = ' '
      else:
        result[j] = s[i]
    else: result[j] = s[i]
    inc(i)
    inc(j)
  setLen(result, j)

proc encodeQuery*(query: openArray[(string, string)], usePlus = true,
    omitEq = true): string =
  ## 将一组(键、值)参数编码到 URL 查询字符串中。
  ##
  ## 这些对由“&”字符连接在一起。
  ##
  ## ``usePlus``参数被传递给 ``encodeUrl`` 函数，该函数用于字符串值的URL编码。
  ##
  ## **See also:**
  ## * ``encodeUrl proc<#encodeUrl,string>``_
  runnableExamples:
    assert encodeQuery({: }) == ""
    assert encodeQuery({"a": "1", "b": "2"}) == "a=1&b=2"
    assert encodeQuery({"a": "1", "b": ""}) == "a=1&b"
  for elem in query:
    # 对 ``key = value`` 对进行编码，并用 ``&`` 分隔它们
    if result.len > 0: result.add('&')
    let (key, val) = elem
    result.add(encodeUrl(key, usePlus))
    # 如果值字符串为空，则省略'='
    if not omitEq or val.len > 0:
      result.add('=')
      result.add(encodeUrl(val, usePlus))

proc parseAuthority(authority: string, result: var Uri) =
  var i = 0
  var inPort = false
  var inIPv6 = false
  while i < authority.len:
    case authority[i]
    of '@':
      swap result.password, result.port
      result.port.setLen(0)
      swap result.username, result.hostname
      result.hostname.setLen(0)
      inPort = false
    of ':':
      if inIPv6:
        result.hostname.add(authority[i])
      else:
        inPort = true
    of '[':
      inIPv6 = true
    of ']':
      inIPv6 = false
    else:
      if inPort:
        result.port.add(authority[i])
      else:
        result.hostname.add(authority[i])
    i.inc

proc parsePath(uri: string, i: var int, result: var Uri) =

  i.inc parseUntil(uri, result.path, {'?', '#'}, i)

  # 'mailto'方案的路径实际上包含主机名/用户名
  if cmpIgnoreCase(result.scheme, "mailto") == 0:
    parseAuthority(result.path, result)
    result.path.setLen(0)

  if i < uri.len and uri[i] == '?':
    i.inc # Skip '?'
    i.inc parseUntil(uri, result.query, {'#'}, i)

  if i < uri.len and uri[i] == '#':
    i.inc # Skip '#'
    i.inc parseUntil(uri, result.anchor, {}, i)

proc initUri*(): Uri =
  ## 初始化一个URI 包含``scheme``、 ``username``, ``password``,
  ## ``hostname``, ``port``, ``path``, ``query`` and ``anchor``.
  ##
  ## **See also:**
  ## * ``Uri type <#Uri>``_ for available fields in the URI type
  runnableExamples:
    var uri2: Uri
    assert initUri() == uri2
  result = Uri(scheme: "", username: "", password: "", hostname: "", port: "",
                path: "", query: "", anchor: "")

proc resetUri(uri: var Uri) =
  for f in uri.fields:
    when f is string:
      f.setLen(0)
    else:
      f = false

proc parseUri*(uri: string, result: var Uri) =
  ## 解析一个URI，变量 ``result`` 将会在解析之前被清楚。
  ##
  ## **See also:**
  ## * ``Uri type <#Uri>``_ for available fields in the URI type
  ## * ``initUri proc <#initUri>``_ for initializing a URI
  runnableExamples:
    var res = initUri()
    parseUri("https://nim-lang.org/docs/manual.html", res)
    assert res.scheme == "https"
    assert res.hostname == "nim-lang.org"
    assert res.path == "/docs/manual.html"
  resetUri(result)

  var i = 0

  # 检查这是否是一个引用URI(相对URI)
  let doubleSlash = uri.len > 1 and uri[1] == '/'
  if i < uri.len and uri[i] == '/':
    # 确保 ``uri`` 不以 ``//`` 开头
    if not doubleSlash:
      parsePath(uri, i, result)
      return

  # 方案
  i.inc parseWhile(uri, result.scheme, Letters + Digits + {'+', '-', '.'}, i)
  if (i >= uri.len or uri[i] != ':') and not doubleSlash:
    # 假设这是一个引用URI(相对URI)
    i = 0
    result.scheme.setLen(0)
    parsePath(uri, i, result)
    return
  if not doubleSlash:
    i.inc # Skip ':'

  # Authority
  if i+1 < uri.len and uri[i] == '/' and uri[i+1] == '/':
    i.inc(2) # Skip //
    var authority = ""
    i.inc parseUntil(uri, authority, {'/', '?', '#'}, i)
    if authority.len > 0:
      parseAuthority(authority, result)
  else:
    result.opaque = true

  # Path
  parsePath(uri, i, result)

proc parseUri*(uri: string): Uri =
  ## 解析URI并返回它。
  ##
  ## **See also:**
  ## * ``Uri type <#Uri>`` _ for available fields in the URI type
  runnableExamples:
    let res = parseUri("ftp://Username:Password@Hostname")
    assert res.username == "Username"
    assert res.password == "Password"
    assert res.scheme == "ftp"
  result = initUri()
  parseUri(uri, result)

proc removeDotSegments(path: string): string =
  if path.len == 0: return ""
  var collection: seq[string] = @[]
  let endsWithSlash = path[path.len-1] == '/'
  var i = 0
  var currentSegment = ""
  while i < path.len:
    case path[i]
    of '/':
      collection.add(currentSegment)
      currentSegment = ""
    of '.':
      if i+2 < path.len and path[i+1] == '.' and path[i+2] == '/':
        if collection.len > 0:
          discard collection.pop()
          i.inc 3
          continue
      elif path[i+1] == '/':
        i.inc 2
        continue
      currentSegment.add path[i]
    else:
      currentSegment.add path[i]
    i.inc
  if currentSegment != "":
    collection.add currentSegment

  result = collection.join("/")
  if endsWithSlash: result.add '/'

proc merge(base, reference: Uri): string =
  # http://tools.ietf.org/html/rfc3986#section-5.2.3
  if base.hostname != "" and base.path == "":
    '/' & reference.path
  else:
    let lastSegment = rfind(base.path, "/")
    if lastSegment == -1:
      reference.path
    else:
      base.path[0 .. lastSegment] & reference.path

proc combine*(base: Uri, reference: Uri): Uri =
  ## 将基URI与引用URI组合。
  ##
  ## 这使用了指定的算法 ``section 5.2.2 of RFC 3986 <http://tools.ietf.org/html/rfc3986#section-5.2.2>``_.
  ##
  ## 这意味着基URI路径和引用URI路径中的斜线将影响结果URI。
  ##
  ## **See also:**
  ## * ``/ proc <#/,Uri,string>``_ for building URIs
  runnableExamples:
    let foo = combine(parseUri("https://nim-lang.org/foo/bar"), parseUri("/baz"))
    assert foo.path == "/baz"
    let bar = combine(parseUri("https://nim-lang.org/foo/bar"), parseUri("baz"))
    assert bar.path == "/foo/baz"
    let qux = combine(parseUri("https://nim-lang.org/foo/bar/"), parseUri("baz"))
    assert qux.path == "/foo/bar/baz"

  template setAuthority(dest, src): untyped =
    dest.hostname = src.hostname
    dest.username = src.username
    dest.port = src.port
    dest.password = src.password

  result = initUri()
  if reference.scheme != base.scheme and reference.scheme != "":
    result = reference
    result.path = removeDotSegments(result.path)
  else:
    if reference.hostname != "":
      setAuthority(result, reference)
      result.path = removeDotSegments(reference.path)
      result.query = reference.query
    else:
      if reference.path == "":
        result.path = base.path
        if reference.query != "":
          result.query = reference.query
        else:
          result.query = base.query
      else:
        if reference.path.startsWith("/"):
          result.path = removeDotSegments(reference.path)
        else:
          result.path = removeDotSegments(merge(base, reference))
        result.query = reference.query
      setAuthority(result, base)
    result.scheme = base.scheme
  result.anchor = reference.anchor

proc combine*(uris: varargs[Uri]): Uri =
  ## 将多个uri组合在一起。
  ##
  ## **See also:**
  ## * ``/ proc <#/,Uri,string>``_ for building URIs
  runnableExamples:
    let foo = combine(parseUri("https://nim-lang.org/"), parseUri("docs/"),
        parseUri("manual.html"))
    assert foo.hostname == "nim-lang.org"
    assert foo.path == "/docs/manual.html"
  result = uris[0]
  for i in 1 ..< uris.len:
    result = combine(result, uris[i])

proc isAbsolute*(uri: Uri): bool =
  ## 如果URI是绝对的，则返回true，否则返回false
  runnableExamples:
    let foo = parseUri("https://nim-lang.org")
    assert isAbsolute(foo) == true
    let bar = parseUri("nim-lang")
    assert isAbsolute(bar) == false
  return uri.scheme != "" and (uri.hostname != "" or uri.path != "")

proc ``/``*(x: Uri, path: string): Uri =
  ## 将指定的路径连接到指定URI的路径。
  ##
  ## 与“组合”过程相反，您不必分别担心路径的开始和结束处的斜线和URI的路径
  ##
  ## **See also:**
  ## * ``combine proc <#combine,Uri,Uri>``_
  runnableExamples:
    let foo = parseUri("https://nim-lang.org/foo/bar") / "/baz"
    assert foo.path == "/foo/bar/baz"
    let bar = parseUri("https://nim-lang.org/foo/bar") / "baz"
    assert bar.path == "/foo/bar/baz"
    let qux = parseUri("https://nim-lang.org/foo/bar/") / "baz"
    assert qux.path == "/foo/bar/baz"
  result = x

  if result.path.len == 0:
    if path.len == 0 or path[0] != '/':
      result.path = "/"
    result.path.add(path)
    return

  if result.path.len > 0 and result.path[result.path.len-1] == '/':
    if path.len > 0 and path[0] == '/':
      result.path.add(path[1 .. path.len-1])
    else:
      result.path.add(path)
  else:
    if path.len == 0 or path[0] != '/':
      result.path.add '/'
    result.path.add(path)

proc ``?``*(u: Uri, query: openArray[(string, string)]): Uri =
  ## 将查询参数连接到指定的URI对象。
  runnableExamples:
    let foo = parseUri("https://example.com") / "foo" ? {"bar": "qux"}
    assert $foo == "https://example.com/foo?bar=qux"
  result = u
  result.query = encodeQuery(query)

proc ``$``*(u: Uri): string =
  ## 返回指定URI对象的字符串表示形式。
  runnableExamples:
    let foo = parseUri("https://nim-lang.org")
    assert $foo == "https://nim-lang.org"
  result = ""
  if u.scheme.len > 0:
    result.add(u.scheme)
    if u.opaque:
      result.add(":")
    else:
      result.add("://")
  if u.username.len > 0:
    result.add(u.username)
    if u.password.len > 0:
      result.add(":")
      result.add(u.password)
    result.add("@")
  if u.hostname.endsWith('/'):
    result.add(u.hostname[0..^2])
  else:
    result.add(u.hostname)
  if u.port.len > 0:
    result.add(":")
    result.add(u.port)
  if u.path.len > 0:
    if u.hostname.len > 0 and u.path[0] != '/':
      result.add('/')
    result.add(u.path)
  if u.query.len > 0:
    result.add("?")
    result.add(u.query)
  if u.anchor.len > 0:
    result.add("#")
    result.add(u.anchor)

when isMainModule:
  block:
    const test1 = "abc\L+def xyz"
    doAssert encodeUrl(test1) == "abc%0A%2Bdef+xyz"
    doAssert decodeUrl(encodeUrl(test1)) == test1
    doAssert encodeUrl(test1, false) == "abc%0A%2Bdef%20xyz"
    doAssert decodeUrl(encodeUrl(test1, false), false) == test1
    doAssert decodeUrl(encodeUrl(test1)) == test1

  block:
    let str = "http://localhost"
    let test = parseUri(str)
    doAssert test.path == ""

  block:
    let str = "http://localhost/"
    let test = parseUri(str)
    doAssert test.path == "/"

  block:
    let str = "http://localhost:8080/test"
    let test = parseUri(str)
    doAssert test.scheme == "http"
    doAssert test.port == "8080"
    doAssert test.path == "/test"
    doAssert test.hostname == "localhost"
    doAssert($test == str)

  block:
    let str = "foo://username:password@example.com:8042/over/there" &
              "/index.dtb?type=animal&name=narwhal#nose"
    let test = parseUri(str)
    doAssert test.scheme == "foo"
    doAssert test.username == "username"
    doAssert test.password == "password"
    doAssert test.hostname == "example.com"
    doAssert test.port == "8042"
    doAssert test.path == "/over/there/index.dtb"
    doAssert test.query == "type=animal&name=narwhal"
    doAssert test.anchor == "nose"
    doAssert($test == str)

  block:
    # IPv6 地址
    let str = "foo://[::1]:1234/bar?baz=true&qux#quux"
    let uri = parseUri(str)
    doAssert uri.scheme == "foo"
    doAssert uri.hostname == "::1"
    doAssert uri.port == "1234"
    doAssert uri.path == "/bar"
    doAssert uri.query == "baz=true&qux"
    doAssert uri.anchor == "quux"

  block:
    let str = "urn:example:animal:ferret:nose"
    let test = parseUri(str)
    doAssert test.scheme == "urn"
    doAssert test.path == "example:animal:ferret:nose"
    doAssert($test == str)

  block:
    let str = "mailto:username@example.com?subject=Topic"
    let test = parseUri(str)
    doAssert test.scheme == "mailto"
    doAssert test.username == "username"
    doAssert test.hostname == "example.com"
    doAssert test.query == "subject=Topic"
    doAssert($test == str)

  block:
    let str = "magnet:?xt=urn:sha1:72hsga62ba515sbd62&dn=foobar"
    let test = parseUri(str)
    doAssert test.scheme == "magnet"
    doAssert test.query == "xt=urn:sha1:72hsga62ba515sbd62&dn=foobar"
    doAssert($test == str)

  block:
    let str = "/test/foo/bar?q=2#asdf"
    let test = parseUri(str)
    doAssert test.scheme == ""
    doAssert test.path == "/test/foo/bar"
    doAssert test.query == "q=2"
    doAssert test.anchor == "asdf"
    doAssert($test == str)

  block:
    let str = "test/no/slash"
    let test = parseUri(str)
    doAssert test.path == "test/no/slash"
    doAssert($test == str)

  block:
    let str = "//git@github.com:dom96/packages"
    let test = parseUri(str)
    doAssert test.scheme == ""
    doAssert test.username == "git"
    doAssert test.hostname == "github.com"
    doAssert test.port == "dom96"
    doAssert test.path == "/packages"

  block:
    let str = "file:///foo/bar/baz.txt"
    let test = parseUri(str)
    doAssert test.scheme == "file"
    doAssert test.username == ""
    doAssert test.hostname == ""
    doAssert test.port == ""
    doAssert test.path == "/foo/bar/baz.txt"

  # Remove dot segments tests
  block:
    doAssert removeDotSegments("/foo/bar/baz") == "/foo/bar/baz"

  # 集成测试（结合测试）
  block:
    let concat = combine(parseUri("http://google.com/foo/bar/"), parseUri("baz"))
    doAssert concat.path == "/foo/bar/baz"
    doAssert concat.hostname == "google.com"
    doAssert concat.scheme == "http"

  block:
    let concat = combine(parseUri("http://google.com/foo"), parseUri("/baz"))
    doAssert concat.path == "/baz"
    doAssert concat.hostname == "google.com"
    doAssert concat.scheme == "http"

  block:
    let concat = combine(parseUri("http://google.com/foo/test"), parseUri("bar"))
    doAssert concat.path == "/foo/bar"

  block:
    let concat = combine(parseUri("http://google.com/foo/test"), parseUri("/bar"))
    doAssert concat.path == "/bar"

  block:
    let concat = combine(parseUri("http://google.com/foo/test"), parseUri("bar"))
    doAssert concat.path == "/foo/bar"

  block:
    let concat = combine(parseUri("http://google.com/foo/test/"), parseUri("bar"))
    doAssert concat.path == "/foo/test/bar"

  block:
    let concat = combine(parseUri("http://google.com/foo/test/"), parseUri("bar/"))
    doAssert concat.path == "/foo/test/bar/"

  block:
    let concat = combine(parseUri("http://google.com/foo/test/"), parseUri("bar/"),
                         parseUri("baz"))
    doAssert concat.path == "/foo/test/bar/baz"

  # ``/`` tests
  block:
    let test = parseUri("http://example.com/foo") / "bar/asd"
    doAssert test.path == "/foo/bar/asd"

  block:
    let test = parseUri("http://example.com/foo/") / "/bar/asd"
    doAssert test.path == "/foo/bar/asd"

  # removeDotSegments tests
  block:
    # empty test
    doAssert removeDotSegments("") == ""

  # bug #3207
  block:
    doAssert parseUri("http://qq/1").combine(parseUri("https://qqq")). ``$`` == "https://qqq"

  # bug #4959
  block:
    let foo = parseUri("http://example.com") / "/baz"
    doAssert foo.path == "/baz"

  # bug found on stream 13/10/17
  block:
    let foo = parseUri("http://localhost:9515") / "status"
    doAssert $foo == "http://localhost:9515/status"

  # bug #6649 #6652
  block:
    var foo = parseUri("http://example.com")
    foo.hostname = "example.com"
    foo.path = "baz"
    doAssert $foo == "http://example.com/baz"

    foo.hostname = "example.com/"
    foo.path = "baz"
    doAssert $foo == "http://example.com/baz"

    foo.hostname = "example.com"
    foo.path = "/baz"
    doAssert $foo == "http://example.com/baz"

    foo.hostname = "example.com/"
    foo.path = "/baz"
    doAssert $foo == "http://example.com/baz"

    foo.hostname = "example.com/"
    foo.port = "8000"
    foo.path = "baz"
    doAssert $foo == "http://example.com:8000/baz"

    foo = parseUri("file:/dir/file")
    foo.path = "relative"
    doAssert $foo == "file:relative"

  # isAbsolute tests
  block:
    doAssert "www.google.com".parseUri().isAbsolute() == false
    doAssert "http://www.google.com".parseUri().isAbsolute() == true
    doAssert "file:/dir/file".parseUri().isAbsolute() == true
    doAssert "file://localhost/dir/file".parseUri().isAbsolute() == true
    doAssert "urn:ISSN:1535-3613".parseUri().isAbsolute() == true

    # path-relative URL *relative
    doAssert "about".parseUri().isAbsolute == false
    doAssert "about/staff.html".parseUri().isAbsolute == false
    doAssert "about/staff.html?".parseUri().isAbsolute == false
    doAssert "about/staff.html?parameters".parseUri().isAbsolute == false

    # absolute-path-relative URL *relative
    doAssert "/".parseUri().isAbsolute == false
    doAssert "/about".parseUri().isAbsolute == false
    doAssert "/about/staff.html".parseUri().isAbsolute == false
    doAssert "/about/staff.html?".parseUri().isAbsolute == false
    doAssert "/about/staff.html?parameters".parseUri().isAbsolute == false

    # scheme-relative URL *relative
    doAssert "//username:password@example.com:8888".parseUri().isAbsolute == false
    doAssert "//username@example.com".parseUri().isAbsolute == false
    doAssert "//example.com".parseUri().isAbsolute == false
    doAssert "//example.com/".parseUri().isAbsolute == false
    doAssert "//example.com/about".parseUri().isAbsolute == false
    doAssert "//example.com/about/staff.html".parseUri().isAbsolute == false
    doAssert "//example.com/about/staff.html?".parseUri().isAbsolute == false
    doAssert "//example.com/about/staff.html?parameters".parseUri().isAbsolute == false

    # absolute URL *absolute
    doAssert "https://username:password@example.com:8888".parseUri().isAbsolute == true
    doAssert "https://username@example.com".parseUri().isAbsolute == true
    doAssert "https://example.com".parseUri().isAbsolute == true
    doAssert "https://example.com/".parseUri().isAbsolute == true
    doAssert "https://example.com/about".parseUri().isAbsolute == true
    doAssert "https://example.com/about/staff.html".parseUri().isAbsolute == true
    doAssert "https://example.com/about/staff.html?".parseUri().isAbsolute == true
    doAssert "https://example.com/about/staff.html?parameters".parseUri().isAbsolute == true

  # encodeQuery tests
  block:
    doAssert encodeQuery({:}) == ""
    doAssert encodeQuery({"foo": "bar"}) == "foo=bar"
    doAssert encodeQuery({"foo": "bar & baz"}) == "foo=bar+%26+baz"
    doAssert encodeQuery({"foo": "bar & baz"}, usePlus = false) == "foo=bar%20%26%20baz"
    doAssert encodeQuery({"foo": ""}) == "foo"
    doAssert encodeQuery({"foo": ""}, omitEq = false) == "foo="
    doAssert encodeQuery({"a": "1", "b": "", "c": "3"}) == "a=1&b&c=3"
    doAssert encodeQuery({"a": "1", "b": "", "c": "3"}, omitEq = false) == "a=1&b=&c=3"

    block:
      var foo = parseUri("http://example.com") / "foo" ? {"bar": "1", "baz": "qux"}
      var foo1 = parseUri("http://example.com/foo?bar=1&baz=qux")
      doAssert foo == foo1

    block:
      var foo = parseUri("http://example.com") / "foo" ? {"do": "do", "bar": ""}
      var foo1 = parseUri("http://example.com/foo?do=do&bar")
      doAssert foo == foo1

  echo("All good!")
