@Grab(group = 'commons-httpclient', module = 'commons-httpclient', version = '3.0.1')
import org.apache.commons.httpclient.HttpClient

debug = false
show = ['settings':true, 'config':false, 'cookies':false, 'headers':false, 'data':false]
defaults = ['resetSession':false, 'addReferer':false, 'followRedirects':false, 'localAddress':null, 'proxy':null, 'headers':[:], 'expectedStatus':200]
options = ['{{{':~/^#\{\{\{/, '}}}':~/^\}\}\}$/, '{':~/^\{$/, '}':~/^\}$/, 
               'Get':~'^Get: (.*)', 'Post':~'^Post: (.*)', 'Head':~'^Head: (.*)',
               'Cookie':~'^Cookie: (.*)', 'RequestHeader':~'^Header: (.*)', 'Parameter':~'^Parameter: (.*)',
               'FollowRedirects':~'^FollowRedirects: (.*)', 'LocalAddress':~'^LocalAddress: (.*)', 'Proxy':~'^Proxy: (.*)',
               'expectedStatus':~'^ExpectedStatus: (.*)', 'expectedData':~'^ExpectedData: (.*)', 'expectedHeaders':~'^ExpectedHeader: (.*)', 'expectedCookies':~'^ExpectedCookie: (.*)', 'dataFileName':~'^SaveData: (.*)']
inets = null
session = null
tests = []

java.util.logging.Logger.getLogger("org.apache.commons.httpclient").setLevel(java.util.logging.Level.SEVERE);


def lookupIP(ipstr) {                                                           ;if (debug) println "DEBUG: lookupIP(${ipstr})"
  if (!inets) NetworkInterface.networkInterfaces.each {ni-> ni.inetAddresses.each {inet-> inets.add(inet) }}
  ipstr = '/' + ipstr
  return inets.find {inet-> ipstr == inet.toString() }
}

def splitNVP(line) {                                                            ;if (debug) println "DEBUG: splitNVP(${line})"
  int index = line.indexOf('=')
  return [line.substring(0,index).trim(), line.substring(index+1).trim()]
}

def initTest(name, conditional, disabled) {                                     ;if (debug) println "DEBUG: initTest(${name})"
  def t = ['name':name, 'conditional':conditional, 'disabled':disabled]
  if (session==null || defaults.resetSession)
    session = new HttpClient()
  t.expectedStatus = defaults.expectedStatus
  t.expectedData = []
  t.expectedHeaders = [:]
  t.expectedCookies = [:]
  t.errors = []
  return t
}

def initMethod(mthd, prev) {                                                    ;if (debug) println "DEBUG: initMethod()"
  mthd.followRedirects = defaults.followRedirects
  if (defaults.localAddress)
    mthd.hostConfiguration.localAddress = lookupIP(defaults.localAddress) 
  if (defaults.proxy) {
    hostAndPort = defaults.proxy.tokenize(':')
    mthd.hostConfiguration.setProxy(hostAndPort[0], hostAndPort[1]?Integer.parseInt(hostAndPort[1]):80)  
  }
  defaults.headers.each {header-> mthd.setRequestHeader(header.key, header.value)}
  if (defaults.addReferer && prev.url)
    mthd.setRequestHeader('Referer', prev.url)
  return mthd
}

def showBefore(t) {                                                             ;if (debug) println "DEBUG: showBefore()"
  if (show.settings) {
    println "SETTINGS:"
    println "  host=${t.call.hostConfiguration.host}"
    if (t.call.hostConfiguration.localAddress)
      println "  localAddress=${t.call.hostConfiguration.localAddress}"
  }
  if (show.cookies) {
    println "COOKIES-BEFORE:"
    session.state.cookies.each {item-> println "  ${item.name}=${item.value} (domain=${item.domain}, path=${item.path})"}
  }  
}

def showAfter(t) {                                                              ;if (debug) println "DEBUG: showAfter()"
  println "REQUEST: ${t.call.name} ${t.call.path}${((t.call.queryString) ? '?'+t.call.queryString : '')}"
  if (show.settings) 
    println "  statusLine=${t.statusLine}\n  status=${t.status}"
  if (show.headers) {
    println "REQUEST-HEADERS:"
    t.call.requestHeaders.each {item-> print "  ${item}"}   
    println "RESPONSE-HEADERS:"
    t.call.responseHeaders.each {item-> print "  ${item}"}
  }
  if (show.cookies) {
    println "COOKIES-AFTER:"
    session.state.cookies.each {item-> println "  ${item.name}=${item.value} (domain=${item.domain}, path=${item.path})"}
  }  
  if (show.data) 
    println "DATA: ${t.data.size()}\n${t.data}"
}

def checkForErrors(t) {                                                         ;if (debug) println "DEBUG: checkForErrors()"
  if (t.expectedStatus && t.expectedStatus.toString() != t.status.toString())                         
    t.errors.add("ERROR-STATUS: expected='${t.expectedStatus}' actual='${t.status}'")
  t.expectedHeaders.each {item-> 
    def header = t.call.getResponseHeader(item.key)
    def act = (header)? header.value : null
    if (!header || !(act == item.value))
      t.errors.add("ERROR-HEADER: ${item.key} expected=${item.value} actual=${act}")
  }
  t.expectedCookies.each {item->
    def cookie = t.cookies[item.key]
    def act = (cookie)? cookie.value : null
    def pattern = (item.value)? ~item.value : null
    if (!cookie || !(act ==~ pattern)) 
      t.errors.add("ERROR-COOKIE: ${item.key} expected=${item.value} actual=${act}")
  } 
  t.expectedData.each {item-> if (t.data.indexOf(item) < 0) t.errors.add("ERROR-DATA: ${item}") }
}

def doTest(t, prev) {                                                           ;if (debug) println "DEBUG: doTest()"
  if (!t.disabled && (!t.conditional || !prev.errors)) {
    if (!t.call) 
      test.errors.add("ERROR: no call method defined")
    else {
      showBefore(t)
      try {
        t.status = session.executeMethod(t.call);
        t.statusLine = t.call.statusLine;
        t.url = t.call.URI.toString()
        t.cookies = [:]
        session.state.cookies.each {cookie-> t.cookies.put(cookie.name, cookie)}
        t.headers = [:]
        t.call.responseHeaders.each {header-> t.headers.put(header.name, header.value)}
        t.data = t.call.responseBodyAsString
        if (t.dataFileName) { // byte by byte copy is a "tad" inefficient to say the least... oh well
          def out = new File(t.dataFileName).newOutputStream()
          t.call.getResponseBodyAsStream().eachByte {b-> out.write((int)b)}
          out.close()
        }
        checkForErrors(t)
      }
      catch (Exception e) {
        t.errors.add("ERROR: ${e}, ${e.message}")
      }
      showAfter(t)
    }
    if (t.errors) {t.errors.each{err->println err}} else { println "PASSED!" }
  }  
  tests.add(t)
}

  int lineNum = 0
  def code = ''
  def name = null
  def test = null
  def previousTest = [:]
  boolean inBlock = false, inTest = false
  boolean conditional = false, disabled = false;
  String item = null; 
  part = null;
  
  new File(args[0]).eachLine {line->                                              ;if (debug) println "DEBUG ${++lineNum}: ${line}" 
    item = line.trim()
    if (item != '' && !item.startsWith(';') && !item.startsWith('//')) {
      if (inTest && show.config && item != '}') println '  '+item
      if (inBlock && item != '}}}') 
        code += item + '\n' 
      else {
        def matcher = null
        def option = options.find {o-> (matcher = o.value.matcher(item)).matches()}
        if (option) {
          part = matcher.groupCount()>0?evaluate('"'+matcher.group(1)+'"'):''     ;if (debug) println "DEBUG ${lineNum}>>> option.key=${option.key}, part=${part}"                       
          switch (option.key) {                                                   
            case '{{{':
              inBlock = true
              break;
            case '}}}':
              inBlock = false
              evaluate(code)
              code = ''
              break;
            case '{':
              inTest = true
              println "\n${name?name:''}\n{"
              test = initTest(name, conditional, disabled)
              break
            case '}':
              inTest = false
              doTest(test, previousTest)
              println "}\n"
              previousTest.data = null // save memory when there are many tests (maybe this should be an option)
              previousTest = test
              break
              
            case ['Get', 'Post', 'Head']:
              if (!test.name) test.name = part;  
              test.call = initMethod(evaluate("new org.apache.commons.httpclient.methods.${option.key}Method(part)"), previousTest)
              break
              
            case 'Cookie':
              def params = [:] 
              part.tokenize('; ').each {subpart-> params.put(splitNVP(subpart)) }
              session.state.addCookie(new org.apache.commons.httpclient.Cookie(params))
              break
            case 'RequestHeader':
              test.call.setRequestHeader(splitNVP(part))
              break
            case 'Parameter':  
              test.call.addParameter(splitNVP(part))
              break
            case 'FollowRedirects':
              test.call.followRedirects = part.equals('true')
              break
            case 'LocalAddress':
              test.call.hostConfiguration.localAddress = lookupIP(part) 
              break
            case 'Proxy':
              hostAndPort = part.tokenize(':')
              test.call.hostConfiguration.setProxy(hostAndPort[0], hostAndPort[1]?Integer.parseInt(hostAndPort[1]):80)
              break
  
            case 'expectedStatus':
              test.expectedStatus = part
              break
            case 'dataFileName':
              test.dataFileName = part
              break
            case 'expectedData':
              test.expectedData.add(part) 
              break
            case 'expectedHeaders':
              test.expectedHeaders.put(splitNVP(part))
              break
            case 'expectedCookies':
              test.expectedCookies.put(splitNVP(part))
              break
          }
        } 
        else if (item =~ '.*=.*' || item =~ '^print') {                           ;if (debug) println "DEBUG ${lineNum}: ${item}"
          evaluate(item)                                                          
        }
        else { 
          part = evaluate('"'+item+'"')                    
          disabled = part.startsWith('-')
          conditional = part.startsWith('?')
          name = (disabled||conditional)?part.substring(1):part
        }
      }
    }
  }
  
  failed = tests.findAll {t-> t.errors}
  println "\nPASSED: ${tests.size() - failed.size()}\n"
  println "FAILED: ${failed.size()}\n"
  failed.each {t-> println '   '+t.name; t.errors.each{err-> println '      '+err}; println ''}
