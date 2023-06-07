description = [[
  Get HTTP Response Body
]]

---
-- @usage
-- nmap -p 8081 <ip> --script http-response
--
-- @output
-- PORT     STATE SERVICE
-- 8081/tcp open  unknown
-- | http-response:
-- |   body:              "xxxxx"
--
--

author = {"bees"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}


local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"
local http = require "http"
-- https://github.com/nmap/nmap/blob/master/nselib/http.lua
-- https://nmap.org/book/nse-api.html#nse-api-arguments





local function dbg(str, ...)
  stdnse.debug2(str, ...)
end

local function dbgt(tbl)
  for k,v in pairs(tbl) do
    dbg(" %s = %s " , tostring(k), tostring(v))
  end
end


-- 根据status code判断是否重定向
local function isRedirect(status)
  if status == nil then
    return false
  end
  return status >= 300 and status <=399
end


portrule = function(host, port)
  local service_fp = port.version.service_fp
  local service = port.version.name
  local pattern = "HTTP/1\\.[01]\\x20[0-9][0-9][0-9]\\x20"
  stdnse.print_debug(1, "%s: %s", SCRIPT_NAME, service_fp)
  if service ~= nil and string.match(service, 'http') then
      return true
  elseif service_fp ~= nil and string.match(service_fp, pattern) then
      return true
  else
      return false
  end
end

https_service_arr = {'https', 'https-alt'}

-- 是否在数组中
local function isInArray(arr, val)
	for _, v in ipairs(arr) do
		if v == val then
			return true
		end
	end
	return false
end

-- 主要功能
action = function(host, port)
  local options = {header={}}
  local service = port.version.name
  options['header']['User-Agent'] = "Mozilla/5.0 (compatible; YDLAB_SecTeam; Windows NT 6.3; Win64; x64)"
  options['no_cache'] = true
  options['redirect_ok'] = 3
  if service == 'https' or service == 'https-alt' then
    options['scheme'] = 'https'
  end
  local path = '/'
  local response = http.get(host, port, path, options)
  -- redirect? nmap can auto redirect, fllow code is not need
  if response and isRedirect(response.status) and response.header and response.header.location then
    local u = url.parse(response.header.location)
    u.host = u.host or stdnse.get_hostname(host)
    u.port = u.port or url.get_default_port(u.scheme) or port.number
    u.path = url.absolute(path, u.path or '/')
    if ( u.query ) then
      u.path = ("%s?%s"):format( u.path, u.query )
    end
    response = http.get(u.host, u.port, u.path, options)
  end

  local output_tab = stdnse.output_table()
  if string.match(response["status-line"], '^HTTP/') then
    if not isInArray(https_service_arr, service) and (port.version.service_dtype == 'table' or service == nil or service == 'unknown') then
      port.version.name ='http'
      port.version.service_dtype = 'probe'
      port.version.name_confidence = 10
      nmap.set_port_version(host,port)
    end
    output_tab.body = response.body
    output_tab.headers = response.rawheader
    output_tab.location = response.location
    output_tab.status_code = response.status
    return output_tab
  end
end