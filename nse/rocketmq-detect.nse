description = [[
    Detects Apache RocketMQ.
]]

---
-- @usage
-- nmap -p 9876 --script rocketmq-detect <target>
--
-- @output
-- PORT     STATE SERVICE
-- 9876/tcp open  rocketmq
-- | rocketmq-detect: 
-- |_  Version: xxx

author = {"bees"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

local shortport = require("shortport") 
local comm = require("comm")
local nmap = require("nmap")
local table = require("table")
local stdnse = require("stdnse")


portrule = shortport.port_or_service({98761}, {"sd", "ssl", "rocketmq"}, "tcp", {"open", "open|filtered"})

action = function(host, port)

    local socket, err = comm.opencon(host, port, "")

    if not socket then
        return nil, "Failed to connect: " .. (err or "unknown error")
    end

    -- 发送客户端请求（例如一个识别RocketMQ服务器的简单命令）
    -- 这里需要根据RocketMQ的协议来构建请求
    local binary_data = build_query_request()
    socket:send(binary_data)

    -- 接收RocketMQ服务器的回复
    local status, result = socket:receive();

    if (not status) then
        socket:close()
        return nil, "Filed to receive" .. result
    end

    -- 检查接收到的回复是否符合预期（例如版本信息、特定协议关键字等）
    stdnse.debug(string.format("response: %s", result))

    if result and is_rocketmq_response(result) then
        return format_output(result, host, port)
    end

end


function is_rocketmq_response(response)
    -- 根据回复判断响应体，code:1
    local rocketmq_pattern = "\"code\":"
    if string.find(response, rocketmq_pattern) then
        return true
    else
        return false
    end
end

-- 构建请求
function build_query_request()
    -- 构建一个查询请求
    local hex_payload = '000000c8000000b17b22636f6465223a32352c226578744669656c6473223a7b224163636573734b6579223a22726f636b65746d7132222c225369676e6174757265223a222b7a6452645575617a6953516b4855557164727477673146386a6b3d227d2c22666c6167223a302c226c616e6775616765223a224a415641222c226f7061717565223a302c2273657269616c697a655479706543757272656e74525043223a224a534f4e222c2276657273696f6e223a3433337d746573745f6b65793d746573745f76616c7565'
     -- Convert the hex string to binary
    local binary_data = stdnse.fromhex(hex_payload)

    return binary_data
end


function format_output(response, host, port)
    local output = stdnse.output_table()
    local version = get_version(response)
    output["Version"] = version

    port.version.product = 'Apache RocketMQ'
    port.version.name = 'rocketmq'
    port.version.service_dtype = 'probe'
    port.version.name_confidence = 10
    port.version.version = version

    nmap.set_port_version(host,port)
    return output
end


function get_version(response)
    -- 从回复中提取实际的版本号
    local version_pattern = "\"version\":(%d+)"
    local version = string.match(response, version_pattern)

    if version then
        return version
    else
        return "unknown"
    end
end